use anyhow::Context;
use anyhow::Result;
use keyring::Entry;
use oauth2::AccessToken;
use oauth2::EmptyExtraTokenFields;
use oauth2::RefreshToken;
use oauth2::Scope;
use oauth2::TokenResponse;
use oauth2::basic::BasicTokenType;
use rmcp::transport::auth::OAuthTokenResponse;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::map::Map as JsonMap;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tracing::warn;

use rmcp::transport::auth::AuthorizationManager;
use tokio::sync::Mutex;

use crate::find_codex_home::find_codex_home;

const KEYRING_SERVICE: &str = "Codex MCP Credentials";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredOAuthTokens {
    pub server_name: String,
    pub url: String,
    pub client_id: String,
    pub token_response: WrappedOAuthTokenResponse,
}

/// Wrap OAuthTokenResponse to allow for partial equality comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedOAuthTokenResponse(pub OAuthTokenResponse);

impl PartialEq for WrappedOAuthTokenResponse {
    fn eq(&self, other: &Self) -> bool {
        match (serde_json::to_string(self), serde_json::to_string(other)) {
            (Ok(s1), Ok(s2)) => s1 == s2,
            _ => false,
        }
    }
}

pub(crate) fn load_oauth_tokens(server_name: &str, url: &str) -> Result<Option<StoredOAuthTokens>> {
    match Entry::new(KEYRING_SERVICE, server_name) {
        Ok(entry) => match entry.get_password() {
            Ok(serialized) => {
                let tokens: StoredOAuthTokens = serde_json::from_str(&serialized)
                    .context("failed to deserialize OAuth tokens from keyring")?;
                Ok(Some(tokens))
            }
            Err(keyring::Error::NoEntry) => load_oauth_tokens_from_file(server_name, url),
            Err(err) => {
                warn!("failed to read OAuth tokens from keyring: {err}");
                load_oauth_tokens_from_file(server_name, url)
                    .with_context(|| format!("failed to read OAuth tokens from keyring: {err}"))
            }
        },
        Err(err) => {
            warn!("failed to access keyring entry for {server_name}: {err}");
            load_oauth_tokens_from_file(server_name, url)
                .with_context(|| format!("failed to access keyring entry for {server_name}: {err}"))
        }
    }
}

pub fn save_oauth_tokens(server_name: &str, tokens: &StoredOAuthTokens) -> Result<()> {
    let serialized = serde_json::to_string(tokens).context("failed to serialize OAuth tokens")?;

    match Entry::new(KEYRING_SERVICE, server_name) {
        Ok(entry) => match entry.set_password(&serialized) {
            Ok(()) => {
                // Clean up any fallback entry so the keyring remains the source of truth.
                if let Err(error) = delete_oauth_tokens_from_file(server_name, Some(&tokens.url)) {
                    warn!("failed to remove OAuth tokens from fallback storage: {error:?}");
                }
                Ok(())
            }
            Err(err) => {
                warn!("failed to write OAuth tokens to keyring: {err:?}");
                save_oauth_tokens_to_file(tokens)
                    .with_context(|| format!("failed to write OAuth tokens to keyring: {err}"))
            }
        },
        Err(err) => {
            warn!("failed to access keyring entry for {server_name}: {err:?}");
            save_oauth_tokens_to_file(tokens)
                .with_context(|| format!("failed to access keyring entry for {server_name}: {err}"))
        }
    }
}

pub fn delete_oauth_tokens(server_name: &str) -> Result<bool> {
    let mut keyring_removed = false;

    match Entry::new(KEYRING_SERVICE, server_name) {
        Ok(entry) => match entry.delete_credential() {
            Ok(()) => keyring_removed = true,
            Err(keyring::Error::NoEntry) => {}
            Err(err) => {
                warn!("failed to delete OAuth tokens from keyring: {err:?}");
                return Err(err).context("failed to delete OAuth tokens from keyring");
            }
        },
        Err(err) => warn!("failed to access keyring entry for {server_name}: {err:?}"),
    }

    let file_removed = delete_oauth_tokens_from_file(server_name, None)?;
    Ok(keyring_removed || file_removed)
}

#[derive(Clone)]
pub(crate) struct OAuthRuntime {
    inner: Arc<OAuthRuntimeInner>,
}

struct OAuthRuntimeInner {
    server_name: String,
    url: String,
    authorization_manager: Arc<Mutex<AuthorizationManager>>,
    last_credentials: Mutex<Option<StoredOAuthTokens>>,
}

impl OAuthRuntime {
    pub(crate) fn new(
        server_name: String,
        url: String,
        manager: Arc<Mutex<AuthorizationManager>>,
        initial_credentials: Option<StoredOAuthTokens>,
    ) -> Self {
        Self {
            inner: Arc::new(OAuthRuntimeInner {
                server_name,
                url,
                authorization_manager: manager,
                last_credentials: Mutex::new(initial_credentials),
            }),
        }
    }

    /// Persists the latest stored credentials if they have changed.
    /// Deletes the credentials if they are no longer present.
    pub(crate) async fn persist_if_needed(&self) -> Result<()> {
        let (client_id, maybe_credentials) = {
            let manager = self.inner.authorization_manager.clone();
            let guard = manager.lock().await;
            guard.get_credentials().await
        }?;

        match maybe_credentials {
            Some(credentials) => {
                let stored = StoredOAuthTokens {
                    server_name: self.inner.server_name.clone(),
                    url: self.inner.url.clone(),
                    client_id,
                    token_response: WrappedOAuthTokenResponse(credentials.clone()),
                };
                let mut last_credentials = self.inner.last_credentials.lock().await;
                if last_credentials.as_ref() != Some(&stored) {
                    save_oauth_tokens(&self.inner.server_name, &stored)?;
                    *last_credentials = Some(stored);
                }
            }
            None => {
                let mut last_serialized = self.inner.last_credentials.lock().await;
                if last_serialized.take().is_some()
                    && let Err(error) = delete_oauth_tokens(&self.inner.server_name)
                {
                    warn!(
                        "failed to remove OAuth tokens for server {}: {error}",
                        self.inner.server_name
                    );
                }
            }
        }

        Ok(())
    }
}

const FALLBACK_FILENAME: &str = ".credentials.json";
const MCP_SERVER_TYPE: &str = "http";

type FallbackFile = BTreeMap<String, FallbackTokenEntry>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FallbackTokenEntry {
    server_name: String,
    server_url: String,
    client_id: String,
    access_token: String,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

fn load_oauth_tokens_from_file(server_name: &str, url: &str) -> Result<Option<StoredOAuthTokens>> {
    let Some(store) = read_fallback_file()? else {
        return Ok(None);
    };

    let key = compute_store_key(server_name, url)?;

    for entry in store.values() {
        let entry_key = compute_store_key(&entry.server_name, &entry.server_url)?;
        if entry_key != key {
            continue;
        }

        let mut token_response = OAuthTokenResponse::new(
            AccessToken::new(entry.access_token.clone()),
            BasicTokenType::Bearer,
            EmptyExtraTokenFields {},
        );

        if let Some(refresh) = entry.refresh_token.clone() {
            token_response.set_refresh_token(Some(RefreshToken::new(refresh)));
        }

        let scopes = entry.scopes.clone();
        if !scopes.is_empty() {
            token_response.set_scopes(Some(scopes.into_iter().map(Scope::new).collect()));
        }

        if let Some(expires_at) = entry.expires_at
            && let Some(seconds) = expires_in_from_timestamp(expires_at)
        {
            let duration = Duration::from_secs(seconds);
            token_response.set_expires_in(Some(&duration));
        }

        let stored = StoredOAuthTokens {
            server_name: entry.server_name.clone(),
            url: entry.server_url.clone(),
            client_id: entry.client_id.clone(),
            token_response: WrappedOAuthTokenResponse(token_response),
        };

        return Ok(Some(stored));
    }

    Ok(None)
}

fn save_oauth_tokens_to_file(tokens: &StoredOAuthTokens) -> Result<()> {
    let mut store = read_fallback_file()?.unwrap_or_default();
    let key = compute_store_key(&tokens.server_name, &tokens.url)?;

    let token_response = &tokens.token_response.0;
    let refresh_token = token_response
        .refresh_token()
        .map(|token| token.secret().to_string());
    let scopes = token_response
        .scopes()
        .map(|s| s.iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let entry = FallbackTokenEntry {
        server_name: tokens.server_name.clone(),
        server_url: tokens.url.clone(),
        client_id: tokens.client_id.clone(),
        access_token: token_response.access_token().secret().to_string(),
        expires_at: compute_expires_at_millis(token_response),
        refresh_token,
        scopes,
    };

    store.insert(key, entry);
    write_fallback_file(&store)
}

fn delete_oauth_tokens_from_file(server_name: &str, url: Option<&str>) -> Result<bool> {
    let mut store = match read_fallback_file()? {
        Some(store) => store,
        None => return Ok(false),
    };

    let removed = if let Some(target_url) = url {
        let key = compute_store_key(server_name, target_url)?;
        store.remove(&key).is_some()
    } else {
        let original_len = store.len();
        store.retain(|_, entry| entry.server_name != server_name);
        store.len() != original_len
    };

    if removed {
        write_fallback_file(&store)?;
    }

    Ok(removed)
}

fn compute_expires_at_millis(response: &OAuthTokenResponse) -> Option<u64> {
    let expires_in = response.expires_in()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let expiry = now.checked_add(expires_in)?;
    let millis = expiry.as_millis();
    if millis > u128::from(u64::MAX) {
        Some(u64::MAX)
    } else {
        Some(millis as u64)
    }
}

fn expires_in_from_timestamp(expires_at: u64) -> Option<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let now_ms = now.as_millis() as u64;

    if expires_at <= now_ms {
        None
    } else {
        Some((expires_at - now_ms) / 1000)
    }
}

fn compute_store_key(server_name: &str, server_url: &str) -> Result<String> {
    let mut payload = JsonMap::new();
    payload.insert(
        "type".to_string(),
        Value::String(MCP_SERVER_TYPE.to_string()),
    );
    payload.insert("url".to_string(), Value::String(server_url.to_string()));
    payload.insert("headers".to_string(), Value::Object(JsonMap::new()));

    let truncated = sha_256_prefix(&Value::Object(payload))?;
    Ok(format!("{server_name}|{truncated}"))
}

fn fallback_file_path() -> Result<PathBuf> {
    let mut path = find_codex_home()?;
    path.push(FALLBACK_FILENAME);
    Ok(path)
}

fn read_fallback_file() -> Result<Option<FallbackFile>> {
    let path = fallback_file_path()?;
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).context(format!(
                "failed to read credentials file at {}",
                path.display()
            ));
        }
    };

    match serde_json::from_str::<FallbackFile>(&contents) {
        Ok(store) => Ok(Some(store)),
        Err(e) => Err(e).context(format!(
            "failed to parse credentials file at {}",
            path.display()
        )),
    }
}

fn write_fallback_file(store: &FallbackFile) -> Result<()> {
    let path = fallback_file_path()?;

    if store.is_empty() {
        if path.exists() {
            fs::remove_file(path)?;
        }
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let serialized = serde_json::to_string(store)?;
    fs::write(&path, serialized)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

fn sha_256_prefix(value: &Value) -> Result<String> {
    let serialized =
        serde_json::to_string(&value).context("failed to serialize MCP OAuth key payload")?;
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    let truncated = &hex[..16];
    Ok(truncated.to_string())
}

// TODO: implement this.
// fn determine_oauth_status(name: &str, cfg: &McpServerConfig) -> McpOAuthStatus {
//     match &cfg.transport {
//         McpServerTransportConfig::Stdio { .. } => McpOAuthStatus::Unsupported,
//         McpServerTransportConfig::StreamableHttp {
//             bearer_token: Some(_),
//             ..
//         } => McpOAuthStatus::Unsupported,
//         McpServerTransportConfig::StreamableHttp { url, .. } => {
//             match load_oauth_tokens(name, url) {
//                 Ok(Some(_)) => McpOAuthStatus::LoggedIn,
//                 Ok(None) => McpOAuthStatus::LoggedOut,
//                 Err(err) => {
//                     eprintln!("warning: failed to read OAuth credentials for `{name}`: {err}");
//                     McpOAuthStatus::Error {
//                         message: err.to_string(),
//                     }
//                 }
//             }
//         }
//     }
// }
