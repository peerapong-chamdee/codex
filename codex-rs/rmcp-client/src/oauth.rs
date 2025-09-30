use anyhow::Context;
use anyhow::Result;
use keyring::Entry;
use rmcp::transport::auth::OAuthTokenResponse;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;

use rmcp::transport::auth::AuthorizationManager;
use tokio::sync::Mutex;
use tracing::warn;

const KEYRING_SERVICE: &str = "Codex MCP Credentials";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOAuthTokens {
    pub server_name: String,
    pub url: String,
    pub client_id: String,
    pub token_response: OAuthTokenResponse,
}

pub fn load_oauth_tokens(server_name: &str) -> Result<Option<StoredOAuthTokens>> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    match entry.get_password() {
        Ok(serialized) => {
            let tokens: StoredOAuthTokens = serde_json::from_str(&serialized)
                .context("failed to deserialize OAuth tokens from keyring")?;
            Ok(Some(tokens))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => {
            println!("failed to read OAuth tokens from keyring: {err:?}");
            Err(err).context("failed to read OAuth tokens from keyring")
        }
    }
}

pub fn save_oauth_tokens(server_name: &str, tokens: &StoredOAuthTokens) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    let serialized = serde_json::to_string(tokens).context("failed to serialize OAuth tokens")?;
    entry
        .set_password(&serialized)
        .context("failed to write OAuth tokens to keyring")
}

pub fn delete_oauth_tokens(server_name: &str) -> Result<bool> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(err) => {
            println!("failed to delete OAuth tokens from keyring: {err:?}");
            Err(err).context("failed to delete OAuth tokens from keyring")
        }
    }
}

#[derive(Clone)]
pub(crate) struct OAuthRuntime {
    inner: Arc<OAuthRuntimeInner>,
}

struct OAuthRuntimeInner {
    server_name: String,
    url: String,
    authorization_manager: Arc<Mutex<AuthorizationManager>>,
    last_serialized: Mutex<Option<String>>,
}

impl OAuthRuntime {
    pub(crate) fn new(
        server_name: String,
        url: String,
        manager: Arc<Mutex<AuthorizationManager>>,
        initial_serialized: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(OAuthRuntimeInner {
                server_name,
                url,
                authorization_manager: manager,
                last_serialized: Mutex::new(initial_serialized),
            }),
        }
    }

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
                    token_response: credentials.clone(),
                };
                let serialized = serde_json::to_string(&stored)?;
                let mut last_serialized = self.inner.last_serialized.lock().await;
                if last_serialized.as_deref() != Some(serialized.as_str()) {
                    save_oauth_tokens(&self.inner.server_name, &stored)?;
                    *last_serialized = Some(serialized);
                }
            }
            None => {
                let mut last_serialized = self.inner.last_serialized.lock().await;
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
