use anyhow::Context;
use anyhow::Result;
use keyring::Entry;
use rmcp::transport::auth::OAuthTokenResponse;
use serde::Deserialize;
use serde::Serialize;

const KEYRING_SERVICE: &str = "Codex MCP Credentials";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOAuthTokens {
    pub server_name: String,
    pub url: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub token_response: OAuthTokenResponse,
}

pub fn load_tokens(server_name: &str) -> Result<Option<StoredOAuthTokens>> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    match entry.get_password() {
        Ok(serialized) => {
            let tokens: StoredOAuthTokens = serde_json::from_str(&serialized)
                .context("failed to deserialize OAuth tokens from keyring")?;
            Ok(Some(tokens))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err).context("failed to read OAuth tokens from keyring"),
    }
}

pub fn save_tokens(server_name: &str, tokens: &StoredOAuthTokens) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    let serialized = serde_json::to_string(tokens).context("failed to serialize OAuth tokens")?;
    entry
        .set_password(&serialized)
        .context("failed to write OAuth tokens to keyring")
}

pub fn delete_tokens(server_name: &str) -> Result<bool> {
    let entry = Entry::new(KEYRING_SERVICE, server_name)?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(err) => Err(err).context("failed to delete OAuth tokens from keyring"),
    }
}

pub fn default_scopes() -> Vec<String> {
    vec!["mcp".to_string()]
}
