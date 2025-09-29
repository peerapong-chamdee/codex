use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use futures::FutureExt;
use mcp_types::CallToolRequestParams;
use mcp_types::CallToolResult;
use mcp_types::InitializeRequestParams;
use mcp_types::InitializeResult;
use mcp_types::ListToolsRequestParams;
use mcp_types::ListToolsResult;
use rmcp::model::CallToolRequestParam;
use rmcp::model::InitializeRequestParam;
use rmcp::model::PaginatedRequestParam;
use rmcp::service::RoleClient;
use rmcp::service::RunningService;
use rmcp::service::{self};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::auth::AuthClient;
use rmcp::transport::auth::AuthorizationManager;
use rmcp::transport::auth::OAuthState;
use rmcp::transport::child_process::TokioChildProcess;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time;
use tracing::info;
use tracing::warn;

use crate::logging_client_handler::LoggingClientHandler;
use crate::oauth::StoredOAuthTokens;
use crate::oauth::delete_tokens;
use crate::oauth::save_tokens;
use crate::utils::convert_call_tool_result;
use crate::utils::convert_to_mcp;
use crate::utils::convert_to_rmcp;
use crate::utils::create_env_for_mcp_server;
use crate::utils::run_with_timeout;

#[derive(Debug, Clone)]
pub struct StreamableHttpClientConfig {
    pub server_name: String,
    pub url: String,
    pub auth: Option<StreamableHttpAuth>,
}

#[derive(Debug, Clone)]
pub struct OAuthClientConfig {
    pub stored_tokens: Option<StoredOAuthTokens>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum StreamableHttpAuth {
    BearerToken(Box<String>),
    Oauth(Box<OAuthClientConfig>),
}

enum PendingTransport {
    ChildProcess(TokioChildProcess),
    StreamableHttp(StreamableHttpClientTransport<reqwest::Client>),
    StreamableHttpWithAuth {
        transport: StreamableHttpClientTransport<AuthClient<reqwest::Client>>,
        oauth: OAuthRuntime,
    },
}

enum ClientState {
    Connecting {
        transport: Option<PendingTransport>,
    },
    Ready {
        service: Arc<RunningService<RoleClient, LoggingClientHandler>>,
        oauth: Option<OAuthRuntime>,
    },
}

/// MCP client implemented on top of the official `rmcp` SDK.
/// https://github.com/modelcontextprotocol/rust-sdk
pub struct RmcpClient {
    state: Mutex<ClientState>,
}

#[derive(Clone)]
struct OAuthRuntime {
    inner: Arc<OAuthRuntimeInner>,
}

struct OAuthRuntimeInner {
    server_name: String,
    url: String,
    scopes: Vec<String>,
    authorization_manager: Arc<Mutex<AuthorizationManager>>,
    last_serialized: Mutex<Option<String>>,
}

impl OAuthRuntime {
    fn new(
        server_name: String,
        url: String,
        scopes: Vec<String>,
        manager: Arc<Mutex<AuthorizationManager>>,
        initial_serialized: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(OAuthRuntimeInner {
                server_name,
                url,
                scopes,
                authorization_manager: manager,
                last_serialized: Mutex::new(initial_serialized),
            }),
        }
    }

    async fn persist_if_needed(&self) -> Result<()> {
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
                    scopes: self.inner.scopes.clone(),
                    token_response: credentials.clone(),
                };
                let serialized = serde_json::to_string(&stored)?;
                let mut last_serialized = self.inner.last_serialized.lock().await;
                if last_serialized.as_deref() != Some(serialized.as_str()) {
                    save_tokens(&self.inner.server_name, &stored)?;
                    *last_serialized = Some(serialized);
                }
            }
            None => {
                let mut last_serialized = self.inner.last_serialized.lock().await;
                if last_serialized.take().is_some()
                    && let Err(error) = delete_tokens(&self.inner.server_name)
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

impl RmcpClient {
    pub async fn new_stdio_client(
        program: OsString,
        args: Vec<OsString>,
        env: Option<HashMap<String, String>>,
    ) -> io::Result<Self> {
        let program_name = program.to_string_lossy().into_owned();
        let mut command = Command::new(&program);
        command
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .env_clear()
            .envs(create_env_for_mcp_server(env))
            .args(&args);

        let (transport, stderr) = TokioChildProcess::builder(command)
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                loop {
                    match reader.next_line().await {
                        Ok(Some(line)) => {
                            info!("MCP server stderr ({program_name}): {line}");
                        }
                        Ok(None) => break,
                        Err(error) => {
                            warn!("Failed to read MCP server stderr ({program_name}): {error}");
                            break;
                        }
                    }
                }
            });
        }

        Ok(Self {
            state: Mutex::new(ClientState::Connecting {
                transport: Some(PendingTransport::ChildProcess(transport)),
            }),
        })
    }

    pub async fn new_streamable_http_client(
        mut config: StreamableHttpClientConfig,
    ) -> Result<Self> {
        let transport = match config.auth.take() {
            Some(StreamableHttpAuth::Oauth(oauth_config)) => {
                let (transport, runtime) = create_oauth_transport(&config, *oauth_config).await?;
                PendingTransport::StreamableHttpWithAuth {
                    transport,
                    oauth: runtime,
                }
            }
            Some(StreamableHttpAuth::BearerToken(token)) => {
                let http_config = StreamableHttpClientTransportConfig::with_uri(config.url.clone())
                    .auth_header(format!("Bearer {token}"));
                let transport = StreamableHttpClientTransport::from_config(http_config);
                PendingTransport::StreamableHttp(transport)
            }
            None => {
                let http_config = StreamableHttpClientTransportConfig::with_uri(config.url.clone());
                let transport = StreamableHttpClientTransport::from_config(http_config);
                PendingTransport::StreamableHttp(transport)
            }
        };

        Ok(Self {
            state: Mutex::new(ClientState::Connecting {
                transport: Some(transport),
            }),
        })
    }

    /// Perform the initialization handshake with the MCP server.
    /// https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle#initialization
    pub async fn initialize(
        &self,
        params: InitializeRequestParams,
        timeout: Option<Duration>,
    ) -> Result<InitializeResult> {
        let rmcp_params: InitializeRequestParam = convert_to_rmcp(params.clone())?;
        let client_handler = LoggingClientHandler::new(rmcp_params);

        let (transport, oauth_runtime) = {
            let mut guard = self.state.lock().await;
            match &mut *guard {
                ClientState::Connecting { transport } => match transport.take() {
                    Some(PendingTransport::ChildProcess(transport)) => (
                        service::serve_client(client_handler.clone(), transport).boxed(),
                        None,
                    ),
                    Some(PendingTransport::StreamableHttp(transport)) => (
                        service::serve_client(client_handler.clone(), transport).boxed(),
                        None,
                    ),
                    Some(PendingTransport::StreamableHttpWithAuth { transport, oauth }) => (
                        service::serve_client(client_handler.clone(), transport).boxed(),
                        Some(oauth),
                    ),
                    None => return Err(anyhow!("client already initializing")),
                },
                ClientState::Ready { .. } => return Err(anyhow!("client already initialized")),
            }
        };

        let service = match timeout {
            Some(duration) => time::timeout(duration, transport)
                .await
                .map_err(|_| anyhow!("timed out handshaking with MCP server after {duration:?}"))?
                .map_err(|err| anyhow!("handshaking with MCP server failed: {err}"))?,
            None => transport
                .await
                .map_err(|err| anyhow!("handshaking with MCP server failed: {err}"))?,
        };

        let initialize_result_rmcp = service
            .peer()
            .peer_info()
            .ok_or_else(|| anyhow!("handshake succeeded but server info was missing"))?;
        let initialize_result = convert_to_mcp(initialize_result_rmcp)?;

        {
            let mut guard = self.state.lock().await;
            *guard = ClientState::Ready {
                service: Arc::new(service),
                oauth: oauth_runtime.clone(),
            };
        }

        if let Some(runtime) = oauth_runtime
            && let Err(error) = runtime.persist_if_needed().await
        {
            warn!("failed to persist OAuth tokens after initialize: {error}");
        }

        Ok(initialize_result)
    }

    pub async fn list_tools(
        &self,
        params: Option<ListToolsRequestParams>,
        timeout: Option<Duration>,
    ) -> Result<ListToolsResult> {
        let service = self.service().await?;
        let rmcp_params = params
            .map(convert_to_rmcp::<_, PaginatedRequestParam>)
            .transpose()?;

        let fut = service.list_tools(rmcp_params);
        let result = run_with_timeout(fut, timeout, "tools/list").await?;
        let converted = convert_to_mcp(result)?;
        self.persist_oauth_tokens().await;
        Ok(converted)
    }

    pub async fn call_tool(
        &self,
        name: String,
        arguments: Option<serde_json::Value>,
        timeout: Option<Duration>,
    ) -> Result<CallToolResult> {
        let service = self.service().await?;
        let params = CallToolRequestParams { arguments, name };
        let rmcp_params: CallToolRequestParam = convert_to_rmcp(params)?;
        let fut = service.call_tool(rmcp_params);
        let rmcp_result = run_with_timeout(fut, timeout, "tools/call").await?;
        let converted = convert_call_tool_result(rmcp_result)?;
        self.persist_oauth_tokens().await;
        Ok(converted)
    }

    async fn service(&self) -> Result<Arc<RunningService<RoleClient, LoggingClientHandler>>> {
        let guard = self.state.lock().await;
        match &*guard {
            ClientState::Ready { service, .. } => Ok(Arc::clone(service)),
            ClientState::Connecting { .. } => Err(anyhow!("MCP client not initialized")),
        }
    }

    async fn oauth_runtime(&self) -> Option<OAuthRuntime> {
        let guard = self.state.lock().await;
        match &*guard {
            ClientState::Ready {
                oauth: Some(runtime),
                ..
            } => Some(runtime.clone()),
            _ => None,
        }
    }

    async fn persist_oauth_tokens(&self) {
        if let Some(runtime) = self.oauth_runtime().await
            && let Err(error) = runtime.persist_if_needed().await
        {
            warn!("failed to persist OAuth tokens: {error}");
        }
    }
}

async fn create_oauth_transport(
    config: &StreamableHttpClientConfig,
    oauth_config: OAuthClientConfig,
) -> Result<(
    StreamableHttpClientTransport<AuthClient<reqwest::Client>>,
    OAuthRuntime,
)> {
    let http_client = reqwest::Client::builder().build()?;
    let mut oauth_state = OAuthState::new(config.url.clone(), Some(http_client.clone())).await?;

    let initial_serialized = if let Some(stored) = &oauth_config.stored_tokens {
        oauth_state
            .set_credentials(&stored.client_id, stored.token_response.clone())
            .await?;
        Some(serde_json::to_string(stored)?)
    } else {
        None
    };

    let manager = match oauth_state {
        OAuthState::Authorized(manager) => manager,
        OAuthState::Unauthorized(manager) => manager,
        OAuthState::Session(_) | OAuthState::AuthorizedHttpClient(_) => {
            return Err(anyhow!("unexpected OAuth state during client setup"));
        }
    };

    let auth_client = AuthClient::new(http_client, manager);
    let auth_manager = auth_client.auth_manager.clone();

    let transport = StreamableHttpClientTransport::with_client(
        auth_client,
        StreamableHttpClientTransportConfig::with_uri(config.url.clone()),
    );

    let scopes = if oauth_config.scopes.is_empty() {
        vec!["mcp".to_string()]
    } else {
        oauth_config.scopes
    };

    let runtime = OAuthRuntime::new(
        config.server_name.clone(),
        config.url.clone(),
        scopes,
        auth_manager,
        initial_serialized,
    );

    Ok((transport, runtime))
}
