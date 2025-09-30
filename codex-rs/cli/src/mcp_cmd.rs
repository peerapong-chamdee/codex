use std::collections::HashMap;
use std::path::PathBuf;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use codex_common::CliConfigOverrides;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use codex_core::config::find_codex_home;
use codex_core::config::load_global_mcp_servers;
use codex_core::config::write_global_mcp_servers;
use codex_core::config_types::McpServerConfig;
use codex_core::config_types::McpServerTransportConfig;
use codex_protocol::protocol::McpOAuthStatus;
use codex_rmcp_client::StoredOAuthTokens;
use codex_rmcp_client::delete_oauth_tokens;
use codex_rmcp_client::load_oauth_tokens;
use codex_rmcp_client::save_oauth_tokens;
use rmcp::transport::auth::OAuthState;
use tiny_http::Response;
use tiny_http::Server;
use tokio::sync::oneshot;
use tokio::time::timeout;
use urlencoding::decode;

/// [experimental] Launch Codex as an MCP server or manage configured MCP servers.
///
/// Subcommands:
/// - `serve`  — run the MCP server on stdio
/// - `list`   — list configured servers (with `--json`)
/// - `get`    — show a single server (with `--json`)
/// - `add`    — add a server launcher entry to `~/.codex/config.toml`
/// - `remove` — delete a server entry
#[derive(Debug, clap::Parser)]
pub struct McpCli {
    #[clap(flatten)]
    pub config_overrides: CliConfigOverrides,

    #[command(subcommand)]
    pub cmd: Option<McpSubcommand>,
}

#[derive(Debug, clap::Subcommand)]
pub enum McpSubcommand {
    /// [experimental] Run the Codex MCP server (stdio transport).
    Serve,

    /// [experimental] List configured MCP servers.
    List(ListArgs),

    /// [experimental] Show details for a configured MCP server.
    Get(GetArgs),

    /// [experimental] Add a global MCP server entry.
    Add(AddArgs),

    /// [experimental] Remove a global MCP server entry.
    Remove(RemoveArgs),

    /// [experimental] Authenticate with a configured MCP server via OAuth.
    Login(LoginArgs),

    /// [experimental] Remove stored OAuth credentials for a server.
    Logout(LogoutArgs),
}

#[derive(Debug, clap::Parser)]
pub struct ListArgs {
    /// Output the configured servers as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Parser)]
pub struct GetArgs {
    /// Name of the MCP server to display.
    pub name: String,

    /// Output the server configuration as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, clap::Parser)]
pub struct AddArgs {
    /// Name for the MCP server configuration.
    pub name: String,

    /// Environment variables to set when launching the server.
    #[arg(long, value_parser = parse_env_pair, value_name = "KEY=VALUE")]
    pub env: Vec<(String, String)>,

    /// Command to launch the MCP server.
    #[arg(trailing_var_arg = true, num_args = 1..)]
    pub command: Vec<String>,
}

#[derive(Debug, clap::Parser)]
pub struct RemoveArgs {
    /// Name of the MCP server configuration to remove.
    pub name: String,
}

#[derive(Debug, clap::Parser)]
pub struct LoginArgs {
    /// Name of the MCP server configuration to authenticate.
    pub name: String,
}

#[derive(Debug, clap::Parser)]
pub struct LogoutArgs {
    /// Name of the MCP server configuration to deauthenticate.
    pub name: String,
}

impl McpCli {
    pub async fn run(self, codex_linux_sandbox_exe: Option<PathBuf>) -> Result<()> {
        let McpCli {
            config_overrides,
            cmd,
        } = self;
        let subcommand = cmd.unwrap_or(McpSubcommand::Serve);

        match subcommand {
            McpSubcommand::Serve => {
                codex_mcp_server::run_main(codex_linux_sandbox_exe, config_overrides).await?;
            }
            McpSubcommand::List(args) => {
                run_list(&config_overrides, args)?;
            }
            McpSubcommand::Get(args) => {
                run_get(&config_overrides, args)?;
            }
            McpSubcommand::Add(args) => {
                run_add(&config_overrides, args)?;
            }
            McpSubcommand::Remove(args) => {
                run_remove(&config_overrides, args)?;
            }
            McpSubcommand::Login(args) => {
                run_login(&config_overrides, args).await?;
            }
            McpSubcommand::Logout(args) => {
                run_logout(&config_overrides, args)?;
            }
        }

        Ok(())
    }
}

fn run_add(config_overrides: &CliConfigOverrides, add_args: AddArgs) -> Result<()> {
    // Validate any provided overrides even though they are not currently applied.
    config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;

    let AddArgs { name, env, command } = add_args;

    validate_server_name(&name)?;

    let mut command_parts = command.into_iter();
    let command_bin = command_parts
        .next()
        .ok_or_else(|| anyhow!("command is required"))?;
    let command_args: Vec<String> = command_parts.collect();

    let env_map = if env.is_empty() {
        None
    } else {
        let mut map = HashMap::new();
        for (key, value) in env {
            map.insert(key, value);
        }
        Some(map)
    };

    let codex_home = find_codex_home().context("failed to resolve CODEX_HOME")?;
    let mut servers = load_global_mcp_servers(&codex_home)
        .with_context(|| format!("failed to load MCP servers from {}", codex_home.display()))?;

    let new_entry = McpServerConfig {
        transport: McpServerTransportConfig::Stdio {
            command: command_bin,
            args: command_args,
            env: env_map,
        },
        startup_timeout_sec: None,
        tool_timeout_sec: None,
    };

    servers.insert(name.clone(), new_entry);

    write_global_mcp_servers(&codex_home, &servers)
        .with_context(|| format!("failed to write MCP servers to {}", codex_home.display()))?;

    println!("Added global MCP server '{name}'.");

    Ok(())
}

fn run_remove(config_overrides: &CliConfigOverrides, remove_args: RemoveArgs) -> Result<()> {
    config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;

    let RemoveArgs { name } = remove_args;

    validate_server_name(&name)?;

    let codex_home = find_codex_home().context("failed to resolve CODEX_HOME")?;
    let mut servers = load_global_mcp_servers(&codex_home)
        .with_context(|| format!("failed to load MCP servers from {}", codex_home.display()))?;

    let removed = servers.remove(&name).is_some();

    if removed {
        write_global_mcp_servers(&codex_home, &servers)
            .with_context(|| format!("failed to write MCP servers to {}", codex_home.display()))?;
    }

    if removed {
        println!("Removed global MCP server '{name}'.");
    } else {
        println!("No MCP server named '{name}' found.");
    }

    Ok(())
}

async fn run_login(config_overrides: &CliConfigOverrides, login_args: LoginArgs) -> Result<()> {
    let overrides = config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;
    let config = Config::load_with_cli_overrides(overrides, ConfigOverrides::default())
        .context("failed to load configuration")?;

    let LoginArgs { name } = login_args;

    let Some(server) = config.mcp_servers.get(&name) else {
        bail!("No MCP server named '{name}' found.");
    };

    let url = match &server.transport {
        McpServerTransportConfig::StreamableHttp { url, .. } => url.clone(),
        _ => bail!("OAuth login is only supported for streamable_http transports."),
    };

    perform_oauth_login(&name, &url).await?;
    println!("Successfully logged in to MCP server '{name}'.");
    Ok(())
}

fn run_logout(config_overrides: &CliConfigOverrides, logout_args: LogoutArgs) -> Result<()> {
    let overrides = config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;
    let config = Config::load_with_cli_overrides(overrides, ConfigOverrides::default())
        .context("failed to load configuration")?;

    let LogoutArgs { name } = logout_args;

    if !config.mcp_servers.contains_key(&name) {
        println!("No MCP server named '{name}' found in configuration.");
    }

    match delete_oauth_tokens(&name) {
        Ok(true) => println!("Removed OAuth credentials for '{name}'."),
        Ok(false) => println!("No OAuth credentials stored for '{name}'."),
        Err(err) => return Err(anyhow!("failed to delete OAuth credentials: {err}")),
    }

    Ok(())
}

fn run_list(config_overrides: &CliConfigOverrides, list_args: ListArgs) -> Result<()> {
    let overrides = config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;
    let config = Config::load_with_cli_overrides(overrides, ConfigOverrides::default())
        .context("failed to load configuration")?;

    let mut entries: Vec<_> = config.mcp_servers.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut status_map: HashMap<String, McpOAuthStatus> = HashMap::new();
    for (name, cfg) in &config.mcp_servers {
        status_map.insert(name.clone(), determine_oauth_status(name, cfg));
    }

    if list_args.json {
        let json_entries: Vec<_> = entries
            .into_iter()
            .map(|(name, cfg)| {
                let transport = match &cfg.transport {
                    McpServerTransportConfig::Stdio { command, args, env } => serde_json::json!({
                        "type": "stdio",
                        "command": command,
                        "args": args,
                        "env": env,
                    }),
                    McpServerTransportConfig::StreamableHttp { url, bearer_token } => {
                        serde_json::json!({
                            "type": "streamable_http",
                            "url": url,
                            "bearer_token": bearer_token,
                        })
                    }
                };

                let status = status_map
                    .get(name)
                    .cloned()
                    .unwrap_or(McpOAuthStatus::Unsupported);

                serde_json::json!({
                    "name": name,
                    "transport": transport,
                    "startup_timeout_sec": cfg
                        .startup_timeout_sec
                        .map(|timeout| timeout.as_secs_f64()),
                    "tool_timeout_sec": cfg
                        .tool_timeout_sec
                        .map(|timeout| timeout.as_secs_f64()),
                    "oauth_status": oauth_status_label(&status),
                })
            })
            .collect();
        let output = serde_json::to_string_pretty(&json_entries)?;
        println!("{output}");
        return Ok(());
    }

    if entries.is_empty() {
        println!("No MCP servers configured yet. Try `codex mcp add my-tool -- my-command`.");
        return Ok(());
    }

    let mut stdio_rows: Vec<[String; 5]> = Vec::new();
    let mut http_rows: Vec<[String; 4]> = Vec::new();

    for (name, cfg) in entries {
        let status = status_map
            .get(name)
            .cloned()
            .unwrap_or(McpOAuthStatus::Unsupported);
        let status_label = oauth_status_label(&status);
        match &cfg.transport {
            McpServerTransportConfig::Stdio { command, args, env } => {
                let args_display = if args.is_empty() {
                    "-".to_string()
                } else {
                    args.join(" ")
                };
                let env_display = match env.as_ref() {
                    None => "-".to_string(),
                    Some(map) if map.is_empty() => "-".to_string(),
                    Some(map) => {
                        let mut pairs: Vec<_> = map.iter().collect();
                        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
                        pairs
                            .into_iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                };
                stdio_rows.push([
                    name.clone(),
                    command.clone(),
                    args_display,
                    env_display,
                    status_label.clone(),
                ]);
            }
            McpServerTransportConfig::StreamableHttp { url, bearer_token } => {
                let has_bearer = if bearer_token.is_some() {
                    "True"
                } else {
                    "False"
                };
                http_rows.push([name.clone(), url.clone(), has_bearer.into(), status_label]);
            }
        }
    }

    if !stdio_rows.is_empty() {
        let mut widths = [
            "Name".len(),
            "Command".len(),
            "Args".len(),
            "Env".len(),
            "OAuth".len(),
        ];
        for row in &stdio_rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.len());
            }
        }

        println!(
            "{:<name_w$}  {:<cmd_w$}  {:<args_w$}  {:<env_w$}  {:<oauth_w$}",
            "Name",
            "Command",
            "Args",
            "Env",
            "OAuth",
            name_w = widths[0],
            cmd_w = widths[1],
            args_w = widths[2],
            env_w = widths[3],
            oauth_w = widths[4],
        );

        for row in &stdio_rows {
            println!(
                "{:<name_w$}  {:<cmd_w$}  {:<args_w$}  {:<env_w$}  {:<oauth_w$}",
                row[0],
                row[1],
                row[2],
                row[3],
                row[4],
                name_w = widths[0],
                cmd_w = widths[1],
                args_w = widths[2],
                env_w = widths[3],
                oauth_w = widths[4],
            );
        }
    }

    if !stdio_rows.is_empty() && !http_rows.is_empty() {
        println!();
    }

    if !http_rows.is_empty() {
        let mut widths = [
            "Name".len(),
            "Url".len(),
            "Has Bearer Token".len(),
            "OAuth".len(),
        ];
        for row in &http_rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(cell.len());
            }
        }

        println!(
            "{:<name_w$}  {:<url_w$}  {:<token_w$}  {:<oauth_w$}",
            "Name",
            "Url",
            "Has Bearer Token",
            "OAuth",
            name_w = widths[0],
            url_w = widths[1],
            token_w = widths[2],
            oauth_w = widths[3],
        );

        for row in &http_rows {
            println!(
                "{:<name_w$}  {:<url_w$}  {:<token_w$}  {:<oauth_w$}",
                row[0],
                row[1],
                row[2],
                row[3],
                name_w = widths[0],
                url_w = widths[1],
                token_w = widths[2],
                oauth_w = widths[3],
            );
        }
    }

    Ok(())
}

fn run_get(config_overrides: &CliConfigOverrides, get_args: GetArgs) -> Result<()> {
    let overrides = config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;
    let config = Config::load_with_cli_overrides(overrides, ConfigOverrides::default())
        .context("failed to load configuration")?;

    let Some(server) = config.mcp_servers.get(&get_args.name) else {
        bail!("No MCP server named '{name}' found.", name = get_args.name);
    };

    let status = determine_oauth_status(&get_args.name, server);

    if get_args.json {
        let transport = match &server.transport {
            McpServerTransportConfig::Stdio { command, args, env } => serde_json::json!({
                "type": "stdio",
                "command": command,
                "args": args,
                "env": env,
            }),
            McpServerTransportConfig::StreamableHttp { url, bearer_token } => serde_json::json!({
                "type": "streamable_http",
                "url": url,
                "bearer_token": bearer_token,
            }),
        };
        let output = serde_json::to_string_pretty(&serde_json::json!({
            "name": get_args.name,
            "transport": transport,
            "startup_timeout_sec": server
                .startup_timeout_sec
                .map(|timeout| timeout.as_secs_f64()),
            "tool_timeout_sec": server
                .tool_timeout_sec
                .map(|timeout| timeout.as_secs_f64()),
            "oauth_status": oauth_status_label(&status),
        }))?;
        println!("{output}");
        return Ok(());
    }

    println!("{}", get_args.name);
    match &server.transport {
        McpServerTransportConfig::Stdio { command, args, env } => {
            println!("  transport: stdio");
            println!("  command: {command}");
            let args_display = if args.is_empty() {
                "-".to_string()
            } else {
                args.join(" ")
            };
            println!("  args: {args_display}");
            let env_display = match env.as_ref() {
                None => "-".to_string(),
                Some(map) if map.is_empty() => "-".to_string(),
                Some(map) => {
                    let mut pairs: Vec<_> = map.iter().collect();
                    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
                    pairs
                        .into_iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };
            println!("  env: {env_display}");
        }
        McpServerTransportConfig::StreamableHttp { url, bearer_token } => {
            println!("  transport: streamable_http");
            println!("  url: {url}");
            let bearer = bearer_token.as_deref().unwrap_or("-");
            println!("  bearer_token: {bearer}");
        }
    }
    if let Some(timeout) = server.startup_timeout_sec {
        println!("  startup_timeout_sec: {}", timeout.as_secs_f64());
    }
    if let Some(timeout) = server.tool_timeout_sec {
        println!("  tool_timeout_sec: {}", timeout.as_secs_f64());
    }
    println!("  oauth_status: {}", oauth_status_label(&status));
    println!("  remove: codex mcp remove {}", get_args.name);

    Ok(())
}

fn parse_env_pair(raw: &str) -> Result<(String, String), String> {
    let mut parts = raw.splitn(2, '=');
    let key = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "environment entries must be in KEY=VALUE form".to_string())?;
    let value = parts
        .next()
        .map(str::to_string)
        .ok_or_else(|| "environment entries must be in KEY=VALUE form".to_string())?;

    Ok((key.to_string(), value))
}

fn validate_server_name(name: &str) -> Result<()> {
    let is_valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

    if is_valid {
        Ok(())
    } else {
        bail!("invalid server name '{name}' (use letters, numbers, '-', '_')");
    }
}

struct CallbackServerGuard {
    server: Arc<Server>,
}

impl Drop for CallbackServerGuard {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

async fn perform_oauth_login(server_name: &str, server_url: &str) -> Result<()> {
    let server = Arc::new(Server::http("127.0.0.1:0").map_err(|err| anyhow!(err))?);
    let guard = CallbackServerGuard {
        server: Arc::clone(&server),
    };

    let actual_port = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| anyhow!("unable to determine callback port"))?
        .port();
    let redirect_uri = format!("http://localhost:{actual_port}/callback");

    let (tx, rx) = oneshot::channel();
    spawn_callback_server(server, tx);

    let mut oauth_state = OAuthState::new(server_url, None).await?;
    oauth_state.start_authorization(&[], &redirect_uri).await?;
    let auth_url = oauth_state.get_authorization_url().await?;

    println!("Authorize `{server_name}` by opening this URL in your browser:\n{auth_url}\n");

    if webbrowser::open(&auth_url).is_err() {
        println!("(Browser launch failed; please copy the URL above manually.)");
    }

    let (code, csrf_state) = timeout(Duration::from_secs(300), rx)
        .await
        .context("timed out waiting for OAuth callback")?
        .context("OAuth callback was cancelled")?;

    oauth_state
        .handle_callback(&code, &csrf_state)
        .await
        .context("failed to handle OAuth callback")?;

    let (client_id, credentials_opt) = oauth_state
        .get_credentials()
        .await
        .context("failed to retrieve OAuth credentials")?;
    let credentials =
        credentials_opt.ok_or_else(|| anyhow!("OAuth provider did not return credentials"))?;

    let stored = StoredOAuthTokens {
        server_name: server_name.to_string(),
        url: server_url.to_string(),
        client_id,
        token_response: credentials,
    };
    save_oauth_tokens(server_name, &stored)?;

    drop(guard);
    Ok(())
}

fn spawn_callback_server(server: Arc<Server>, tx: oneshot::Sender<(String, String)>) {
    std::thread::spawn(move || {
        while let Ok(request) = server.recv() {
            let path = request.url().to_string();
            if let Some((code, state)) = parse_oauth_callback(&path) {
                let response =
                    Response::from_string("Authentication complete. You may close this window.");
                let _ = request.respond(response);
                let _ = tx.send((code, state));
                break;
            } else {
                let response =
                    Response::from_string("Invalid OAuth callback").with_status_code(400);
                let _ = request.respond(response);
            }
        }
    });
}

fn parse_oauth_callback(path: &str) -> Option<(String, String)> {
    let (route, query) = path.split_once('?')?;
    if route != "/callback" {
        return None;
    }

    let mut code = None;
    let mut state = None;

    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        let decoded = decode(value).ok()?.into_owned();
        match key {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            _ => {}
        }
    }

    Some((code?, state?))
}

fn determine_oauth_status(name: &str, cfg: &McpServerConfig) -> McpOAuthStatus {
    match &cfg.transport {
        McpServerTransportConfig::Stdio { .. } => McpOAuthStatus::Unsupported,
        McpServerTransportConfig::StreamableHttp {
            bearer_token: Some(_),
            ..
        } => McpOAuthStatus::Unsupported,
        McpServerTransportConfig::StreamableHttp { .. } => match load_oauth_tokens(name) {
            Ok(Some(_)) => McpOAuthStatus::LoggedIn,
            Ok(None) => McpOAuthStatus::LoggedOut,
            Err(err) => {
                eprintln!("warning: failed to read OAuth credentials for `{name}`: {err}");
                McpOAuthStatus::Error {
                    message: err.to_string(),
                }
            }
        },
    }
}

fn oauth_status_label(status: &McpOAuthStatus) -> String {
    match status {
        McpOAuthStatus::Unsupported => "not supported".to_string(),
        McpOAuthStatus::LoggedIn => "logged in".to_string(),
        McpOAuthStatus::LoggedOut => "not logged in".to_string(),
        McpOAuthStatus::LoginRequired => "login required".to_string(),
        McpOAuthStatus::Error { message } => format!("error: {message}"),
    }
}
