#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use std::any::Any;
use std::fs;
use std::future::Future;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use tokio::task;
use toml::Value as TomlValue;

const CONFIG_TOML_FILE: &str = "config.toml";
const MANAGED_CONFIG_TOML_FILE: &str = "managed_config.toml";

#[derive(Debug)]
pub(crate) struct LoadedConfigLayers {
    pub base: TomlValue,
    pub managed_config: Option<TomlValue>,
    pub managed_preferences: Option<TomlValue>,
}

// Configuration layering pipeline (top overrides bottom):
//
//        +-------------------------+
//        | Managed preferences (*) |
//        +-------------------------+
//                    ^
//                    |
//        +-------------------------+
//        |  managed_config.toml   |
//        +-------------------------+
//                    ^
//                    |
//        +-------------------------+
//        |    config.toml (base)   |
//        +-------------------------+
//
// (*) Only available on macOS via managed device profiles.

pub async fn load_config_as_toml_async(codex_home: PathBuf) -> io::Result<TomlValue> {
    let LoadedConfigLayers {
        mut base,
        managed_config,
        managed_preferences,
    } = load_config_layers_async(codex_home).await?;

    for overlay in [managed_config, managed_preferences].into_iter().flatten() {
        merge_toml_values(&mut base, &overlay);
    }

    Ok(base)
}

pub fn load_config_as_toml(codex_home: &Path) -> io::Result<TomlValue> {
    block_on_config_future(load_config_as_toml_async(codex_home.to_path_buf()))
}

pub(crate) async fn load_config_layers_async(
    codex_home: PathBuf,
) -> io::Result<LoadedConfigLayers> {
    let user_config = read_config_from_path_async(codex_home.join(CONFIG_TOML_FILE), true).await?;
    let managed_config =
        read_config_from_path_async(codex_home.join(MANAGED_CONFIG_TOML_FILE), false).await?;
    let managed_preferences = load_managed_admin_config_layer_async().await?;

    Ok(LoadedConfigLayers {
        base: user_config.unwrap_or_else(default_empty_table),
        managed_config,
        managed_preferences,
    })
}

pub(crate) fn load_config_layers(codex_home: &Path) -> io::Result<LoadedConfigLayers> {
    block_on_config_future(load_config_layers_async(codex_home.to_path_buf()))
}

fn default_empty_table() -> TomlValue {
    TomlValue::Table(Default::default())
}

async fn read_config_from_path_async(
    path: PathBuf,
    log_missing_as_info: bool,
) -> io::Result<Option<TomlValue>> {
    let path_display = path.clone();
    task::spawn_blocking(move || read_config_from_path(path.as_path(), log_missing_as_info))
        .await
        .map_err(|err| {
            io::Error::other(format!(
                "failed to read {} via blocking task: {err}",
                path_display.display()
            ))
        })?
}

fn read_config_from_path(path: &Path, log_missing_as_info: bool) -> io::Result<Option<TomlValue>> {
    match fs::read_to_string(path) {
        Ok(contents) => match toml::from_str::<TomlValue>(&contents) {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                tracing::error!("Failed to parse {}: {err}", path.display());
                Err(io::Error::new(io::ErrorKind::InvalidData, err))
            }
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if log_missing_as_info {
                tracing::info!("{} not found, using defaults", path.display());
            } else {
                tracing::debug!("{} not found", path.display());
            }
            Ok(None)
        }
        Err(err) => {
            tracing::error!("Failed to read {}: {err}", path.display());
            Err(err)
        }
    }
}

#[cfg(target_os = "macos")]
async fn load_managed_admin_config_layer_async() -> io::Result<Option<TomlValue>> {
    const LOAD_ERROR: &str = "Failed to load managed preferences configuration";

    let join_result =
        task::spawn_blocking(|| std::panic::catch_unwind(load_managed_admin_config)).await;

    match join_result {
        Ok(Ok(result)) => result,
        Ok(Err(panic)) => {
            if let Some(msg) = panic_payload_to_string(panic) {
                tracing::error!("Configuration loader for managed preferences panicked: {msg}");
            } else {
                tracing::error!("Configuration loader for managed preferences panicked");
            }

            Err(io::Error::other(LOAD_ERROR))
        }
        Err(join_err) => {
            if join_err.is_cancelled() {
                tracing::error!("Managed preferences load task was cancelled");
            } else {
                tracing::error!("Managed preferences load task failed: {join_err}");
            }
            Err(io::Error::other(LOAD_ERROR))
        }
    }
}

#[cfg(not(target_os = "macos"))]
async fn load_managed_admin_config_layer_async() -> io::Result<Option<TomlValue>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn panic_payload_to_string(panic: Box<dyn Any + Send + 'static>) -> Option<String> {
    match panic.downcast::<String>() {
        Ok(message) => Some(*message),
        Err(panic) => match panic.downcast::<&'static str>() {
            Ok(message) => Some((*message).to_string()),
            Err(_) => None,
        },
    }
}

fn block_on_config_future<F, T>(future: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        task::block_in_place(|| handle.block_on(future))
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                io::Error::other(format!(
                    "failed to create runtime for managed preferences loading: {err}"
                ))
            })?;
        runtime.block_on(future)
    }
}

//  Merge config `overlay` into `base` config TomlValue, with `overlay` taking precedence.
pub(crate) fn merge_toml_values(base: &mut TomlValue, overlay: &TomlValue) {
    if let TomlValue::Table(overlay_table) = overlay
        && let TomlValue::Table(base_table) = base
    {
        for (key, value) in overlay_table {
            if let Some(existing) = base_table.get_mut(key) {
                merge_toml_values(existing, value);
            } else {
                base_table.insert(key.clone(), value.clone());
            }
        }
    } else {
        *base = overlay.clone();
    }
}

#[cfg(target_os = "macos")]
fn load_managed_admin_config() -> io::Result<Option<TomlValue>> {
    macos::load_managed_admin_config()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn merges_managed_config_layer_on_top() {
        let run_test = || {
            let tmp = tempdir().expect("tempdir");
            std::fs::write(
                tmp.path().join(CONFIG_TOML_FILE),
                r#"foo = 1

[nested]
value = "base"
"#,
            )
            .expect("write base");
            std::fs::write(
                tmp.path().join(MANAGED_CONFIG_TOML_FILE),
                r#"foo = 2

[nested]
value = "managed_config"
extra = true
"#,
            )
            .expect("write managed config");

            let loaded = load_config_as_toml(tmp.path()).expect("load config");
            let table = loaded.as_table().expect("top-level table expected");

            assert_eq!(table.get("foo"), Some(&TomlValue::Integer(2)));
            let nested = table
                .get("nested")
                .and_then(|v| v.as_table())
                .expect("nested");
            assert_eq!(
                nested.get("value"),
                Some(&TomlValue::String("managed_config".to_string()))
            );
            assert_eq!(nested.get("extra"), Some(&TomlValue::Boolean(true)));
        };

        #[cfg(target_os = "macos")]
        super::macos::with_cleared_test_managed_preferences(run_test);

        #[cfg(not(target_os = "macos"))]
        run_test();
    }

    #[test]
    fn returns_empty_when_all_layers_missing() {
        let run_test = || {
            let tmp = tempdir().expect("tempdir");
            let layers = load_config_layers(tmp.path()).expect("load layers");
            let base_table = layers.base.as_table().expect("base table expected");
            assert!(
                base_table.is_empty(),
                "expected empty base layer when configs missing"
            );
            assert!(
                layers.managed_config.is_none(),
                "managed config layer should be absent when file missing"
            );

            #[cfg(not(target_os = "macos"))]
            {
                let loaded = load_config_as_toml(tmp.path()).expect("load config");
                let table = loaded.as_table().expect("top-level table expected");
                assert!(
                    table.is_empty(),
                    "expected empty table when configs missing"
                );
            }
        };

        #[cfg(target_os = "macos")]
        super::macos::with_cleared_test_managed_preferences(run_test);

        #[cfg(not(target_os = "macos"))]
        run_test();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn managed_preferences_take_highest_precedence() {
        use base64::Engine;

        let managed_payload = r#"
[nested]
value = "managed"
flag = false
"#;
        let encoded = base64::prelude::BASE64_STANDARD.encode(managed_payload.as_bytes());

        super::macos::with_encoded_test_managed_preferences(&encoded, || {
            let tmp = tempdir().expect("tempdir");
            std::fs::write(
                tmp.path().join(CONFIG_TOML_FILE),
                r#"[nested]
value = "base"
"#,
            )
            .expect("write base");
            std::fs::write(
                tmp.path().join(MANAGED_CONFIG_TOML_FILE),
                r#"[nested]
value = "managed_config"
flag = true
"#,
            )
            .expect("write managed config");

            let loaded = load_config_as_toml(tmp.path()).expect("load config");
            let nested = loaded
                .get("nested")
                .and_then(|v| v.as_table())
                .expect("nested table");
            assert_eq!(
                nested.get("value"),
                Some(&TomlValue::String("managed".to_string()))
            );
            assert_eq!(nested.get("flag"), Some(&TomlValue::Boolean(false)));
        });
    }
}
