#[cfg(target_os = "macos")]
mod macos;

use std::future::Future;
use std::io;
use std::path::Path;
use tokio::fs;
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

pub fn load_config_as_toml(codex_home: &Path) -> io::Result<TomlValue> {
    let LoadedConfigLayers {
        mut base,
        managed_config,
        managed_preferences,
    } = load_config_layers(codex_home)?;

    for overlay in [managed_config, managed_preferences].into_iter().flatten() {
        merge_toml_values(&mut base, &overlay);
    }

    Ok(base)
}

pub(crate) fn load_config_layers(codex_home: &Path) -> io::Result<LoadedConfigLayers> {
    block_on_config_loader(load_config_layers_async(codex_home))
}

async fn load_config_layers_async(codex_home: &Path) -> io::Result<LoadedConfigLayers> {
    let user_config_path = codex_home.join(CONFIG_TOML_FILE);
    let managed_config_path = codex_home.join(MANAGED_CONFIG_TOML_FILE);

    let (user_config, managed_config, managed_preferences) = tokio::try_join!(
        read_config_from_path(&user_config_path, true),
        read_config_from_path(&managed_config_path, false),
        load_managed_admin_config_async(),
    )?;

    Ok(LoadedConfigLayers {
        base: user_config.unwrap_or_else(default_empty_table),
        managed_config,
        managed_preferences,
    })
}

fn default_empty_table() -> TomlValue {
    TomlValue::Table(Default::default())
}

async fn read_config_from_path(
    path: &Path,
    log_missing_as_info: bool,
) -> io::Result<Option<TomlValue>> {
    match fs::read_to_string(path).await {
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

async fn load_managed_admin_config_async() -> io::Result<Option<TomlValue>> {
    #[cfg(target_os = "macos")]
    {
        match tokio::task::spawn_blocking(load_managed_admin_config).await {
            Ok(result) => result,
            Err(join_error) => {
                match join_error.try_into_panic() {
                    Ok(panic) => {
                        if let Some(msg) = panic.downcast_ref::<&str>() {
                            tracing::error!(
                                "Configuration loader for managed preferences panicked: {msg}"
                            );
                        } else if let Some(msg) = panic.downcast_ref::<String>() {
                            tracing::error!(
                                "Configuration loader for managed preferences panicked: {msg}"
                            );
                        } else {
                            tracing::error!(
                                "Configuration loader for managed preferences panicked"
                            );
                        }
                    }
                    Err(join_error) => {
                        tracing::error!(
                            "Configuration loader for managed preferences failed: {join_error}"
                        );
                    }
                }
                Err(io::Error::other(
                    "Failed to load managed preferences configuration",
                ))
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        load_managed_admin_config()
    }
}

fn block_on_config_loader<F, T>(future: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(future)
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

#[cfg(not(target_os = "macos"))]
fn load_managed_admin_config() -> io::Result<Option<TomlValue>> {
    Ok(None)
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
