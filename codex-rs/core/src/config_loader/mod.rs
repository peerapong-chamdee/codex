#[cfg(target_os = "macos")]
mod macos;

use std::io;
use std::path::Path;
use std::thread;
use toml::Value as TomlValue;

const CONFIG_TOML_FILE: &str = "config.toml";
const CONFIG_OVERRIDE_TOML_FILE: &str = "config_override.toml";

#[derive(Debug)]
pub(crate) struct LoadedConfigLayers {
    pub base: TomlValue,
    pub override_layer: Option<TomlValue>,
    pub managed_layer: Option<TomlValue>,
}

// Configuration layering pipeline (top overrides bottom):
//
//        +-------------------------+
//        | Managed preferences (*) |
//        +-------------------------+
//                    ^
//                    |
//        +-------------------------+
//        |  config_override.toml   |
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
        override_layer,
        managed_layer,
    } = load_config_layers(codex_home)?;

    for overlay in [override_layer, managed_layer].into_iter().flatten() {
        merge_toml_values(&mut base, &overlay);
    }

    Ok(base)
}

pub(crate) fn load_config_layers(codex_home: &Path) -> io::Result<LoadedConfigLayers> {
    let user_config_path = codex_home.join(CONFIG_TOML_FILE);
    let override_config_path = codex_home.join(CONFIG_OVERRIDE_TOML_FILE);

    thread::scope(|scope| {
        let user_handle = scope.spawn(|| read_config_from_path(&user_config_path, true));
        let override_handle =
            scope.spawn(move || read_config_from_path(&override_config_path, false));
        let managed_handle = scope.spawn(load_managed_admin_config);

        let user_config = join_config_result(user_handle, "user config.toml")?;
        let override_config = join_config_result(override_handle, "config_override.toml")?;
        let managed_config = join_config_result(managed_handle, "managed preferences")?;

        Ok(LoadedConfigLayers {
            base: user_config.unwrap_or_else(default_empty_table),
            override_layer: override_config,
            managed_layer: managed_config,
        })
    })
}

fn default_empty_table() -> TomlValue {
    TomlValue::Table(Default::default())
}

fn join_config_result(
    handle: thread::ScopedJoinHandle<'_, io::Result<Option<TomlValue>>>,
    label: &str,
) -> io::Result<Option<TomlValue>> {
    match handle.join() {
        Ok(result) => result,
        Err(panic) => {
            if let Some(msg) = panic.downcast_ref::<&str>() {
                tracing::error!("Configuration loader for {label} panicked: {msg}");
            } else if let Some(msg) = panic.downcast_ref::<String>() {
                tracing::error!("Configuration loader for {label} panicked: {msg}");
            } else {
                tracing::error!("Configuration loader for {label} panicked");
            }
            Err(io::Error::other(format!(
                "Failed to load {label} configuration"
            )))
        }
    }
}

fn read_config_from_path(path: &Path, log_missing_as_info: bool) -> io::Result<Option<TomlValue>> {
    match std::fs::read_to_string(path) {
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

/// Recursively merge `overlay` into `base`, preserving nested tables.
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
    fn merges_override_layer_on_top() {
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
                tmp.path().join(CONFIG_OVERRIDE_TOML_FILE),
                r#"foo = 2

[nested]
value = "override"
extra = true
"#,
            )
            .expect("write override");

            let loaded = load_config_as_toml(tmp.path()).expect("load config");
            let table = loaded.as_table().expect("top-level table expected");

            assert_eq!(table.get("foo"), Some(&TomlValue::Integer(2)));
            let nested = table
                .get("nested")
                .and_then(|v| v.as_table())
                .expect("nested");
            assert_eq!(
                nested.get("value"),
                Some(&TomlValue::String("override".to_string()))
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
            let loaded = load_config_as_toml(tmp.path()).expect("load config");
            let table = loaded.as_table().expect("top-level table expected");
            assert!(
                table.is_empty(),
                "expected empty table when configs missing"
            );
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
                tmp.path().join(CONFIG_OVERRIDE_TOML_FILE),
                r#"[nested]
value = "override"
flag = true
"#,
            )
            .expect("write override");

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
