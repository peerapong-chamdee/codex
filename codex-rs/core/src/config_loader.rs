#[cfg(target_os = "macos")]
use base64::Engine;
#[cfg(target_os = "macos")]
use base64::prelude::BASE64_STANDARD;
use std::io;
use std::path::Path;
use std::thread;
use toml::Value as TomlValue;

const CONFIG_TOML_FILE: &str = "config.toml";
const CONFIG_OVERRIDE_TOML_FILE: &str = "config_override.toml";

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

        let mut merged = user_config.unwrap_or_else(default_empty_table);

        for overlay in [override_config, managed_config].into_iter().flatten() {
            merge_toml_values(&mut merged, &overlay);
        }

        Ok(merged)
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

fn merge_toml_values(base: &mut TomlValue, overlay: &TomlValue) {
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
        return;
    }

    *base = overlay.clone();
}

fn load_managed_admin_config() -> io::Result<Option<TomlValue>> {
    load_managed_admin_config_impl()
}

#[cfg(target_os = "macos")]
fn load_managed_admin_config_impl() -> io::Result<Option<TomlValue>> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation::string::CFStringRef;
    use std::ffi::c_void;

    #[cfg(test)]
    {
        if let Ok(encoded) = std::env::var("CODEX_TEST_MANAGED_PREFERENCES_BASE64") {
            let trimmed = encoded.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            return parse_managed_preferences_base64(trimmed).map(Some);
        }
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFPreferencesCopyAppValue(key: CFStringRef, application_id: CFStringRef) -> *mut c_void;
    }

    const MANAGED_PREFERENCES_APPLICATION_ID: &str = "com.openai.codex";
    const MANAGED_PREFERENCES_CONFIG_KEY: &str = "config_toml_base64";

    let application_id = CFString::new(MANAGED_PREFERENCES_APPLICATION_ID);
    let key = CFString::new(MANAGED_PREFERENCES_CONFIG_KEY);

    let value_ref = unsafe {
        CFPreferencesCopyAppValue(
            key.as_concrete_TypeRef(),
            application_id.as_concrete_TypeRef(),
        )
    };

    if value_ref.is_null() {
        tracing::debug!(
            "Managed preferences for {} key {} not found",
            MANAGED_PREFERENCES_APPLICATION_ID,
            MANAGED_PREFERENCES_CONFIG_KEY
        );
        return Ok(None);
    }

    let value = unsafe { CFString::wrap_under_create_rule(value_ref as _) };
    let contents = value.to_string();
    let trimmed = contents.trim();

    parse_managed_preferences_base64(trimmed).map(Some)
}

#[cfg(not(target_os = "macos"))]
fn load_managed_admin_config_impl() -> io::Result<Option<TomlValue>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn parse_managed_preferences_base64(encoded: &str) -> io::Result<TomlValue> {
    let decoded = BASE64_STANDARD.decode(encoded.as_bytes()).map_err(|err| {
        tracing::error!("Failed to decode managed preferences as base64: {err}");
        io::Error::new(io::ErrorKind::InvalidData, err)
    })?;

    let decoded_str = String::from_utf8(decoded).map_err(|err| {
        tracing::error!("Managed preferences base64 contents were not valid UTF-8: {err}");
        io::Error::new(io::ErrorKind::InvalidData, err)
    })?;

    match toml::from_str::<TomlValue>(&decoded_str) {
        Ok(parsed) => Ok(parsed),
        Err(err) => {
            tracing::error!("Failed to parse managed preferences TOML: {err}");
            Err(io::Error::new(io::ErrorKind::InvalidData, err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(target_os = "macos")]
    const MANAGED_ENV: &str = "CODEX_TEST_MANAGED_PREFERENCES_BASE64";

    #[cfg(target_os = "macos")]
    use base64::Engine as _;

    #[cfg(target_os = "macos")]
    struct ManagedEnvGuard {
        previous: Option<String>,
    }

    #[cfg(target_os = "macos")]
    impl ManagedEnvGuard {
        fn set(value: &str) -> Self {
            let previous = std::env::var(MANAGED_ENV).ok();
            std::env::set_var(MANAGED_ENV, value);
            Self { previous }
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for ManagedEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(prev) => std::env::set_var(MANAGED_ENV, prev),
                None => std::env::remove_var(MANAGED_ENV),
            }
        }
    }

    #[test]
    fn merges_override_layer_on_top() {
        #[cfg(target_os = "macos")]
        let _guard = ManagedEnvGuard::set("");

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

        assert_eq!(table.get("foo").and_then(|v| v.as_integer()), Some(2));
        let nested = table
            .get("nested")
            .and_then(|v| v.as_table())
            .expect("nested");
        assert_eq!(
            nested.get("value").and_then(|v| v.as_str()),
            Some("override")
        );
        assert_eq!(nested.get("extra").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn returns_empty_when_all_layers_missing() {
        #[cfg(target_os = "macos")]
        let _guard = ManagedEnvGuard::set("");

        let tmp = tempdir().expect("tempdir");
        let loaded = load_config_as_toml(tmp.path()).expect("load config");
        let table = loaded.as_table().expect("top-level table expected");
        assert!(
            table.is_empty(),
            "expected empty table when configs missing"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn managed_preferences_take_highest_precedence() {
        let _guard = ManagedEnvGuard::set("");
        let managed_payload = r#"
[nested]
value = "managed"
flag = false
"#;
        let encoded = super::BASE64_STANDARD.encode(managed_payload.as_bytes());
        std::env::set_var(MANAGED_ENV, encoded);

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
            nested.get("value").and_then(|v| v.as_str()),
            Some("managed")
        );
        assert_eq!(nested.get("flag").and_then(|v| v.as_bool()), Some(false));
    }
}
