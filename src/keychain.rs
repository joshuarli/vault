use std::process::Command;

const SERVICE: &str = "dev.joshuarli.vault";

#[cfg(not(test))]
mod imp {
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::passwords;

    pub fn set(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        let _ = passwords::delete_generic_password(service, name);
        passwords::set_generic_password(service, name, value).map_err(|e| format!("vault: {}", e))
    }

    pub fn get(service: &str, name: &str) -> Result<String, String> {
        let password = passwords::get_generic_password(service, name)
            .map_err(|_| format!("vault: {} not found", name))?;
        String::from_utf8(password).map_err(|e| format!("vault: invalid UTF-8 in {}: {}", name, e))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        passwords::get_generic_password(service, name)
            .map_err(|_| format!("vault: {} not found", name))?;
        passwords::delete_generic_password(service, name).map_err(|e| format!("vault: {}", e))
    }

    pub fn list(service: &str) -> Result<Vec<String>, String> {
        let items = match ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(service)
            .load_attributes(true)
            .limit(Limit::All)
            .search()
        {
            Ok(items) => items,
            Err(e) if e.code() == security_framework_sys::base::errSecItemNotFound => {
                return Ok(Vec::new());
            }
            Err(e) => return Err(format!("vault: {}", e)),
        };

        let mut names = Vec::new();
        for item in &items {
            if let Some(dict) = item.simplify_dict()
                && let Some(account) = dict.get("acct")
            {
                names.push(account.clone());
            }
        }
        Ok(names)
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_types)]
mod imp {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};

    static STORE: LazyLock<Mutex<HashMap<(String, String), Vec<u8>>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    pub fn set(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        STORE
            .lock()
            .unwrap()
            .insert((service.to_string(), name.to_string()), value.to_vec());
        Ok(())
    }

    pub fn get(service: &str, name: &str) -> Result<String, String> {
        let guard = STORE.lock().unwrap();
        let value = guard
            .get(&(service.to_string(), name.to_string()))
            .ok_or_else(|| format!("vault: {} not found", name))?;
        String::from_utf8(value.clone())
            .map_err(|e| format!("vault: invalid UTF-8 in {}: {}", name, e))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        STORE
            .lock()
            .unwrap()
            .remove(&(service.to_string(), name.to_string()))
            .map(|_| ())
            .ok_or_else(|| format!("vault: {} not found", name))
    }

    pub fn list(service: &str) -> Result<Vec<String>, String> {
        let service = service.to_string();
        let guard = STORE.lock().unwrap();
        let mut names: Vec<String> = guard
            .keys()
            .filter(|(s, _)| *s == service)
            .map(|(_, name)| name.clone())
            .collect();
        names.sort();
        Ok(names)
    }
}

pub fn set_secret(name: &str, value: &[u8]) -> Result<(), String> {
    imp::set(SERVICE, name, value)
}

pub fn get_secret(name: &str) -> Result<String, String> {
    imp::get(SERVICE, name)
}

pub fn delete_secret(name: &str) -> Result<(), String> {
    imp::remove(SERVICE, name)
}

pub fn list_secrets() -> Result<Vec<String>, String> {
    imp::list(SERVICE)
}

/// Spawn `cmd` and exit this process with the child's exit status.
/// If the child was killed by a signal, exits with 128 + signal number.
pub fn spawn_and_exit(mut cmd: Command) -> ! {
    use std::os::unix::process::ExitStatusExt;

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("vault: {}", e);
        std::process::exit(1);
    });

    if let Some(sig) = status.signal() {
        std::process::exit(128 + sig);
    }
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(name: &str) -> String {
        format!("TEST_{name}")
    }

    #[test]
    fn roundtrip() {
        set_secret(&k("R1"), b"hunter2").unwrap();
        assert_eq!(get_secret(&k("R1")).unwrap(), "hunter2");
    }

    #[test]
    fn overwrite_updates() {
        set_secret(&k("OW"), b"first").unwrap();
        set_secret(&k("OW"), b"second").unwrap();
        assert_eq!(get_secret(&k("OW")).unwrap(), "second");
    }

    #[test]
    fn get_missing_is_not_found() {
        let err = get_secret(&k("NOEXIST")).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn delete_missing_is_not_found() {
        let err = delete_secret(&k("NOEXIST")).unwrap_err();
        assert!(err.contains("not found"), "{err}");
    }

    #[test]
    fn delete_then_get_is_missing() {
        set_secret(&k("DEL"), b"x").unwrap();
        delete_secret(&k("DEL")).unwrap();
        assert!(get_secret(&k("DEL")).unwrap_err().contains("not found"));
    }

    #[test]
    fn double_delete_errors() {
        set_secret(&k("DD"), b"x").unwrap();
        delete_secret(&k("DD")).unwrap();
        assert!(delete_secret(&k("DD")).unwrap_err().contains("not found"));
    }

    #[test]
    fn empty_value() {
        set_secret(&k("EMPTY"), b"").unwrap();
        assert_eq!(get_secret(&k("EMPTY")).unwrap(), "");
    }

    #[test]
    fn multiline_value() {
        let secret = "line1\nline2\r\nline3";
        set_secret(&k("ML"), secret.as_bytes()).unwrap();
        assert_eq!(get_secret(&k("ML")).unwrap(), secret);
    }

    #[test]
    fn unicode_value() {
        let secret = "café 🚀 ñoño";
        set_secret(&k("UNI"), secret.as_bytes()).unwrap();
        assert_eq!(get_secret(&k("UNI")).unwrap(), secret);
    }

    #[test]
    fn non_utf8_rejected_on_get() {
        set_secret(&k("BIN"), &[0xFF, 0xFE, 0x00]).unwrap();
        let err = get_secret(&k("BIN")).unwrap_err();
        assert!(err.contains("invalid UTF-8"), "{err}");
    }

    #[test]
    fn special_chars_in_name() {
        set_secret("TEST_UNDER_SCORE.DOT-DASH", b"val").unwrap();
        assert_eq!(get_secret("TEST_UNDER_SCORE.DOT-DASH").unwrap(), "val");
    }

    #[test]
    fn list_reflects_additions_and_deletions() {
        set_secret(&k("L1"), b"a").unwrap();
        set_secret(&k("L2"), b"b").unwrap();
        set_secret(&k("L3"), b"c").unwrap();

        let names = list_secrets().unwrap();
        assert!(names.contains(&k("L1")));
        assert!(names.contains(&k("L2")));
        assert!(names.contains(&k("L3")));

        delete_secret(&k("L1")).unwrap();
        delete_secret(&k("L3")).unwrap();

        let names = list_secrets().unwrap();
        assert!(!names.contains(&k("L1")));
        assert!(names.contains(&k("L2")));
        assert!(!names.contains(&k("L3")));

        delete_secret(&k("L2")).unwrap();
    }

    #[test]
    fn list_never_contains_values() {
        set_secret(&k("LV"), b"secret-value-123").unwrap();
        let names = list_secrets().unwrap();
        assert!(names.contains(&k("LV")));
        assert!(!names.contains(&"secret-value-123".to_string()));
        delete_secret(&k("LV")).unwrap();
    }
}
