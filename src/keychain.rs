use std::process::Command;

const SERVICE: &str = "dev.joshuarli.vault";

// Production implementation — real macOS Keychain via Security framework.
//
// Keychain ACL model (important, non-obvious):
//
//   When SecItemAdd creates a keychain item, macOS automatically adds an
//   application-specific ACL entry that restricts access to the exact binary
//   that created it (matched by filesystem path AND cdhash — the code-directory
//   hash embedded in the ad-hoc signature). Every `cargo build` produces a new
//   cdhash, so the freshly-built vault binary can't access items created by the
//   previous build. The old items still exist — macOS just denies access.
//
//   The fix: create items with the legacy SecKeychainAddGenericPassword API,
//   which does NOT stamp an application-specific ACL (items get
//   `applications: <null>` — any app can access). Updates use the modern
//   SecItemUpdate, which preserves the existing ACL. Both are single calls.
//
// Error reporting:
//
//   We preserve the actual Security framework error instead of mapping
//   everything to "not found". An auth failure (errSecAuthFailed, -25293) and a
//   genuinely missing item (errSecItemNotFound, -25300) need different
//   remedies; collapsing them into one message made this bug hard to diagnose.
//
#[cfg(not(test))]
mod imp {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
    use security_framework::passwords;
    use security_framework_sys::base::{SecKeychainRef, errSecItemNotFound};
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain::{SecKeychainAddGenericPassword, SecKeychainCopyDefault};
    use security_framework_sys::keychain_item::{SecItemDelete, SecItemUpdate};
    use std::ffi::{CString, c_void};

    // Pointer-type coercion helper. The kSec* constants from
    // security-framework-sys are typed as CFStringRef = *const __CFString;
    // we need *const c_void for sec_str.
    unsafe fn sec_str(c: *const c_void) -> CFString {
        unsafe { CFString::wrap_under_get_rule(c as _) }
    }

    macro_rules! k {
        ($const:ident) => {
            ($const as *const c_void)
        };
    }

    /// Build a query dict for matching a vault item by service + account.
    fn query_dict(
        service: &str,
        name: &str,
    ) -> CFDictionary<CFString, core_foundation::base::CFType> {
        let pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![
            (
                unsafe { sec_str(k!(kSecClass)) },
                unsafe { sec_str(k!(kSecClassGenericPassword)) }.into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrService)) },
                CFString::from(service).into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrAccount)) },
                CFString::from(name).into_CFType(),
            ),
        ];
        CFDictionary::from_CFType_pairs(&pairs)
    }

    /// Create a new keychain item. Uses the legacy SecKeychainAddGenericPassword
    /// API because it creates items with `applications: <null>` in a single
    /// call — no ACL fix-up step needed.
    fn create(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        let service_c =
            CString::new(service).map_err(|e| format!("vault: invalid service name: {e}"))?;
        let account_c =
            CString::new(name).map_err(|e| format!("vault: invalid account name: {e}"))?;

        let mut keychain: SecKeychainRef = std::ptr::null_mut();
        let status = unsafe { SecKeychainCopyDefault(&mut keychain) };
        if status != 0 {
            return Err(format!(
                "vault: set failed: SecKeychainCopyDefault OSStatus {status}"
            ));
        }

        let status = unsafe {
            SecKeychainAddGenericPassword(
                keychain,
                service_c.as_bytes().len() as u32,
                service_c.as_ptr(),
                account_c.as_bytes().len() as u32,
                account_c.as_ptr(),
                value.len() as u32,
                value.as_ptr() as *const c_void,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(format!("vault: set failed: OSStatus {status}"));
        }
        Ok(())
    }

    pub fn set(service: &str, name: &str, value: &[u8]) -> Result<(), String> {
        // Try update first — one call for the common "change a secret" case.
        let query = query_dict(service, name);

        let update_pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![(
            unsafe { sec_str(k!(kSecValueData)) },
            CFData::from_buffer(value).into_CFType(),
        )];
        let update = CFDictionary::from_CFType_pairs(&update_pairs);

        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) };

        if status == 0 {
            return Ok(());
        }

        if status == errSecItemNotFound {
            return create(service, name, value);
        }

        Err(format!(
            "vault: set failed: SecItemUpdate returned OSStatus {status}"
        ))
    }

    pub fn get(service: &str, name: &str) -> Result<String, String> {
        let password = passwords::get_generic_password(service, name)
            .map_err(|e| format!("vault: {name}: {e}"))?;
        String::from_utf8(password).map_err(|e| format!("vault: invalid UTF-8 in {name}: {e}"))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        let del_err = match passwords::delete_generic_password(service, name) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        match passwords::get_generic_password(service, name) {
            Ok(_) => Err(format!("vault: {name}: {del_err}")),
            Err(get_err) => Err(format!("vault: {name}: {get_err}")),
        }
    }

    pub fn purge(service: &str) -> Result<usize, String> {
        let before = list(service)?.len();
        if before == 0 {
            return Ok(0);
        }
        // SecItemDelete with a service-only query (no account filter) removes
        // every generic password under that service in one call.
        let pairs: Vec<(CFString, core_foundation::base::CFType)> = vec![
            (
                unsafe { sec_str(k!(kSecClass)) },
                unsafe { sec_str(k!(kSecClassGenericPassword)) }.into_CFType(),
            ),
            (
                unsafe { sec_str(k!(kSecAttrService)) },
                CFString::from(service).into_CFType(),
            ),
        ];
        let params = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemDelete(params.as_concrete_TypeRef()) };
        if status != 0 {
            return Err(format!("vault: purge failed: OSStatus {status}"));
        }
        Ok(before)
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
            Err(e) => return Err(format!("vault: {e}")),
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

// In-memory test store. Keeps unit tests fast and free of macOS keychain
// approval prompts. The integration tests in tests/ cover the real keychain
// path (gated behind #[ignore]).
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
            .ok_or_else(|| format!("vault: {}: not found", name))?;
        String::from_utf8(value.clone())
            .map_err(|e| format!("vault: invalid UTF-8 in {}: {}", name, e))
    }

    pub fn remove(service: &str, name: &str) -> Result<(), String> {
        STORE
            .lock()
            .unwrap()
            .remove(&(service.to_string(), name.to_string()))
            .map(|_| ())
            .ok_or_else(|| format!("vault: {}: not found", name))
    }

    pub fn purge(service: &str) -> Result<usize, String> {
        let service = service.to_string();
        let mut guard = STORE.lock().unwrap();
        let before = guard.keys().filter(|(s, _)| *s == service).count();
        guard.retain(|(s, _), _| *s != service);
        Ok(before)
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

pub fn purge_secrets() -> Result<usize, String> {
    imp::purge(SERVICE)
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

    #[test]
    fn purge_removes_all_for_service() {
        // Clean up from any previous run, then add three items.
        for name in list_secrets().unwrap() {
            if name.starts_with("TEST_P") {
                delete_secret(&name).unwrap();
            }
        }
        set_secret(&k("P1"), b"a").unwrap();
        set_secret(&k("P2"), b"b").unwrap();
        set_secret(&k("P3"), b"c").unwrap();

        let count = purge_secrets().unwrap();
        assert!(count >= 3, "expected at least 3 purged, got {count}");

        let names = list_secrets().unwrap();
        assert!(!names.contains(&k("P1")));
        assert!(!names.contains(&k("P2")));
        assert!(!names.contains(&k("P3")));
    }

    #[test]
    fn purge_empty_returns_zero() {
        for name in list_secrets().unwrap() {
            if name.starts_with("TEST_") {
                delete_secret(&name).unwrap();
            }
        }
        assert_eq!(purge_secrets().unwrap(), 0);
    }
}
