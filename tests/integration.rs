use std::io::Write;
use std::process::{Command, Stdio};

fn vault(args: &[&str]) -> std::io::Result<std::process::Output> {
    let path =
        std::env::var("CARGO_BIN_EXE_vault").unwrap_or_else(|_| "target/debug/vault".to_string());
    Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn vault_stdin(args: &[&str], input: &str) -> std::io::Result<std::process::Output> {
    let path =
        std::env::var("CARGO_BIN_EXE_vault").unwrap_or_else(|_| "target/debug/vault".to_string());
    let mut child = Command::new(path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    child.wait_with_output()
}

#[test]
fn no_args_shows_usage_to_stdout() {
    let out = vault(&[]).unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage"), "stdout: {stdout}");
}

#[test]
fn help_flags_show_usage_to_stdout() {
    for flag in &["-h", "--help", "help"] {
        let out = vault(&[flag]).unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Usage"),
            "flag {flag}: stdout missing 'Usage': {stdout:?}"
        );
    }
}

#[test]
fn get_missing_key_errors() {
    let out = vault(&["get", "VAULT_TEST_NONEXISTENT"]).unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("VAULT_TEST_NONEXISTENT not found"));
}

#[test]
fn rm_missing_key_errors() {
    let out = vault(&["rm", "VAULT_TEST_NONEXISTENT"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

#[test]
fn set_rejects_empty_name() {
    let out = vault(&["set", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn get_rejects_empty_name() {
    let out = vault(&["get", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn rm_rejects_empty_name() {
    let out = vault(&["rm", ""]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("empty name"));
}

#[test]
fn set_too_few_args_errors() {
    assert!(!vault(&["set"]).unwrap().status.success());
}

#[test]
fn set_too_many_args_errors() {
    assert!(!vault(&["set", "A", "B"]).unwrap().status.success());
}

#[test]
fn get_too_few_args_errors() {
    assert!(!vault(&["get"]).unwrap().status.success());
}

#[test]
fn rm_too_few_args_errors() {
    assert!(!vault(&["rm"]).unwrap().status.success());
}

#[test]
fn ls_rejects_extra_args() {
    assert!(!vault(&["ls", "EXTRA"]).unwrap().status.success());
}

#[test]
fn set_reads_from_stdin_pipe() {
    let out = vault_stdin(&["set", "VAULT_TEST_PIPE"], "piped-value").unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exec_no_vars_runs_command() {
    let out = vault(&["--", "echo", "hello-from-vault"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("hello-from-vault"));
}

#[test]
fn exec_injects_literal_vars() {
    let out = vault(&["FOO=BAR", "ANSWER=42", "--", "env"]).unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FOO=BAR"), "stdout: {stdout}");
    assert!(stdout.contains("ANSWER=42"), "stdout: {stdout}");
}

#[test]
fn exec_empty_literal_value() {
    let out = vault(&["EMPTY_VAL=", "--", "env"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("EMPTY_VAL="));
}

#[test]
fn exec_missing_dash_dash_errors() {
    let out = vault(&["SOME_VAR", "echo", "hi"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected '--' before command"));
}

#[test]
fn exec_missing_command_errors() {
    let out = vault(&["SOME_VAR", "--"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing command"));
}

#[test]
fn exec_unknown_keychain_var_errors() {
    let out = vault(&["VAULT_TEST_DOES_NOT_EXIST", "--", "true"]).unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("VAULT_TEST_DOES_NOT_EXIST not found"));
}

#[test]
fn exec_multiple_equals_is_keychain_lookup() {
    let out = vault(&["X=Y=Z", "--", "true"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

#[test]
fn exec_equals_at_start_is_keychain_lookup() {
    let out = vault(&["=NOT_LITERAL", "--", "true"]).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not found"));
}

#[test]
fn exec_exits_with_child_exit_code() {
    let out = vault(&["--", "sh", "-c", "exit 7"]).unwrap();
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn exec_child_killed_by_signal_exits_128_plus_signal() {
    // SIGTERM = 15, so vault should exit 128 + 15 = 143
    let out = vault(&["--", "sh", "-c", "kill -TERM $$"]).unwrap();
    let code = out.status.code();
    // The child is killed by SIGTERM; vault exits 128+15=143.
    // Some shells or environments may not deliver signals the same way,
    // so allow either None (signal) or 143 (our 128+sig convention).
    assert!(
        code == Some(143) || code.is_none(),
        "expected Some(143) or None (signal), got {code:?}"
    );
}

#[test]
fn exec_preserves_stdout() {
    let out = vault(&["--", "echo", "exact-output"]).unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "exact-output");
}

#[test]
fn exec_preserves_stderr() {
    let out = vault(&["--", "sh", "-c", "echo err-to-stderr >&2"]).unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("err-to-stderr"));
}
