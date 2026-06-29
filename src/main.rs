use vault::keychain;

use std::io::{self, IsTerminal, Read, Write};
use std::process::{self, Command};

const USAGE: &str = "\
vault — macOS Keychain secret manager

Usage:

  vault set   <NAME>            Store a secret (prompts for value)
  vault isset <NAME>            Store a secret (silent, no prompt)
  vault get   <NAME>            Print a secret to stdout
  vault rm    <NAME>            Delete a secret
  vault ls                      List all stored secret names

  vault [ENV ...] -- <CMD> [ARGS ...]   Run CMD with secrets injected

Environment specifications before -- may be:

  KEY                          Look up KEY in the Keychain
  KEY=VALUE                    Pass literal KEY=VALUE

Examples:

  vault set OPENAI_API_KEY
  vault OPENAI_API_KEY DATABASE_URL RUST_LOG=debug -- cargo run
  vault -- cargo run
";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print!("{}", USAGE);
        return;
    }

    let first = &args[1];

    match first.as_str() {
        "set" => cmd_set(&args, false),
        "isset" => cmd_set(&args, true),
        "get" => cmd_get(&args),
        "rm" => cmd_rm(&args),
        "ls" => cmd_ls(&args),
        "-h" | "--help" | "help" => {
            print!("{}", USAGE);
        }
        _ => exec_mode(&args[1..]),
    }
}

fn require_exact_args(args: &[String], cmd: &str, expected: usize) {
    if args.len() < expected {
        eprintln!("vault: missing name for {cmd}");
        process::exit(1);
    }
    if args.len() > expected {
        eprintln!("vault: unexpected argument: {}", args[expected]);
        process::exit(1);
    }
    if args[2].is_empty() {
        eprintln!("vault: empty name not allowed");
        process::exit(1);
    }
}

fn cmd_set(args: &[String], silent: bool) {
    require_exact_args(args, if silent { "isset" } else { "set" }, 3);
    let name = &args[2];
    let value = read_secret(name, silent);
    if let Err(e) = keychain::set_secret(name, value.as_bytes()) {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn cmd_get(args: &[String]) {
    require_exact_args(args, "get", 3);
    let name = &args[2];
    match keychain::get_secret(name) {
        Ok(value) => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let _ = handle.write_all(value.as_bytes());
            let _ = handle.write_all(b"\n");
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

fn cmd_rm(args: &[String]) {
    require_exact_args(args, "rm", 3);
    let name = &args[2];
    if let Err(e) = keychain::delete_secret(name) {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn cmd_ls(args: &[String]) {
    if args.len() > 2 {
        eprintln!("vault: ls takes no arguments");
        process::exit(1);
    }
    match keychain::list_secrets() {
        Ok(names) => {
            for name in names {
                println!("{}", name);
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    }
}

fn exec_mode(args: &[String]) {
    let dash_pos = args.iter().position(|a| a == "--");

    let dash_pos = match dash_pos {
        Some(p) => p,
        None => {
            eprintln!("vault: expected '--' before command");
            process::exit(1);
        }
    };

    let env_specs = &args[..dash_pos];
    let cmd_args = &args[dash_pos + 1..];

    if cmd_args.is_empty() {
        eprintln!("vault: missing command");
        process::exit(1);
    }

    let mut cmd = Command::new(&cmd_args[0]);
    cmd.args(&cmd_args[1..]);

    for spec in env_specs {
        // Exactly one '=' not at position 0 → literal NAME=VALUE.
        if let Some((name, value)) = spec.split_once('=')
            && !name.is_empty()
            && !value.contains('=')
        {
            cmd.env(name, value);
            continue;
        }
        let value = keychain::get_secret(spec).unwrap_or_else(|e| {
            eprintln!("{}", e);
            process::exit(1);
        });
        cmd.env(spec, &value);
    }

    keychain::spawn_and_exit(cmd);
}

fn read_secret(name: &str, silent: bool) -> String {
    if io::stdin().is_terminal() {
        if !silent {
            eprint!("Enter value for {}: ", name);
            io::stderr().flush().unwrap();
        }
        read_without_echo()
    } else {
        let mut value = String::new();
        io::stdin().read_to_string(&mut value).unwrap_or_else(|e| {
            eprintln!("vault: failed to read stdin: {}", e);
            process::exit(1);
        });
        strip_trailing_newline(&mut value);
        value
    }
}

fn read_without_echo() -> String {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let stdin = io::stdin();

    let Ok(original) = tcgetattr(&stdin) else {
        let mut value = String::new();
        let _ = io::stdin().read_line(&mut value);
        strip_trailing_newline(&mut value);
        return value;
    };

    let mut termios = original.clone();
    termios.local_modes &= !(LocalModes::ECHO | LocalModes::ECHONL);
    let _ = tcsetattr(&stdin, OptionalActions::Now, &termios);

    // Restore terminal on drop — works for panics and early returns.
    // Scoped so terminal is always restored before any process::exit,
    // since process::exit skips destructors.
    struct Restore(io::Stdin, rustix::termios::Termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = tcsetattr(&self.0, OptionalActions::Now, &self.1);
        }
    }

    let mut value = String::new();
    let result = {
        let _restore = Restore(stdin, original);
        io::stdin().read_line(&mut value)
    };

    match result {
        Ok(_) => {
            strip_trailing_newline(&mut value);
            value
        }
        Err(e) => {
            eprintln!("vault: failed to read input: {}", e);
            process::exit(1);
        }
    }
}

fn strip_trailing_newline(s: &mut String) {
    if s.ends_with('\n') {
        s.pop();
    }
    if s.ends_with('\r') {
        s.pop();
    }
}
