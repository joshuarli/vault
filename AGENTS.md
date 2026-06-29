`vault` is a macOS CLI that stores secrets in the native Keychain and injects them into child processes. Think `env` but the values come from Keychain instead of arguments.

## Architecture

```
src/main.rs     — CLI dispatch, terminal I/O, exec logic
src/keychain.rs — thin wrappers around security-framework for Keychain CRUD
```

Two modes, distinguished by `args[1]`:

| args[1] | Mode | Example |
|----------|------|---------|
| `set`, `get`, `rm`, `ls` | Keychain management | `vault set OPENAI_API_KEY` |
| anything else | Exec mode | `vault OPENAI_API_KEY -- cargo run` |

There is no config, no daemon, no networking, no async, no serialization.

## Keychain model

Generic Password items in the login Keychain:

- **Service:** `dev.josh.vault`
- **Account:** the environment variable name
- **Password:** the secret value

Operations use `security_framework::passwords::{get,set,delete}_generic_password`. Listing uses `ItemSearchOptions` with `simplify_dict()` to extract the `"acct"` key. Empty keychain returns `[]` (we catch `errSecItemNotFound`).

## Exec mode

Parse `--` as a separator. Everything before is env specs, everything after is the command.

Env specs before `--`:
- Contains exactly one `=` not at position 0 → literal `NAME=VALUE`
- Otherwise → Keychain lookup

`std::process::Command` spawns the child. No shell. Stdio inherited. Exit with the child's exit code.

## Terminal input

`vault set` disables echo via `rustix::termios` (not libc). On non-TTY stdin, reads from pipe. Terminal state is restored even if `read_line` fails.

## Philosophy

- Simplest correct solution. No premature abstraction.
- Plain functions, no objects, no traits (none needed).
- Match on strings directly instead of a CLI framework — it's 6 lines.
- `Result<_, String>` with hand-rolled error messages. No anyhow.
- Dependencies only when they carry real weight (security-framework, rustix).
- Secrets never logged, debug-printed, or written to disk.
- macOS only. Linux/Windows are non-goals.

## Coding style

- No banner/separator comments.
- Preserve comments that explain *why*.
- Match the surrounding code: same error patterns, same `eprintln!` + `process::exit(1)` style.
- New modules only when genuinely useful. Two files is the right number for this size.
