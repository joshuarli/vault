# vault

Store secrets in the macOS Keychain and inject them into commands.

## Usage

### Store a secret

```bash
vault set OPENAI_API_KEY
```

Prompts securely (echo disabled). Or pipe it in:

```bash
pbpaste | vault set OPENAI_API_KEY
```

### Retrieve a secret

```bash
vault get OPENAI_API_KEY
```

Prints the value and nothing else. Safe for `$(...)`.

### Delete a secret

```bash
vault rm OPENAI_API_KEY
```

### List stored names

```bash
vault ls
```

Names only, never values.

### Run a command with secrets

```bash
vault OPENAI_API_KEY DATABASE_URL -- cargo run
```

Looks up `OPENAI_API_KEY` and `DATABASE_URL` in the Keychain and injects them as environment variables.

Mix with literal values:

```bash
vault OPENAI_API_KEY RUST_LOG=debug PORT=8080 -- cargo run
```

No `--`, no exec:

```bash
vault OPENAI_API_KEY cargo run   # error: expected '--' before command
```

