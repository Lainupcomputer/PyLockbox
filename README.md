# PyLockbox

`PyLockbox` is a small general-purpose object store for Python applications. It stores one
Pickle object in an encrypted, authenticated binary file and provides a simple key/value API for
the common dictionary case.

Version 2 is a breaking rewrite. It intentionally does not read the old JSON format and does not
include a legacy migration layer.

## Install

```bash
python -m pip install pylockbox
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Quick start

The key must be supplied as raw 32-byte data or as base64/hex text. There is no default key.

```python
from pylockbox import SecureStore, encode_key, generate_key

key = generate_key()
print("Store this outside your repository:", encode_key(key))

store = SecureStore("state.lockbox", key=key)
store.set("user.name", "Lainup")
store.set("settings.theme", "dark")
store.save()

reader = SecureStore("state.lockbox", key=key)
print(reader.load())
print(reader.get("user.name"))
```

`save(value)` and `load()` also work with any Pickle-compatible root value. The mapping helpers
(`set`, `get`, `remove`, `keys`, and `items`) require the root value to be a dictionary. Dotted
names such as `settings.theme` address nested dictionaries.

## Environment variables

Use `SecureStore.from_env()` to load configuration from environment variables. The default prefix
is `PYLOCKBOX_`; a custom prefix is supported for applications with multiple stores.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PYLOCKBOX_PATH` | `storage.lockbox` | Storage file path |
| `PYLOCKBOX_KEY` | required | URL-safe base64 or hex encoded 32-byte key |
| `PYLOCKBOX_MAX_FILE_SIZE` | `64MiB` | Maximum file and decoded payload size |
| `PYLOCKBOX_BACKUPS` | `3` | Number of rotating backups; `0` disables backups |
| `PYLOCKBOX_LOCK_TIMEOUT` | `5` | Lock wait time in seconds |
| `PYLOCKBOX_COMPRESSION` | `true` | Compress before encryption when it saves space |

Example in PowerShell:

```powershell
$env:PYLOCKBOX_PATH = "state.lockbox"
$env:PYLOCKBOX_KEY = "paste-a-generated-base64-key-here"
$env:PYLOCKBOX_MAX_FILE_SIZE = "128MiB"
$env:PYLOCKBOX_BACKUPS = "5"
```

```python
from pylockbox import SecureStore

store = SecureStore.from_env()
store.set("counter", 1).save()
```

Configuration precedence is:

```text
per-call override > constructor argument > environment variable > default
```

For example, a one-time load override does not change the store configuration:

```python
value = store.load(key=another_key, max_file_size="256MiB")
```

The library reads environment variables; it never writes secrets back into `os.environ`.

## Security model

Each file contains a versioned binary envelope, not JSON:

- ChaCha20-Poly1305 encrypts and authenticates the payload.
- HKDF separates the encryption and HMAC keys derived from the supplied 32-byte key.
- HMAC-SHA256 authenticates the header and ciphertext as an additional integrity layer.
- Pickle protocol 4/5 opcodes are checked before loading.
- A restricted unpickler allows safe built-in values and classes explicitly registered in code.
- No module is imported because a file requests it; unknown globals and persistent IDs are rejected.
- Maximum file size is checked before reading, and decompression is bounded.
- Writes use a temporary file, `fsync`, and atomic replacement. A cross-platform file lock protects
  concurrent readers/writers, and POSIX files are created with mode `0600` where supported.

### Important Pickle limitation

Pickle is not a security sandbox. This package makes loading substantially safer for authenticated
application state, but no implementation can make arbitrary Pickle data completely safe if an
attacker controls the Python process, obtains the key, or is allowed to register a malicious class.
Only load files protected by a key you trust, and register only classes whose deserialization code
you trust.

## User-defined classes

Custom classes are denied by default. Register the exact class on every process that loads the
file:

```python
from dataclasses import dataclass
from pylockbox import SecureStore

@dataclass
class Profile:
    name: str

key = SecureStore.generate_key()
writer = SecureStore("profiles.lockbox", key=key)
writer.register_type(Profile)
writer.save(Profile("Lainup"))

reader = SecureStore("profiles.lockbox", key=key)
reader.register_type(Profile)
profile = reader.load()
```

This explicit registration is deliberate: arbitrary functions, modules, and classes are not loaded
from file data.

## Development and publishing

Run the tests with the standard library:

```bash
python -m unittest discover -s tests -v
```

The repository includes a build/check/upload script. It does not upload unless `--publish` is
passed, and it never contains a PyPI token:

```bash
# Build and validate only
python scripts/publish.py --clean

# Recommended first upload
python scripts/publish.py --repository testpypi --publish

# Public PyPI upload after TestPyPI verification
python scripts/publish.py --repository pypi --publish
```

On Windows PowerShell the wrapper can be used instead:

```powershell
.\scripts\publish.ps1 --clean
.\scripts\publish.ps1 --repository testpypi --publish
```

Configure credentials through Twine's normal mechanisms (`TWINE_USERNAME`, `TWINE_PASSWORD`, a
keyring, or `.pypirc`). Never commit credentials or a generated storage key.

## License

MIT. See [LICENSE](LICENSE).
