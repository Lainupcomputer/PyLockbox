<div align="center">

# PyLockbox

**Secure, encrypted and easy-to-use object storage for Python applications.**

Encrypted Pickle storage · authenticated files · restricted loading · environment configuration

[![CI](https://github.com/Lainupcomputer/PyLockbox/actions/workflows/ci.yml/badge.svg?branch=v2)](https://github.com/Lainupcomputer/PyLockbox/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Version](https://img.shields.io/badge/Version-2.0.0-7C3AED)
![Security](https://img.shields.io/badge/Security-ChaCha20--Poly1305-8B5CF6)
![License](https://img.shields.io/badge/License-MIT-22C55E)

[Getting Started](#getting-started) · [Environment Variables](#environment-variables) · [Security Model](#security-model) · [API](#api-overview) · [Development](#development)

</div>

---

PyLockbox is a general-purpose storage library for Python. It stores application state in a single encrypted and authenticated binary file while providing a simple dictionary-style API for common key/value data.

The package is designed for configuration, sessions, local application state, caches, and other data that should be protected at rest without requiring a database.

> [!IMPORTANT]
> Version 2.0.0 is a breaking rewrite. PyLockbox v2 intentionally does not read the previous `ez-storage` JSON format and does not include a legacy migration layer.

## Features

- Encrypted binary storage using **ChaCha20-Poly1305**.
- Separate encryption and integrity keys derived with **HKDF**.
- Additional **HMAC-SHA256** authentication for the envelope and ciphertext.
- Restricted Pickle loading with safe built-ins and explicit class registration.
- No dynamic imports based on data stored in a file.
- Atomic writes with temporary files, `fsync`, and replacement.
- Cross-platform file locking for concurrent access.
- Rotating backups with configurable retention.
- File-size and decompression limits to reduce resource-exhaustion risks.
- Optional compression before encryption.
- Environment-variable configuration with custom prefixes.
- Per-call configuration overrides without changing the store defaults.
- Simple dotted-key mapping access such as `profile.name`.
- Python 3.10–3.13 support.

## Getting Started

### Requirements

- Python **3.10 or newer**
- `cryptography >= 42`

### Installation

Install the released package from PyPI:

```bash
python -m pip install pylockbox
```

For local development:

```bash
git clone https://github.com/Lainupcomputer/PyLockbox.git
cd PyLockbox
python -m pip install -e ".[dev]"
```

### Quick start

PyLockbox requires a 32-byte encryption key. There is no insecure default key.

```python
from pylockbox import SecureStore, encode_key, generate_key

key = generate_key()
print("Store this key outside your repository:", encode_key(key))

store = SecureStore("state.lockbox", key=key)
store.set("profile.name", "Lainup")
store.set("settings.theme", "dark")
store.set("launch_count", 1)
store.save()

reader = SecureStore("state.lockbox", key=key)
print(reader.load())
print(reader.get("profile.name"))
```

The generated key must be stored securely. Do not commit it to GitHub or place it directly in source code used in production.

`save(value)` and `load()` also support Pickle-compatible root objects. The dotted-key helpers require the root object to be a dictionary.

## Environment Variables

Use `SecureStore.from_env()` when configuration should come from the process environment. The default prefix is `PYLOCKBOX_`.

| Variable | Default | Description |
| --- | --- | --- |
| `PYLOCKBOX_PATH` | `storage.lockbox` | Storage file path |
| `PYLOCKBOX_KEY` | required | URL-safe base64 or hex encoded 32-byte key |
| `PYLOCKBOX_MAX_FILE_SIZE` | `64MiB` | Maximum storage and decoded payload size |
| `PYLOCKBOX_BACKUPS` | `3` | Number of rotating backups; `0` disables backups |
| `PYLOCKBOX_LOCK_TIMEOUT` | `5` | Lock wait time in seconds |
| `PYLOCKBOX_COMPRESSION` | `true` | Compress when compression reduces the payload size |

Example in Windows PowerShell:

```powershell
$env:PYLOCKBOX_PATH = "state.lockbox"
$env:PYLOCKBOX_KEY = "paste-a-generated-base64-key-here"
$env:PYLOCKBOX_MAX_FILE_SIZE = "128MiB"
$env:PYLOCKBOX_BACKUPS = "5"
$env:PYLOCKBOX_COMPRESSION = "true"
```

```python
from pylockbox import SecureStore

store = SecureStore.from_env()
store.set("counter", 1).save()
value = store.load()
```

Custom prefixes are useful when an application manages more than one store:

```python
store = SecureStore.from_env(prefix="APP_STORAGE_")
```

Configuration precedence is:

```text
per-call override > constructor argument > environment variable > default
```

For example, a one-time load override does not modify the store configuration:

```python
value = store.load(key=another_key, max_file_size="256MiB")
```

PyLockbox reads environment variables but never writes secrets back into `os.environ`.

## Security Model

Every storage file uses a versioned binary envelope rather than JSON:

1. Pickle serializes the application value.
2. Supported Pickle opcodes are validated before loading.
3. The payload is optionally compressed.
4. ChaCha20-Poly1305 encrypts and authenticates the payload.
5. HMAC-SHA256 authenticates the header and ciphertext as an additional integrity layer.
6. A restricted unpickler loads only safe built-ins or classes explicitly registered by the application.

The implementation also applies size limits before reading, bounds decompression, uses atomic file replacement, and protects access with a cross-platform lock.

### Important Pickle limitation

Pickle is not a security sandbox. PyLockbox is intended for authenticated application state protected by a trusted key; it is not intended for arbitrary files from untrusted people.

Do not load a file when an attacker controls the Python process, has obtained the encryption key, or can register malicious classes in your application. Register only classes whose deserialization behavior you trust.

## User-defined Classes

Custom classes are denied by default. Register the exact class on every process that loads the file:

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

print(profile.name)
```

Explicit registration prevents file data from freely importing arbitrary modules, classes, or functions.

## API Overview

| API | Purpose |
| --- | --- |
| `SecureStore(path, key=...)` | Create a configured store |
| `SecureStore.from_env(...)` | Create a store from environment variables |
| `generate_key()` | Generate a cryptographically random 32-byte key |
| `encode_key(key)` | Encode a key for environment variables |
| `store.save(value)` | Encrypt and save a root value |
| `store.load()` | Verify, decrypt, and safely load a value |
| `store.set("a.b", value)` | Set a nested dictionary value |
| `store.get("a.b", default)` | Read a nested dictionary value |
| `store.remove("a.b")` | Remove a nested dictionary value |
| `store.keys()` / `store.items()` | Inspect dictionary contents |
| `store.register_type(MyClass)` | Explicitly allow a custom class |
| `store.list_backups()` | List rotating backup files |
| `store.delete()` | Delete the main storage file |

## Development

Run the test suite with the Python standard library:

```bash
python -m unittest discover -s tests -v
```

The GitHub Actions workflow runs the tests on Python 3.10, 3.11, 3.12, and 3.13.

### Build and validate the package

The repository includes a publishing helper. It builds and validates the package without uploading anything unless `--publish` is explicitly provided:

```bash
# Build and validate only
python scripts/publish.py --clean

# Recommended first upload
python scripts/publish.py --repository testpypi --publish

# Public PyPI upload after TestPyPI verification
python scripts/publish.py --repository pypi --publish
```

Windows PowerShell wrapper:

```powershell
.\scripts\publish.ps1 --clean
.\scripts\publish.ps1 --repository testpypi --publish
```

Configure upload credentials through Twine's normal mechanisms such as `TWINE_USERNAME`, `TWINE_PASSWORD`, a keyring, or `.pypirc`. Never commit credentials or generated storage keys.

## Project Structure

```text
PyLockbox/
├── src/pylockbox/       # Package implementation
├── tests/               # Security and behavior tests
├── scripts/             # Build and publishing helpers
├── pyproject.toml       # Package metadata and tooling
└── README.md            # Documentation
```

## License

PyLockbox is released under the [MIT License](LICENSE).

<div align="center">

Made for Python applications that need simple, protected local storage.

</div>
