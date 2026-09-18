"""Encrypted, authenticated and restricted Pickle-backed object storage.

The module deliberately does not expose a general-purpose ``pickle.loads``
path.  Files are authenticated before decryption and decoded through an
allowlist-based unpickler with no dynamic imports.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import logging
import os
import pickle
import pickletools
import secrets
import shutil
import struct
import tempfile
import time
import zlib
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from re import fullmatch
from typing import Any, ClassVar, Iterator, TypeVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import (
    MissingKeyError,
    StorageConfigurationError,
    StorageFormatError,
    StorageIntegrityError,
    StorageLockError,
    StorageSizeError,
    StorageTypeError,
    UnsafeTypeError,
)

logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_MISSING = object()

KEY_SIZE = 32
NONCE_SIZE = 12
HMAC_SIZE = 32
DEFAULT_MAX_FILE_SIZE = 64 * 1024 * 1024
DEFAULT_BACKUPS = 3
DEFAULT_LOCK_TIMEOUT = 5.0
DEFAULT_COMPRESSION = True
DEFAULT_PATH = "storage.lockbox"

_MAGIC = b"EZST"
_FORMAT_VERSION = 1
_FLAG_COMPRESSED = 0x01
_KNOWN_FLAGS = _FLAG_COMPRESSED
_HEADER = struct.Struct("!4sBBHQQ12s")
_ENVELOPE_OVERHEAD = _HEADER.size + HMAC_SIZE + 16

# This is intentionally a small set.  Lists, dictionaries, strings, numbers
# and byte values are useful application state and do not require imports or
# user-defined code during loading.  Custom classes must be registered on the
# store before loading.
_SAFE_BUILTINS: dict[tuple[str, str], type[Any]] = {
    ("builtins", "NoneType"): type(None),
    ("builtins", "bool"): bool,
    ("builtins", "int"): int,
    ("builtins", "float"): float,
    ("builtins", "complex"): complex,
    ("builtins", "bytes"): bytes,
    ("builtins", "bytearray"): bytearray,
    ("builtins", "str"): str,
    ("builtins", "tuple"): tuple,
    ("builtins", "list"): list,
    ("builtins", "dict"): dict,
    ("builtins", "set"): set,
    ("builtins", "frozenset"): frozenset,
}

# Protocol 4/5 structural opcodes plus the opcodes needed for explicitly
# registered classes.  GLOBAL/STACK_GLOBAL are still gated by
# _RestrictedUnpickler.find_class, so they can never import arbitrary names.
_ALLOWED_OPCODES = {
    "PROTO",
    "FRAME",
    "STOP",
    "NONE",
    "NEWTRUE",
    "NEWFALSE",
    "BININT",
    "BININT1",
    "BININT2",
    "LONG1",
    "LONG4",
    "BINFLOAT",
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "SHORT_BINBYTES",
    "BINBYTES",
    "BINBYTES8",
    "BYTEARRAY8",
    "EMPTY_TUPLE",
    "TUPLE",
    "TUPLE1",
    "TUPLE2",
    "TUPLE3",
    "EMPTY_LIST",
    "LIST",
    "APPEND",
    "APPENDS",
    "EMPTY_DICT",
    "DICT",
    "SETITEM",
    "SETITEMS",
    "EMPTY_SET",
    "ADDITEMS",
    "FROZENSET",
    "MARK",
    "MEMOIZE",
    "BINPUT",
    "LONG_BINPUT",
    "BINGET",
    "LONG_BINGET",
    "POP",
    "POP_MARK",
    "DUP",
    "GLOBAL",
    "STACK_GLOBAL",
    "REDUCE",
    "NEWOBJ",
    "NEWOBJ_EX",
    "BUILD",
}


def generate_key() -> bytes:
    """Return a cryptographically random 256-bit storage key."""

    return secrets.token_bytes(KEY_SIZE)


def encode_key(key: bytes | bytearray | memoryview) -> str:
    """Encode a raw 32-byte key for an environment variable."""

    raw = _normalise_key(key)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _normalise_key(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("base64:"):
            text = text[7:]
            raw = _decode_base64(text)
        elif text.startswith("b64:"):
            text = text[4:]
            raw = _decode_base64(text)
        elif text.startswith("hex:"):
            try:
                raw = bytes.fromhex(text[4:])
            except ValueError as exc:
                raise StorageConfigurationError("EZ storage key is not valid hex") from exc
        else:
            try:
                raw = _decode_base64(text)
            except StorageConfigurationError:
                try:
                    raw = bytes.fromhex(text)
                except ValueError as exc:
                    raise StorageConfigurationError(
                        "key must be 32 raw bytes, base64, or hex"
                    ) from exc
    else:
        raise StorageConfigurationError("key must be bytes or an encoded string")

    if len(raw) != KEY_SIZE:
        raise StorageConfigurationError("storage key must decode to exactly 32 bytes")
    return raw


def _decode_base64(text: str) -> bytes:
    if not text:
        raise StorageConfigurationError("storage key is empty")
    try:
        encoded = text.encode("ascii", errors="strict")
    except UnicodeEncodeError as exc:
        raise StorageConfigurationError("storage key is not valid base64") from exc
    encoded += b"=" * (-len(encoded) % 4)
    try:
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError, base64.binascii.Error) as exc:
        raise StorageConfigurationError("storage key is not valid base64") from exc


def _parse_size(value: int | str) -> int:
    if isinstance(value, bool):
        raise StorageConfigurationError("max_file_size must be a positive integer or size string")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        text = value.strip().replace("_", "").upper()
        match = fullmatch(
            r"([0-9]+(?:\.[0-9]+)?)\s*(B|KB|KIB|MB|MIB|GB|GIB|TB|TIB)?", text, flags=0
        )
        if not match:
            raise StorageConfigurationError(
                "invalid size; use bytes or values such as 64MiB, 1GB, or 500KB"
            )
        number, suffix = match.groups()
        multipliers = {
            None: 1,
            "B": 1,
            "KB": 1_000,
            "MB": 1_000_000,
            "GB": 1_000_000_000,
            "TB": 1_000_000_000_000,
            "KIB": 1 << 10,
            "MIB": 1 << 20,
            "GIB": 1 << 30,
            "TIB": 1 << 40,
        }
        result = int(float(number) * multipliers[suffix])
    else:
        raise StorageConfigurationError("max_file_size must be an integer or size string")
    if result <= 0:
        raise StorageConfigurationError("max_file_size must be greater than zero")
    return result


def _parse_nonnegative_int(value: int | str, name: str) -> int:
    if isinstance(value, bool):
        raise StorageConfigurationError(f"{name} must be a non-negative integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise StorageConfigurationError(f"{name} must be a non-negative integer") from exc
    if result < 0:
        raise StorageConfigurationError(f"{name} must be a non-negative integer")
    return result


def _parse_timeout(value: float | int | str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise StorageConfigurationError("lock_timeout must be a non-negative number") from exc
    if result < 0:
        raise StorageConfigurationError("lock_timeout must be a non-negative number")
    return result


def _parse_bool(value: bool | str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on", "y"}:
            return True
        if text in {"0", "false", "no", "off", "n"}:
            return False
    raise StorageConfigurationError("compression must be true/false, yes/no, or 1/0")


def _derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2,
        salt=None,
        info=b"ez-storage/v2 key separation",
    ).derive(master_key)
    return derived[:KEY_SIZE], derived[KEY_SIZE:]


def _validate_pickle_opcodes(payload: bytes) -> None:
    """Reject unsupported Pickle protocols, opcodes and trailing bytes."""

    seen_protocol = False
    stop_position: int | None = None
    try:
        for opcode, arg, position in pickletools.genops(payload):
            name = opcode.name
            if name not in _ALLOWED_OPCODES:
                raise UnsafeTypeError(f"Pickle opcode {name!r} is not allowed")
            if name == "PROTO":
                if seen_protocol or arg not in {4, 5}:
                    raise StorageFormatError("only Pickle protocol 4 or 5 is supported")
                seen_protocol = True
            elif name == "STOP":
                stop_position = position
        if not seen_protocol:
            raise StorageFormatError("Pickle payload has no supported protocol marker")
        if stop_position is None or stop_position + 1 != len(payload):
            raise StorageFormatError("Pickle payload has no valid final STOP opcode")
    except (StorageFormatError, UnsafeTypeError):
        raise
    except Exception as exc:
        raise StorageFormatError("Pickle opcode validation failed") from exc


class _RestrictedUnpickler(pickle.Unpickler):
    def __init__(self, file: io.BytesIO, allowed_globals: Mapping[tuple[str, str], Any]):
        super().__init__(file)
        self._allowed_globals = allowed_globals

    def find_class(self, module: str, name: str) -> Any:
        key = (module, name)
        try:
            return self._allowed_globals[key]
        except KeyError as exc:
            raise UnsafeTypeError(
                f"Pickle global {module}.{name} is not registered; "
                "register the class explicitly before loading"
            ) from exc


class _FileLock:
    """Small standard-library cross-platform advisory file lock."""

    def __init__(self, path: Path, timeout: float):
        self.path = path
        self.timeout = timeout
        self._handle: Any = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        if os.name == "nt":
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._handle = handle
                return
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise StorageLockError(
                        f"could not lock {self.path} within {self.timeout:g} seconds"
                    ) from exc
                time.sleep(0.05)

    def release(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> _FileLock:
        self.acquire()
        return self

    def __exit__(self, *_: Any) -> None:
        self.release()


class SecureStore:
    """A simple encrypted object store backed by one authenticated file.

    The store reads configuration using this precedence:

    ``per-call override > constructor value > environment > default``.

    The encryption key has no default.  Files are only decoded with safe
    built-in values and classes explicitly registered with ``register_type``.
    """

    _ENV_NAMES: ClassVar[dict[str, str]] = {
        "path": "PATH",
        "key": "KEY",
        "max_file_size": "MAX_FILE_SIZE",
        "backups": "BACKUPS",
        "lock_timeout": "LOCK_TIMEOUT",
        "compression": "COMPRESSION",
    }

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        key: bytes | bytearray | memoryview | str | None = None,
        max_file_size: int | str | None = None,
        backups: int | str | None = None,
        lock_timeout: float | int | str | None = None,
        compression: bool | str | None = None,
        env_prefix: str = "PYLOCKBOX_",
        env: Mapping[str, str] | None = None,
        allowed_types: Iterable[type[Any]] | None = None,
    ):
        if not isinstance(env_prefix, str):
            raise StorageConfigurationError("env_prefix must be a string")
        self._path = Path(path) if path is not None else None
        self._key = key
        self._max_file_size = max_file_size
        self._backups = backups
        self._lock_timeout = lock_timeout
        self._compression = compression
        self._env_prefix = env_prefix
        self._env: Mapping[str, str] = os.environ if env is None else env
        self._allowed_globals: dict[tuple[str, str], Any] = dict(_SAFE_BUILTINS)
        self._data: Any = _MISSING

        if allowed_types is not None:
            for type_ in allowed_types:
                self.register_type(type_)

    @classmethod
    def from_env(
        cls,
        *,
        prefix: str = "PYLOCKBOX_",
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> SecureStore:
        """Create a store whose unset options are read from ``env``."""

        return cls(env_prefix=prefix, env=env, **overrides)

    @staticmethod
    def generate_key() -> bytes:
        """Return a new random 256-bit key."""

        return generate_key()

    @staticmethod
    def encode_key(key: bytes | bytearray | memoryview) -> str:
        """Return a URL-safe base64 key suitable for an environment variable."""

        return encode_key(key)

    @property
    def path(self) -> Path:
        """The currently resolved storage path."""

        return self._resolve_path()

    @property
    def data(self) -> Any:
        """The in-memory value, or ``None`` until a value has been loaded."""

        return None if self._data is _MISSING else self._data

    def register_type(self, type_: type[_T]) -> type[_T]:
        """Allow one user-defined class to be decoded by this store.

        Registration is intentionally explicit and local to this instance;
        the loader never imports a module based on data found in the file.
        """

        if not isinstance(type_, type):
            raise StorageConfigurationError("register_type expects a class")
        module = getattr(type_, "__module__", "")
        name = getattr(type_, "__qualname__", "")
        if not module or not name or "<locals>" in name:
            raise StorageConfigurationError(
                "registered classes must be top-level classes with a stable qualified name"
            )
        self._allowed_globals[(module, name)] = type_
        return type_

    def configure(
        self,
        *,
        path: str | os.PathLike[str] | None | object = _MISSING,
        key: bytes | bytearray | memoryview | str | None | object = _MISSING,
        max_file_size: int | str | None | object = _MISSING,
        backups: int | str | None | object = _MISSING,
        lock_timeout: float | int | str | None | object = _MISSING,
        compression: bool | str | None | object = _MISSING,
    ) -> SecureStore:
        """Update constructor-level settings and return ``self``."""

        if path is not _MISSING:
            self._path = None if path is None else Path(path)  # type: ignore[arg-type]
        if key is not _MISSING:
            self._key = key  # type: ignore[assignment]
        if max_file_size is not _MISSING:
            self._max_file_size = max_file_size  # type: ignore[assignment]
        if backups is not _MISSING:
            self._backups = backups  # type: ignore[assignment]
        if lock_timeout is not _MISSING:
            self._lock_timeout = lock_timeout  # type: ignore[assignment]
        if compression is not _MISSING:
            self._compression = compression  # type: ignore[assignment]
        return self

    def exists(self, *, path: str | os.PathLike[str] | None = None) -> bool:
        """Return whether the resolved storage file exists."""

        return self._resolve_path(path).is_file()

    def load(
        self,
        default: Any = _MISSING,
        *,
        path: str | os.PathLike[str] | None = None,
        key: bytes | bytearray | memoryview | str | None = None,
        max_file_size: int | str | None = None,
        lock_timeout: float | int | str | None = None,
    ) -> Any:
        """Load and return the root object.

        ``key``, ``max_file_size`` and the other constructor settings can be
        overridden for this call.  If the file does not yet exist, ``default``
        is returned; without an explicit default this is an empty dictionary.
        """

        resolved_path = self._resolve_path(path)
        resolved_key = self._resolve_key(key)
        size_limit = self._resolve_max_file_size(max_file_size)
        timeout = self._resolve_lock_timeout(lock_timeout)

        with self._locked(resolved_path, timeout):
            if not resolved_path.exists():
                value = {} if default is _MISSING else default
            else:
                encoded = self._read_limited(resolved_path, size_limit)
                value = self._decode(encoded, resolved_key, size_limit)

        self._data = value
        return value

    def reload(self, *args: Any, **kwargs: Any) -> Any:
        """Alias for :meth:`load`."""

        return self.load(*args, **kwargs)

    def save(
        self,
        value: Any = _MISSING,
        *,
        path: str | os.PathLike[str] | None = None,
        key: bytes | bytearray | memoryview | str | None = None,
        max_file_size: int | str | None = None,
        backups: int | str | None = None,
        lock_timeout: float | int | str | None = None,
        compression: bool | str | None = None,
    ) -> None:
        """Encrypt and atomically save ``value``.

        If ``value`` is omitted, the current in-memory object is saved.  A
        store that has not been loaded starts with an empty dictionary.
        """

        resolved_path = self._resolve_path(path)
        resolved_key = self._resolve_key(key)
        size_limit = self._resolve_max_file_size(max_file_size)
        backup_count = self._resolve_backups(backups)
        timeout = self._resolve_lock_timeout(lock_timeout)
        use_compression = self._resolve_compression(compression)

        if value is _MISSING:
            if self._data is _MISSING:
                value = self.load(
                    path=resolved_path,
                    key=resolved_key,
                    max_file_size=size_limit,
                    lock_timeout=timeout,
                )
            else:
                value = self._data

        encoded = self._encode(value, resolved_key, size_limit, use_compression)
        with self._locked(resolved_path, timeout):
            if resolved_path.exists() and backup_count:
                self._rotate_backups(resolved_path, backup_count)
            self._atomic_write(resolved_path, encoded)
        self._data = value

    def get(self, name: str, default: Any = None) -> Any:
        """Get a top-level or dotted mapping key from the loaded object."""

        mapping = self._ensure_mapping()
        try:
            return self._lookup(mapping, name)
        except KeyError:
            return default

    def set(self, name: str, value: Any, *, autosave: bool = False, **save_options: Any) -> SecureStore:
        """Set a top-level or dotted mapping key."""

        mapping = self._ensure_mapping()
        parts = self._split_key(name)
        current: dict[str, Any] = mapping
        for part in parts[:-1]:
            if part not in current:
                existing = {}
                current[part] = existing
            else:
                existing = current[part]
            if not isinstance(existing, dict):
                raise StorageTypeError(f"cannot descend into non-mapping key {part!r}")
            current = existing
        current[parts[-1]] = value
        if autosave:
            self.save(**save_options)
        return self

    def remove(self, name: str, *, autosave: bool = False, **save_options: Any) -> bool:
        """Remove a mapping key and return whether it existed."""

        mapping = self._ensure_mapping()
        parts = self._split_key(name)
        current: Any = mapping
        for part in parts[:-1]:
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        if not isinstance(current, dict) or parts[-1] not in current:
            return False
        del current[parts[-1]]
        if autosave:
            self.save(**save_options)
        return True

    def clear(self, *, autosave: bool = False, **save_options: Any) -> SecureStore:
        """Clear the in-memory mapping."""

        self._data = {}
        if autosave:
            self.save(**save_options)
        return self

    def keys(self) -> tuple[Any, ...]:
        """Return root mapping keys."""

        return tuple(self._ensure_mapping().keys())

    def items(self) -> tuple[tuple[Any, Any], ...]:
        """Return root mapping items."""

        return tuple(self._ensure_mapping().items())

    def list_backups(self, *, path: str | os.PathLike[str] | None = None) -> tuple[Path, ...]:
        """Return existing backup paths, newest first."""

        resolved_path = self._resolve_path(path)
        backups = list(resolved_path.parent.glob(f"{resolved_path.name}.bak.*"))
        return tuple(
            sorted(
                (item for item in backups if item.name.rsplit(".bak.", 1)[-1].isdigit()),
                key=lambda item: int(item.name.rsplit(".bak.", 1)[-1]),
            )
        )

    def delete(self, *, path: str | os.PathLike[str] | None = None) -> bool:
        """Delete only the main storage file, leaving backups untouched."""

        resolved_path = self._resolve_path(path)
        timeout = self._resolve_lock_timeout(None)
        with self._locked(resolved_path, timeout):
            try:
                resolved_path.unlink()
            except FileNotFoundError:
                return False
        self._data = _MISSING
        return True

    def _env_value(self, setting: str) -> str | None:
        return self._env.get(f"{self._env_prefix}{self._ENV_NAMES[setting]}")

    def _resolve_path(self, override: str | os.PathLike[str] | None | object = None) -> Path:
        if override is not None:
            return Path(override)  # type: ignore[arg-type]
        if self._path is not None:
            return self._path
        env_value = self._env_value("path")
        return Path(env_value) if env_value else Path(DEFAULT_PATH)

    def _resolve_key(
        self, override: bytes | bytearray | memoryview | str | None = None
    ) -> bytes:
        value: bytes | bytearray | memoryview | str | None = override
        if value is None:
            value = self._key
        if value is None:
            value = self._env_value("key")
        if value is None:
            raise MissingKeyError(
                f"no encryption key configured; set {self._env_prefix}{self._ENV_NAMES['key']} "
                "or pass key=..."
            )
        return _normalise_key(value)

    def _resolve_max_file_size(self, override: int | str | None) -> int:
        value: int | str | None = override
        if value is None:
            value = self._max_file_size
        if value is None:
            value = self._env_value("max_file_size")
        return _parse_size(DEFAULT_MAX_FILE_SIZE if value is None else value)

    def _resolve_backups(self, override: int | str | None) -> int:
        value: int | str | None = override
        if value is None:
            value = self._backups
        if value is None:
            value = self._env_value("backups")
        return _parse_nonnegative_int(DEFAULT_BACKUPS if value is None else value, "backups")

    def _resolve_lock_timeout(self, override: float | int | str | None) -> float:
        value: float | int | str | None = override
        if value is None:
            value = self._lock_timeout
        if value is None:
            value = self._env_value("lock_timeout")
        return _parse_timeout(DEFAULT_LOCK_TIMEOUT if value is None else value)

    def _resolve_compression(self, override: bool | str | None) -> bool:
        value: bool | str | None = override
        if value is None:
            value = self._compression
        if value is None:
            value = self._env_value("compression")
        return _parse_bool(DEFAULT_COMPRESSION if value is None else value)

    @contextmanager
    def _locked(self, path: Path, timeout: float) -> Iterator[None]:
        lock_path = Path(f"{path}.lock")
        with _FileLock(lock_path, timeout):
            yield

    @staticmethod
    def _read_limited(path: Path, size_limit: int) -> bytes:
        try:
            if path.stat().st_size > size_limit:
                raise StorageSizeError(
                    f"storage file is larger than the configured limit of {size_limit} bytes"
                )
            with path.open("rb") as handle:
                data = handle.read(size_limit + 1)
        except FileNotFoundError:
            raise
        if len(data) > size_limit:
            raise StorageSizeError(
                f"storage file grew beyond the configured limit of {size_limit} bytes"
            )
        return data

    @staticmethod
    def _encode(value: Any, key: bytes, size_limit: int, compression: bool) -> bytes:
        try:
            payload = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        except (AttributeError, OverflowError, pickle.PickleError, TypeError, ValueError) as exc:
            raise StorageConfigurationError("value cannot be serialized with Pickle") from exc
        _validate_pickle_opcodes(payload)

        flags = 0
        if compression:
            compressed = zlib.compress(payload, level=9)
            if len(compressed) < len(payload):
                payload = compressed
                flags |= _FLAG_COMPRESSED

        if len(payload) + _ENVELOPE_OVERHEAD > size_limit:
            raise StorageSizeError(
                f"serialized value is larger than the configured limit of {size_limit} bytes"
            )

        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext_size = len(payload) + 16
        header = _HEADER.pack(
            _MAGIC,
            _FORMAT_VERSION,
            flags,
            _HEADER.size,
            time.time_ns() & ((1 << 64) - 1),
            ciphertext_size,
            nonce,
        )
        encryption_key, mac_key = _derive_keys(key)
        ciphertext = ChaCha20Poly1305(encryption_key).encrypt(nonce, payload, header)
        tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
        return header + tag + ciphertext

    def _decode(self, encoded: bytes, key: bytes, size_limit: int) -> Any:
        if len(encoded) > size_limit:
            raise StorageSizeError("storage file exceeds the configured limit")
        if len(encoded) < _HEADER.size + HMAC_SIZE + 16:
            raise StorageFormatError("storage file is truncated")

        header = encoded[: _HEADER.size]
        try:
            magic, version, flags, header_size, _generation, payload_size, nonce = _HEADER.unpack(header)
        except struct.error as exc:
            raise StorageFormatError("invalid storage header") from exc
        if magic != _MAGIC:
            raise StorageFormatError("invalid PyLockbox magic header")
        if version != _FORMAT_VERSION:
            raise StorageFormatError(f"unsupported PyLockbox format version: {version}")
        if header_size != _HEADER.size:
            raise StorageFormatError("invalid PyLockbox header size")
        if flags & ~_KNOWN_FLAGS:
            raise StorageFormatError("storage file uses unknown flags")
        if payload_size < 16:
            raise StorageFormatError("invalid encrypted payload size")
        expected_size = _HEADER.size + HMAC_SIZE + payload_size
        if expected_size != len(encoded):
            raise StorageFormatError("storage file has an invalid payload length")

        tag_start = _HEADER.size
        tag_end = tag_start + HMAC_SIZE
        tag = encoded[tag_start:tag_end]
        ciphertext = encoded[tag_end:]
        encryption_key, mac_key = _derive_keys(key)
        expected_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise StorageIntegrityError("storage authentication failed (wrong key or modified file)")

        try:
            payload = ChaCha20Poly1305(encryption_key).decrypt(nonce, ciphertext, header)
        except InvalidTag as exc:
            raise StorageIntegrityError("storage encryption authentication failed") from exc

        if len(payload) > size_limit:
            raise StorageSizeError("decoded payload exceeds the configured limit")
        if flags & _FLAG_COMPRESSED:
            decompressor = zlib.decompressobj()
            payload = decompressor.decompress(payload, size_limit + 1)
            if len(payload) > size_limit or decompressor.unconsumed_tail:
                raise StorageSizeError("decompressed payload exceeds the configured limit")
            payload += decompressor.flush()
            if len(payload) > size_limit:
                raise StorageSizeError("decompressed payload exceeds the configured limit")
            if not decompressor.eof:
                raise StorageFormatError("compressed payload is incomplete")

        _validate_pickle_opcodes(payload)
        try:
            return _RestrictedUnpickler(io.BytesIO(payload), self._allowed_globals).load()
        except (StorageFormatError, UnsafeTypeError):
            raise
        except Exception as exc:
            raise StorageFormatError("restricted Pickle loading failed") from exc

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            try:
                os.chmod(temporary_path, 0o600)
            except OSError:
                pass
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
            except (OSError, TypeError):
                directory_fd = None
            if directory_fd is not None:
                try:
                    os.fsync(directory_fd)
                except OSError:
                    pass
                finally:
                    os.close(directory_fd)
        finally:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass

    @staticmethod
    def _rotate_backups(path: Path, count: int) -> None:
        for index in range(count, 1, -1):
            source = Path(f"{path}.bak.{index - 1}")
            destination = Path(f"{path}.bak.{index}")
            if source.exists():
                os.replace(source, destination)
        backup = Path(f"{path}.bak.1")
        shutil.copy2(path, backup)
        try:
            os.chmod(backup, 0o600)
        except OSError:
            pass

    def _ensure_mapping(self) -> dict[str, Any]:
        if self._data is _MISSING:
            self.load(default={})
        if not isinstance(self._data, dict):
            raise StorageTypeError("key operations require the stored root object to be a dict")
        return self._data

    @staticmethod
    def _split_key(name: str) -> list[str]:
        if not isinstance(name, str) or not name or name.startswith(".") or name.endswith("."):
            raise StorageConfigurationError("mapping key must be a non-empty string")
        parts = name.split(".")
        if any(not part for part in parts):
            raise StorageConfigurationError("mapping key contains an empty path segment")
        return parts

    @classmethod
    def _lookup(cls, mapping: Mapping[str, Any], name: str) -> Any:
        current: Any = mapping
        for part in cls._split_key(name):
            if not isinstance(current, Mapping):
                raise KeyError(name)
            current = current[part]
        return current


__all__ = ["SecureStore", "encode_key", "generate_key"]
