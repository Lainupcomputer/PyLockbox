"""Secure encrypted Pickle storage for Python applications."""

from .errors import (
    MissingKeyError,
    StorageConfigurationError,
    StorageError,
    StorageFormatError,
    StorageIntegrityError,
    StorageLockError,
    StorageSizeError,
    StorageTypeError,
    UnsafeTypeError,
)
from .secure_store import SecureStore, encode_key, generate_key

__version__ = "2.0.0"

__all__ = [
    "SecureStore",
    "encode_key",
    "generate_key",
    "MissingKeyError",
    "StorageConfigurationError",
    "StorageError",
    "StorageFormatError",
    "StorageIntegrityError",
    "StorageLockError",
    "StorageSizeError",
    "StorageTypeError",
    "UnsafeTypeError",
    "__version__",
]
