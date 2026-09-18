"""Exception types raised by :mod:`pylockbox`."""

from __future__ import annotations


class StorageError(Exception):
    """Base class for all PyLockbox errors."""


class StorageConfigurationError(StorageError, ValueError):
    """The store configuration is missing or invalid."""


class MissingKeyError(StorageConfigurationError):
    """No encryption key was supplied by code or the environment."""


class StorageFormatError(StorageError):
    """The file is not a supported PyLockbox envelope."""


class StorageIntegrityError(StorageError):
    """The file failed its authentication or integrity checks."""


class StorageSizeError(StorageError):
    """The file or its decoded payload exceeds the configured limit."""


class UnsafeTypeError(StorageError):
    """The restricted Pickle loader encountered an unapproved type or opcode."""


class StorageLockError(StorageError):
    """The storage file could not be locked before the timeout."""


class StorageTypeError(StorageError, TypeError):
    """A key/value operation requires a mapping but found another object."""
