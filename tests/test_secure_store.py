from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from pylockbox import (
    MissingKeyError,
    SecureStore,
    StorageFormatError,
    StorageIntegrityError,
    StorageSizeError,
    UnsafeTypeError,
    encode_key,
    generate_key,
)


@dataclass
class ExampleState:
    name: str
    count: int


class DangerousValue:
    def __init__(self, marker: str):
        self.marker = marker

    def __reduce__(self):
        return (os.system, (f"touch {self.marker}",))


class SecureStoreTests(unittest.TestCase):
    def test_encrypted_round_trip_and_mapping_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            key = generate_key()

            store = SecureStore(path, key=key, backups=2)
            store.set("profile.name", "Lainup").set("counter", 1).save()

            encoded = path.read_bytes()
            self.assertEqual(encoded[:4], b"EZST")
            self.assertNotIn(b"Lainup", encoded)

            loaded = SecureStore(path, key=encode_key(key)).load()
            self.assertEqual(loaded, {"profile": {"name": "Lainup"}, "counter": 1})

            reloaded_store = SecureStore(path, key=key)
            self.assertEqual(reloaded_store.get("profile.name"), "Lainup")
            self.assertEqual(reloaded_store.get("missing", "fallback"), "fallback")

    def test_wrong_key_and_tampering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            key = generate_key()
            SecureStore(path, key=key).save({"secret": "value"})
            original = path.read_bytes()

            with self.assertRaises(StorageIntegrityError):
                SecureStore(path, key=generate_key()).load()

            tampered = bytearray(original)
            tampered[-1] ^= 0x01
            path.write_bytes(tampered)
            with self.assertRaises(StorageIntegrityError):
                SecureStore(path, key=key).load()

    def test_backups_rotate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            store = SecureStore(path, key=generate_key(), backups=2)
            store.save({"version": 1})
            store.save({"version": 2})
            store.save({"version": 3})

            backups = store.list_backups()
            self.assertEqual([item.name for item in backups], ["state.lockbox.bak.1", "state.lockbox.bak.2"])

    def test_restricted_loader_requires_explicit_class_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            key = generate_key()
            SecureStore(path, key=key).save({"state": ExampleState("demo", 3)})

            with self.assertRaises(UnsafeTypeError):
                SecureStore(path, key=key).load()

            trusted = SecureStore(path, key=key)
            trusted.register_type(ExampleState)
            self.assertEqual(trusted.load()["state"], ExampleState("demo", 3))

    def test_restricted_loader_does_not_execute_arbitrary_reduce(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            marker = str(Path(temporary_directory) / "should-not-exist")
            path = Path(temporary_directory) / "state.lockbox"
            key = generate_key()
            SecureStore(path, key=key).save(DangerousValue(marker))

            with self.assertRaises(UnsafeTypeError):
                SecureStore(path, key=key).load()
            self.assertFalse(Path(marker).exists())

    def test_environment_configuration_and_load_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "from-env.lockbox"
            key = generate_key()
            environment = {
                "APP_STORAGE_PATH": str(path),
                "APP_STORAGE_KEY": encode_key(key),
                "APP_STORAGE_MAX_FILE_SIZE": "1MiB",
                "APP_STORAGE_BACKUPS": "0",
                "APP_STORAGE_COMPRESSION": "off",
            }

            store = SecureStore.from_env(prefix="APP_STORAGE_", env=environment)
            store.save({"from": "environment"})
            loaded = SecureStore.from_env(prefix="APP_STORAGE_", env=environment).load()
            self.assertEqual(loaded, {"from": "environment"})

            other_key = generate_key()
            with self.assertRaises(StorageIntegrityError):
                store.load(key=other_key)
            self.assertEqual(store.load(key=key, max_file_size="2MiB"), {"from": "environment"})

    def test_pylockbox_is_the_default_environment_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "default-prefix.lockbox"
            key = generate_key()
            environment = {
                "PYLOCKBOX_PATH": str(path),
                "PYLOCKBOX_KEY": encode_key(key),
            }

            store = SecureStore.from_env(env=environment)
            store.save({"prefix": "pylockbox"})
            self.assertEqual(SecureStore.from_env(env=environment).load(), {"prefix": "pylockbox"})

    def test_size_limit_and_missing_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            with self.assertRaises(MissingKeyError):
                SecureStore(path).save({"secret": "value"})

            random_payload = os.urandom(4096)
            with self.assertRaises(StorageSizeError):
                SecureStore(path, key=generate_key(), max_file_size="1KiB").save(random_payload)

    def test_invalid_format_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "state.lockbox"
            path.write_bytes(b"not-a-pylockbox-file")
            with self.assertRaises(StorageFormatError):
                SecureStore(path, key=generate_key()).load()


if __name__ == "__main__":
    unittest.main()
