#!/usr/bin/env python3
"""Build, validate and optionally publish PyLockbox to PyPI or TestPyPI."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(*args: str) -> None:
    command = [sys.executable, *args]
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository",
        choices=("testpypi", "pypi"),
        default="testpypi",
        help="upload target when --publish is used (default: testpypi)",
    )
    parser.add_argument("--publish", action="store_true", help="upload artifacts after validation")
    parser.add_argument("--skip-tests", action="store_true", help="skip the local unittest suite")
    parser.add_argument("--clean", action="store_true", help="remove build artifacts before building")
    args = parser.parse_args()

    if args.clean:
        for directory_name in ("build", "dist"):
            directory = ROOT / directory_name
            if directory.exists():
                shutil.rmtree(directory)
        for metadata_directory in ROOT.glob("*.egg-info"):
            if metadata_directory.is_dir():
                shutil.rmtree(metadata_directory)

    if not args.skip_tests:
        run("-m", "unittest", "discover", "-s", "tests", "-v")

    run("-m", "build")
    artifacts = sorted(
        path
        for path in (ROOT / "dist").iterdir()
        if path.is_file() and (path.name.endswith(".whl") or path.name.endswith(".tar.gz"))
    )
    if not artifacts:
        raise RuntimeError("no wheel or source archive was created in dist/")

    run("-m", "twine", "check", *(str(path) for path in artifacts))
    if args.publish:
        upload_args = ["-m", "twine", "upload"]
        if args.repository == "testpypi":
            upload_args.extend(("--repository", "testpypi"))
        upload_args.extend(str(path) for path in artifacts)
        run(*upload_args)
    else:
        print("Build and validation completed. Use --publish to upload the artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
