#!/usr/bin/env python3
"""Extract exactly one canonical signer request and release archive."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tarfile
from pathlib import Path
from typing import NoReturn

GIT_ID_LENGTH = 40
MAX_REQUEST_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_HANDOFF_BYTES = MAX_ARCHIVE_BYTES + MAX_REQUEST_BYTES + 4096


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def copy_member(
    bundle: tarfile.TarFile,
    member: tarfile.TarInfo,
    target: Path,
) -> None:
    source = bundle.extractfile(member)
    if source is None:
        fail("signer handoff member cannot be read")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o440,
    )
    with os.fdopen(descriptor, "wb") as output:
        while chunk := source.read(1024 * 1024):
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if target.stat().st_size != member.size:
        fail("signer handoff member length differs from its tar header")
    target.chmod(0o440)


def extract(bundle_path: Path, output_directory: Path, release_sha: str) -> None:
    if (
        len(release_sha) != GIT_ID_LENGTH
        or any(character not in "0123456789abcdef" for character in release_sha)
    ):
        fail("release SHA is invalid")
    metadata = bundle_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or bundle_path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_HANDOFF_BYTES
    ):
        fail("signer handoff is missing, symbolic, empty, or too large")
    if (
        not output_directory.is_dir()
        or output_directory.is_symlink()
        or any(output_directory.iterdir())
    ):
        fail("signer handoff output must be one empty safe directory")

    request_name = f"spy-signer-request-{release_sha}.txt"
    archive_name = f"spy-application-{release_sha}.tar.gz"
    expected_sizes = {
        archive_name: MAX_ARCHIVE_BYTES,
        request_name: MAX_REQUEST_BYTES,
    }
    with tarfile.open(bundle_path, mode="r:") as bundle:
        members = bundle.getmembers()
        if [member.name for member in members] != sorted(expected_sizes):
            fail("signer handoff must contain exactly two canonical files")
        for member in members:
            if (
                not member.isfile()
                or member.name not in expected_sizes
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or stat.S_IMODE(member.mode) != 0o440
                or member.pax_headers
                or member.size <= 0
                or member.size > expected_sizes[member.name]
            ):
                fail("signer handoff member violates the fixed transport policy")
            copy_member(
                bundle,
                member,
                output_directory / member.name,
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    arguments = parser.parse_args()
    extract(
        arguments.bundle,
        arguments.output_directory,
        arguments.release_sha,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, tarfile.TarError, ValueError) as error:
        print(f"Signer handoff extraction failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
