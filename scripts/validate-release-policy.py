#!/usr/bin/env python3
"""Load one protected public per-release signing policy."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn

GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KEY_GENERATION = re.compile(r"^[a-z0-9][a-z0-9_-]{0,22}$")
FIELDS = (
    "format",
    "source_repository",
    "git_commit",
    "git_tree",
    "release_archive_sha256",
    "release_manifest_sha256",
    "builder_image_digest",
    "node_version",
    "signing_key_generation",
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def parse_policy(path: Path) -> dict[str, str]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_size <= 0
        or metadata.st_size > 16 * 1024
    ):
        fail("release signing policy is missing, symbolic, empty, or too large")
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("release signing policy is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail("release signing policy is not canonical line-oriented text")
    lines = text.removesuffix("\n").split("\n")
    if len(lines) != len(FIELDS):
        fail("release signing policy has an unexpected field count")

    policy: dict[str, str] = {}
    for expected, line in zip(FIELDS, lines, strict=True):
        name, separator, value = line.partition("=")
        if separator != "=" or name != expected or not value:
            fail(f"release signing policy has invalid field '{expected}'")
        policy[name] = value
    return policy


def append_github_output(path: Path, values: dict[str, str]) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail("GITHUB_OUTPUT is not one safe regular file")
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "a", encoding="ascii", newline="\n") as handle:
        for name, value in values.items():
            handle.write(f"{name}={value}\n")
        handle.flush()
        os.fsync(handle.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--github-output", required=True, type=Path)
    arguments = parser.parse_args()

    if GIT_ID.fullmatch(arguments.release_sha) is None:
        fail("release SHA is invalid")
    if REPOSITORY.fullmatch(arguments.source_repository) is None:
        fail("source repository is invalid")
    if arguments.policy.name != f"{arguments.release_sha}.policy":
        fail("release signing policy filename is not the full release SHA")
    policy = parse_policy(arguments.policy)
    expected = {
        "format": "spy-release-signing-policy-v2",
        "source_repository": arguments.source_repository,
        "git_commit": arguments.release_sha,
        "node_version": "v24.15.0",
    }
    for name, value in expected.items():
        if policy[name] != value:
            fail(f"release signing policy violates field '{name}'")
    if GIT_ID.fullmatch(policy["git_tree"]) is None:
        fail("release signing policy Git tree is invalid")
    for name in ("release_archive_sha256", "release_manifest_sha256"):
        if SHA256.fullmatch(policy[name]) is None:
            fail(f"release signing policy {name} is invalid")
    if OCI_DIGEST.fullmatch(policy["builder_image_digest"]) is None:
        fail("release signing policy builder image is invalid")
    generation = policy["signing_key_generation"]
    if KEY_GENERATION.fullmatch(generation) is None:
        fail("release signing key generation is invalid")
    policy_id = f"{generation}-{arguments.release_sha}"
    append_github_output(
        arguments.github_output,
        {
            "approved_builder_image": policy["builder_image_digest"],
            "approved_git_tree": policy["git_tree"],
            "approved_release_archive_sha256": policy[
                "release_archive_sha256"
            ],
            "approved_release_manifest_sha256": policy[
                "release_manifest_sha256"
            ],
            "signing_policy_id": policy_id,
        },
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"Release signing policy validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
