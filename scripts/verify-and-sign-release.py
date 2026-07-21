#!/usr/bin/env python3
"""Verify one canonical Spy release archive and emit an Ed25519 response."""

from __future__ import annotations

import argparse
import hashlib
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import NoReturn

GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_./:@+-]+$")
MIGRATION_NAME = re.compile(r"^[0-9]{4}_[a-z0-9_]+[.]sql$")
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 500_000
MAX_PATH_BYTES = 4096
OPENSSL = "/usr/bin/openssl"
SUPABASE_ROOT_CA_SHA256 = (
    "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7"
)

REQUEST_FIELDS = (
    "format",
    "source_repository",
    "source_ref",
    "git_commit",
    "git_tree",
    "release_archive_name",
    "release_archive_sha256",
    "release_manifest_sha256",
    "builder_image_digest",
    "node_version",
)

SOURCE_EVIDENCE_FIELDS = (
    "format",
    "source_transport",
    "source_repository",
    "source_ref",
    "git_commit",
    "git_tree",
    "handoff_bundle_sha256",
    "request_sha256",
    "archive_sha256",
)


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_limited(path: Path, limit: int = 64 * 1024 * 1024) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{path.name} is not a regular file")
    if metadata.st_size > limit:
        fail(f"{path.name} exceeds its size limit")
    return path.read_bytes()


def parse_canonical_fields(
    path: Path,
    expected_fields: tuple[str, ...],
) -> dict[str, str]:
    raw = read_limited(path, 1024 * 1024)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path.name} is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail(f"{path.name} is not canonical line-oriented text")

    lines = text.removesuffix("\n").split("\n")
    if len(lines) != len(expected_fields):
        fail(f"{path.name} has an unexpected field count")

    parsed: dict[str, str] = {}
    for expected_name, line in zip(expected_fields, lines, strict=True):
        name, separator, value = line.partition("=")
        if separator != "=" or name != expected_name or not value:
            fail(f"{path.name} has a non-canonical '{expected_name}' field")
        if name in parsed:
            fail(f"{path.name} contains a duplicate field")
        parsed[name] = value
    return parsed


def validate_relative_path(value: str, *, top_level: str | None = None) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) > 126 for character in value)
    ):
        fail("archive contains an unsafe path")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts):
        fail("archive contains a non-canonical path")
    canonical = str(path)
    if canonical != value:
        fail("archive contains a non-canonical path")
    if top_level is not None and (
        not path.parts or path.parts[0] != top_level
    ):
        fail("archive member is outside the exact release root")
    return canonical


def validate_link_target(member_name: str, target: str, release_sha: str) -> str:
    if (
        not target
        or len(target.encode("utf-8")) > MAX_PATH_BYTES
        or target.startswith("/")
        or "\\" in target
        or any(ord(character) < 32 or ord(character) > 126 for character in target)
    ):
        fail("archive contains an unsafe symbolic-link target")
    resolved = posixpath.normpath(
        posixpath.join(posixpath.dirname(member_name), target)
    )
    validate_relative_path(resolved, top_level=release_sha)
    if resolved == release_sha:
        fail("archive symbolic link resolves to the release root")
    member_parts = PurePosixPath(member_name).parts[1:]
    resolved_parts = PurePosixPath(resolved).parts[1:]
    for service_boundary in (
        ("apps", "web"),
        ("apps", "control-worker"),
        ("apps", "reconciler"),
        ("ops", "auth-browser-acceptance"),
        ("ops", "r2-production-acceptance"),
    ):
        if member_parts[:2] == service_boundary and (
            resolved_parts[:2] != service_boundary
        ):
            fail("archive symbolic link crosses a service boundary")
    return resolved


def extract_archive(archive: Path, destination: Path, release_sha: str) -> Path:
    archive_metadata = archive.lstat()
    if (
        not stat.S_ISREG(archive_metadata.st_mode)
        or archive.is_symlink()
        or archive_metadata.st_size <= 0
        or archive_metadata.st_size > MAX_ARCHIVE_BYTES
    ):
        fail("unsigned release archive is missing, symbolic, empty, or too large")

    members: list[tarfile.TarInfo] = []
    with tarfile.open(archive, mode="r:gz") as bundle:
        for member in bundle:
            members.append(member)
            if len(members) > MAX_MEMBERS:
                fail("unsigned release archive has too many members")
        if not members:
            fail("unsigned release archive is empty")

        seen: set[str] = set()
        expanded_bytes = 0
        for member in members:
            name = member.name.rstrip("/")
            validate_relative_path(name, top_level=release_sha)
            if name in seen:
                fail("unsigned release archive contains a duplicate path")
            seen.add(name)
            if member.uid != 0 or member.gid != 0 or member.mtime != 0:
                fail("unsigned release archive metadata is not deterministic")
            if member.isdir():
                if stat.S_IMODE(member.mode) != 0o550:
                    fail("unsigned release directory mode is not 0550")
            elif member.isfile():
                if stat.S_IMODE(member.mode) != 0o440:
                    fail("unsigned release file mode is not 0440")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    fail("unsigned release file exceeds its size limit")
                expanded_bytes += member.size
                if expanded_bytes > MAX_EXPANDED_BYTES:
                    fail("unsigned release expands beyond its total size limit")
            elif member.issym():
                validate_link_target(name, member.linkname, release_sha)
            else:
                fail("unsigned release archive contains an unsupported object")

        release_root = destination / release_sha
        directories = sorted(
            (member for member in members if member.isdir()),
            key=lambda item: (len(PurePosixPath(item.name).parts), item.name),
        )
        files = sorted(
            (member for member in members if member.isfile()),
            key=lambda item: item.name,
        )
        links = sorted(
            (member for member in members if member.issym()),
            key=lambda item: item.name,
        )

        for member in directories:
            target = destination / member.name.rstrip("/")
            target.mkdir(mode=0o700, parents=True, exist_ok=False)

        if not release_root.is_dir() or release_root.is_symlink():
            fail("unsigned release archive has no exact release root")

        for member in files:
            target = destination / member.name
            if not target.parent.is_dir() or target.parent.is_symlink():
                fail("unsigned release file has an unsafe parent")
            source = bundle.extractfile(member)
            if source is None:
                fail("unsigned release file cannot be read")
            with target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            if target.stat().st_size != member.size:
                fail("unsigned release file length differs from its tar header")
            target.chmod(0o440)

        for member in links:
            target = destination / member.name
            if not target.parent.is_dir() or target.parent.is_symlink():
                fail("unsigned release symbolic link has an unsafe parent")
            target.symlink_to(member.linkname)

        canonical_release_root = release_root.resolve(strict=True)
        for member in links:
            target = destination / member.name
            resolved_target = target.resolve(strict=True)
            if not resolved_target.is_relative_to(canonical_release_root):
                fail("unsigned release symbolic link escapes the release root")

        for member in sorted(
            directories,
            key=lambda item: (len(PurePosixPath(item.name).parts), item.name),
            reverse=True,
        ):
            (destination / member.name.rstrip("/")).chmod(0o550)

    return destination / release_sha


def list_release_entries(
    release_root: Path,
) -> tuple[list[str], dict[str, Path], dict[str, str]]:
    directories: list[str] = []
    files: dict[str, Path] = {}
    links: dict[str, str] = {}

    for current_root, directory_names, file_names in os.walk(
        release_root,
        topdown=True,
        followlinks=False,
    ):
        directory_names.sort()
        file_names.sort()
        current = Path(current_root)
        if current.is_symlink():
            fail("release walk crossed a symbolic link")

        retained_directories: list[str] = []
        for directory_name in directory_names:
            entry = current / directory_name
            relative = entry.relative_to(release_root).as_posix()
            validate_relative_path(relative)
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(entry)
                validate_link_target(
                    f"{release_root.name}/{relative}",
                    target,
                    release_root.name,
                )
                links[relative] = target
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                fail("release contains an unsupported directory entry")
            if stat.S_IMODE(metadata.st_mode) != 0o550:
                fail("release directory mode is not 0550")
            directories.append(relative)
            retained_directories.append(directory_name)
        directory_names[:] = retained_directories

        for file_name in file_names:
            entry = current / file_name
            relative = entry.relative_to(release_root).as_posix()
            validate_relative_path(relative)
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(entry)
                validate_link_target(
                    f"{release_root.name}/{relative}",
                    target,
                    release_root.name,
                )
                links[relative] = target
            elif stat.S_ISREG(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o440:
                    fail("release file mode is not 0440")
                files[relative] = entry
            else:
                fail("release contains an unsupported filesystem object")

    return (
        sorted(directories, key=lambda value: value.encode("ascii")),
        dict(sorted(files.items(), key=lambda item: item[0].encode("ascii"))),
        dict(sorted(links.items(), key=lambda item: item[0].encode("ascii"))),
    )


def parse_manifest(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("release manifest is not ASCII") from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail("release manifest is not canonical line-oriented text")

    entries: dict[str, str] = {}
    for line in text.removesuffix("\n").split("\n"):
        match = re.fullmatch(r"([a-f0-9]{64})  [.]\/(.+)", line)
        if match is None:
            fail("release manifest contains a non-canonical line")
        relative = validate_relative_path(match.group(2))
        if relative in (
            "RELEASE_MANIFEST.sha256",
            "RELEASE_ATTESTATION",
            "RELEASE_ATTESTATION.sig",
        ):
            fail("release manifest inventories a reserved signing file")
        if relative in entries:
            fail("release manifest contains a duplicate path")
        entries[relative] = match.group(1)

    if list(entries) != sorted(entries, key=lambda value: value.encode("ascii")):
        fail("release manifest is not in canonical byte order")
    return entries


def parse_simple_inventory(content: bytes, label: str) -> list[str]:
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} is not ASCII") from error
    if text and (not text.endswith("\n") or "\r" in text or "\0" in text):
        fail(f"{label} is not canonical line-oriented text")
    values = [] if not text else text.removesuffix("\n").split("\n")
    for value in values:
        validate_relative_path(value)
    if values != sorted(values, key=lambda value: value.encode("ascii")):
        fail(f"{label} is not in canonical byte order")
    if len(values) != len(set(values)):
        fail(f"{label} contains duplicate entries")
    return values


def verify_release(
    release_root: Path,
    request: dict[str, str],
) -> None:
    directories, files, links = list_release_entries(release_root)
    required_files = {
        "RELEASE_DIRECTORIES",
        "RELEASE_MANIFEST.sha256",
        "RELEASE_PLATFORM_SMOKE",
        "RELEASE_PROVENANCE",
        "RELEASE_SCHEMA_BUNDLE_SHA256",
        "RELEASE_SCHEMA_LEDGER_HEAD_SHA256",
        "RELEASE_SCHEMA_MIGRATIONS",
        "RELEASE_SHA",
        "RELEASE_SYMLINKS",
        "apps/control-worker/dist/main.mjs",
        "apps/reconciler/dist/main.mjs",
        "apps/web/.next/standalone/apps/web/preflight.mjs",
        "apps/web/.next/standalone/apps/web/server.js",
        "config/control-worker.env.example",
        "config/reconciler.env.example",
        "config/release.env",
        "config/supabase-prod-ca-2021.crt",
        "config/web.env.example",
        "ops/apache/spy.noeryx.com.application.conf",
        "ops/auth-browser-acceptance/dist/main.mjs",
        "ops/auth-browser-acceptance/node_modules/@playwright/test/package.json",
        "ops/auth-browser-acceptance/node_modules/.pnpm/playwright@1.61.1/"
        "node_modules/playwright/package.json",
        "ops/auth-browser-acceptance/node_modules/.pnpm/playwright-core@1.61.1/"
        "node_modules/playwright-core/package.json",
        "ops/auth-browser-acceptance/package.json",
        "ops/r2-production-acceptance/dist/main.mjs",
        "ops/r2-production-acceptance/node_modules/@aws-sdk/client-s3/package.json",
        "ops/r2-production-acceptance/node_modules/@aws-sdk/s3-request-presigner/"
        "package.json",
        "ops/r2-production-acceptance/node_modules/zod/package.json",
        "ops/r2-production-acceptance/package.json",
        "ops/check-node-runtime.mjs",
        "ops/systemd/spy-control-worker.service",
        "ops/systemd/spy-reconciler.service",
        "ops/systemd/spy-web.service",
    }
    missing_required_files = sorted(
        required_files.difference(files),
        key=lambda value: value.encode("ascii"),
    )
    if missing_required_files:
        fail(
            "release is missing required regular file "
            f"'{missing_required_files[0]}'"
        )
    required_directories = {
        "apps/web/.next/standalone/apps/web/.next/static",
        "ops/auth-browser-acceptance/node_modules",
        "ops/r2-production-acceptance/node_modules",
        "packages/db/migrations",
    }
    missing_required_directories = sorted(
        required_directories.difference(directories),
        key=lambda value: value.encode("ascii"),
    )
    if missing_required_directories:
        fail(
            "release is missing required directory "
            f"'{missing_required_directories[0]}'"
        )
    static_asset_prefix = (
        "apps/web/.next/standalone/apps/web/.next/static/"
    )
    if not any(
        relative.startswith(static_asset_prefix)
        for relative in files
    ):
        fail("release web static asset directory contains no regular files")
    if "RELEASE_ATTESTATION" in files or "RELEASE_ATTESTATION.sig" in files:
        fail("signer accepts only an unsigned release")

    manifest_content = read_limited(files["RELEASE_MANIFEST.sha256"])
    if sha256_bytes(manifest_content) != request["release_manifest_sha256"]:
        fail("release manifest digest does not match the signing request")
    manifest = parse_manifest(manifest_content)
    actual_manifest_files = {
        relative: path
        for relative, path in files.items()
        if relative != "RELEASE_MANIFEST.sha256"
    }
    if set(manifest) != set(actual_manifest_files):
        fail("release regular-file inventory does not match its manifest")
    for relative, digest in manifest.items():
        if sha256_file(actual_manifest_files[relative]) != digest:
            fail("release file content does not match its manifest")

    recorded_directories = parse_simple_inventory(
        read_limited(files["RELEASE_DIRECTORIES"]),
        "release directory inventory",
    )
    if recorded_directories != directories:
        fail("release directory inventory does not match")

    symlink_content = read_limited(files["RELEASE_SYMLINKS"]).decode("ascii")
    if symlink_content and (
        not symlink_content.endswith("\n")
        or "\r" in symlink_content
        or "\0" in symlink_content
    ):
        fail("release symlink inventory is not canonical")
    recorded_links: dict[str, str] = {}
    link_lines = (
        []
        if not symlink_content
        else symlink_content.removesuffix("\n").split("\n")
    )
    for line in link_lines:
        relative, separator, target = line.partition("\t")
        if separator != "\t":
            fail("release symlink inventory contains a non-canonical line")
        validate_relative_path(relative)
        validate_link_target(
            f"{release_root.name}/{relative}",
            target,
            release_root.name,
        )
        if relative in recorded_links:
            fail("release symlink inventory contains a duplicate path")
        recorded_links[relative] = target
    if list(recorded_links) != sorted(
        recorded_links,
        key=lambda value: value.encode("ascii"),
    ):
        fail("release symlink inventory is not in canonical byte order")
    if recorded_links != links:
        fail("release symlink inventory does not match")

    provenance_fields = (
        "format",
        "source",
        "git_object_format",
        "git_commit",
        "git_tree",
        "target_os",
        "target_arch",
        "target_libc",
        "build_glibc_version",
        "build_image_digest",
        "node_version",
        "pnpm_version",
    )
    provenance = parse_canonical_fields(
        files["RELEASE_PROVENANCE"],
        provenance_fields,
    )
    expected_provenance = {
        "format": "spy-release-provenance-v1",
        "source": "isolated-git-archive",
        "git_object_format": "sha1",
        "git_commit": request["git_commit"],
        "git_tree": request["git_tree"],
        "target_os": "linux",
        "target_arch": "x64",
        "target_libc": "glibc",
        "build_image_digest": request["builder_image_digest"],
        "node_version": "v24.15.0",
        "pnpm_version": "11.15.1",
    }
    for name, value in expected_provenance.items():
        if provenance[name] != value:
            fail(f"release provenance violates the '{name}' signing policy")
    if re.fullmatch(r"[0-9]+[.][0-9]+", provenance["build_glibc_version"]) is None:
        fail("release provenance has a non-canonical glibc version")

    if read_limited(files["RELEASE_SHA"]) != (
        f"{request['git_commit']}\n".encode()
    ):
        fail("RELEASE_SHA does not match the signing request")
    if sha256_file(files["config/supabase-prod-ca-2021.crt"]) != (
        SUPABASE_ROOT_CA_SHA256
    ):
        fail("release Supabase Root CA differs from signer policy")
    if read_limited(files["config/release.env"]) != (
        "NODE_ENV=production\n"
        "NODE_EXTRA_CA_CERTS=/srv/spy/current/config/"
        "supabase-prod-ca-2021.crt\n"
        f"SPY_RELEASE_SHA={request['git_commit']}\n"
    ).encode():
        fail("release runtime identity is not canonical")
    if read_limited(files["RELEASE_PLATFORM_SMOKE"]) != (
        b"format=spy-platform-smoke-v1\n"
        b"auth_acceptance_module=passed\n"
        b"r2_acceptance_module=passed\n"
        b"sharp_native=passed\n"
        b"standalone_liveness=passed\n"
    ):
        fail("release platform smoke evidence is incomplete")

    migration_prefix = "packages/db/migrations/"
    migration_files = {
        relative.removeprefix(migration_prefix): path
        for relative, path in files.items()
        if relative.startswith(migration_prefix)
    }
    if not migration_files:
        fail("release migration bundle is empty")
    for relative in migration_files:
        if "/" in relative or MIGRATION_NAME.fullmatch(relative) is None:
            fail("release migration bundle contains a non-canonical path")
    if any(
        relative.startswith(migration_prefix)
        for relative in links
    ):
        fail("release migration bundle contains a symbolic link")

    migration_inventory = b"".join(
        (
            f"{sha256_file(migration_files[name])}  ./{name}\n".encode()
            for name in sorted(
                migration_files,
                key=lambda value: value.encode("ascii"),
            )
        )
    )
    if read_limited(files["RELEASE_SCHEMA_MIGRATIONS"]) != migration_inventory:
        fail("release migration inventory does not match")
    if read_limited(files["RELEASE_SCHEMA_BUNDLE_SHA256"]) != (
        f"{sha256_bytes(migration_inventory)}\n".encode()
    ):
        fail("release schema bundle digest does not match")
    ledger_input = b"".join(
        (
            f"{name}:{sha256_file(migration_files[name])}\n".encode()
            for name in sorted(
                migration_files,
                key=lambda value: value.encode("ascii"),
            )
        )
    )
    if read_limited(files["RELEASE_SCHEMA_LEDGER_HEAD_SHA256"]) != (
        f"{sha256_bytes(ledger_input)}\n".encode()
    ):
        fail("release schema ledger head does not match")


def write_output(path: Path, content: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o440,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(0o440)


def sign_attestation(
    private_key: Path,
    attestation: bytes,
    output_directory: Path,
) -> bytes:
    metadata = private_key.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or private_key.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > 64 * 1024
    ):
        fail("signing key must be one non-symbolic regular file with mode 0600")

    attestation_path = output_directory / ".attestation-to-sign"
    signature_path = output_directory / ".signature-in-progress"
    public_key_path = output_directory / ".derived-public-key"
    attestation_path.write_bytes(attestation)
    attestation_path.chmod(0o600)

    subprocess.run(
        [
            OPENSSL,
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            OPENSSL,
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key),
            "-rawin",
            "-in",
            str(attestation_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            OPENSSL,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(attestation_path),
            "-sigfile",
            str(signature_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        fail("Ed25519 detached signature has an unexpected length")
    attestation_path.unlink()
    signature_path.unlink()
    public_key_path.unlink()
    return signature


def validate_request_and_source(
    request: dict[str, str],
    source_evidence: dict[str, str],
    source_repository: str,
    approved_builder_image: str,
    approved_git_tree: str,
    approved_release_archive_sha256: str,
    approved_release_manifest_sha256: str,
    release_sha: str,
    handoff_bundle_sha256: str,
    archive: Path,
    request_path: Path,
) -> None:
    if request["format"] != "spy-signer-request-v2":
        fail("signing request format is unsupported")
    if source_evidence["format"] != "spy-signer-source-evidence-v2":
        fail("source evidence format is unsupported")
    if source_evidence["source_transport"] != (
        "private-r2-eu-presigned-get"
    ):
        fail("source evidence transport is unsupported")
    if not REPOSITORY.fullmatch(source_repository):
        fail("configured source repository is unsafe")
    if not GIT_ID.fullmatch(release_sha):
        fail("release SHA must be one full lowercase GitHub commit ID")
    if not SHA256.fullmatch(handoff_bundle_sha256):
        fail("handoff bundle SHA-256 is invalid")
    if not OCI_DIGEST.fullmatch(approved_builder_image):
        fail("approved builder image policy is invalid")
    if not GIT_ID.fullmatch(approved_git_tree):
        fail("approved Git tree policy is invalid")
    for digest in (
        approved_release_archive_sha256,
        approved_release_manifest_sha256,
    ):
        if not SHA256.fullmatch(digest):
            fail("approved release digest policy is invalid")

    archive_name = f"spy-application-{release_sha}.tar.gz"
    expected = {
        "source_repository": source_repository,
        "source_ref": "refs/heads/main",
        "git_commit": release_sha,
        "git_tree": approved_git_tree,
        "release_archive_name": archive_name,
        "release_archive_sha256": approved_release_archive_sha256,
        "release_manifest_sha256": approved_release_manifest_sha256,
        "builder_image_digest": approved_builder_image,
        "node_version": "v24.15.0",
    }
    for name, value in expected.items():
        if request[name] != value:
            fail(f"signing request violates the '{name}' policy")
    for name in ("source_repository", "source_ref", "git_commit", "git_tree"):
        if source_evidence[name] != request[name]:
            fail(f"source evidence differs from request field '{name}'")
    if not GIT_ID.fullmatch(request["git_tree"]):
        fail("signing request Git tree is invalid")
    if not SHA256.fullmatch(request["release_archive_sha256"]):
        fail("signing request archive digest is invalid")
    if not SHA256.fullmatch(request["release_manifest_sha256"]):
        fail("signing request manifest digest is invalid")
    for name in ("handoff_bundle_sha256", "request_sha256", "archive_sha256"):
        if not SHA256.fullmatch(source_evidence[name]):
            fail("source evidence contains an invalid SHA-256")
    if source_evidence["handoff_bundle_sha256"] != handoff_bundle_sha256:
        fail("source evidence differs from the dispatched handoff SHA-256")
    if source_evidence["request_sha256"] != sha256_file(request_path):
        fail("source request bytes do not match source evidence")
    if source_evidence["archive_sha256"] != (
        request["release_archive_sha256"]
    ):
        fail("source archive evidence does not match the signing request")
    if sha256_file(archive) != request["release_archive_sha256"]:
        fail("source archive bytes do not match the request")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--source-evidence", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--handoff-bundle-sha256", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--approved-builder-image", required=True)
    parser.add_argument("--approved-git-tree", required=True)
    parser.add_argument("--approved-release-archive-sha256", required=True)
    parser.add_argument("--approved-release-manifest-sha256", required=True)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--signer-repository", required=True)
    parser.add_argument("--signer-workflow-sha", required=True)
    arguments = parser.parse_args()

    if not KEY_ID.fullmatch(arguments.signing_key_id):
        fail("signing key ID is invalid")
    if not arguments.signing_key_id.endswith(
        f"-{arguments.release_sha}"
    ):
        fail("signing policy ID is not tied to the full release SHA")
    if not REPOSITORY.fullmatch(arguments.signer_repository):
        fail("signer repository is invalid")
    if not GIT_ID.fullmatch(arguments.signer_workflow_sha):
        fail("signer workflow SHA is invalid")
    if not SAFE_VALUE.fullmatch(arguments.signing_key_id):
        fail("signing key ID contains an unsafe character")

    request = parse_canonical_fields(arguments.request, REQUEST_FIELDS)
    source_evidence = parse_canonical_fields(
        arguments.source_evidence,
        SOURCE_EVIDENCE_FIELDS,
    )
    validate_request_and_source(
        request,
        source_evidence,
        arguments.source_repository,
        arguments.approved_builder_image,
        arguments.approved_git_tree,
        arguments.approved_release_archive_sha256,
        arguments.approved_release_manifest_sha256,
        arguments.release_sha,
        arguments.handoff_bundle_sha256,
        arguments.archive,
        arguments.request,
    )

    output_directory = arguments.output_directory.resolve()
    if output_directory.exists():
        if output_directory.is_symlink() or any(output_directory.iterdir()):
            fail("signer output directory must be absent or empty")
    else:
        output_directory.mkdir(mode=0o700, parents=False)
    output_directory.chmod(0o700)

    with tempfile.TemporaryDirectory(prefix="spy-signer-verify-") as temporary:
        release_root = extract_archive(
            arguments.archive,
            Path(temporary),
            arguments.release_sha,
        )
        verify_release(release_root, request)

    attestation = (
        "format=spy-release-attestation-v2\n"
        f"signing_key_id={arguments.signing_key_id}\n"
        f"source_repository={request['source_repository']}\n"
        f"git_commit={request['git_commit']}\n"
        f"git_tree={request['git_tree']}\n"
        f"release_archive_sha256={request['release_archive_sha256']}\n"
        f"release_manifest_sha256={request['release_manifest_sha256']}\n"
        f"builder_image_digest={request['builder_image_digest']}\n"
        f"node_version={request['node_version']}\n"
    ).encode()
    signature = sign_attestation(
        arguments.private_key,
        attestation,
        output_directory,
    )

    result = (
        "format=spy-signer-result-v3\n"
        f"source_repository={request['source_repository']}\n"
        f"source_ref={request['source_ref']}\n"
        f"git_commit={request['git_commit']}\n"
        f"git_tree={request['git_tree']}\n"
        f"source_request_sha256={sha256_file(arguments.request)}\n"
        f"handoff_bundle_sha256={arguments.handoff_bundle_sha256}\n"
        f"release_archive_sha256={request['release_archive_sha256']}\n"
        f"release_manifest_sha256={request['release_manifest_sha256']}\n"
        f"builder_image_digest={request['builder_image_digest']}\n"
        f"node_version={request['node_version']}\n"
        f"signing_key_id={arguments.signing_key_id}\n"
        f"signer_repository={arguments.signer_repository}\n"
        f"signer_workflow_sha={arguments.signer_workflow_sha}\n"
        f"attestation_sha256={sha256_bytes(attestation)}\n"
        f"signature_sha256={sha256_bytes(signature)}\n"
    ).encode()

    write_output(output_directory / "RELEASE_ATTESTATION", attestation)
    write_output(output_directory / "RELEASE_ATTESTATION.sig", signature)
    write_output(output_directory / "SPY_SIGNER_RESULT", result)
    output_directory.chmod(0o500)

    print(f"Signer response created for {arguments.release_sha}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, tarfile.TarError, ValueError) as error:
        print(f"Spy release signing failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
