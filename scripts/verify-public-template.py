#!/usr/bin/env python3
"""Fail closed on any drift in the public Spy signer repository template."""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

CHECKOUT_SHA = "93cb6efe18208431cddfb8368fd83d5badbf9bfd"
GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
OCI_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
KEY_GENERATION = re.compile(r"^[a-z0-9][a-z0-9_-]{0,22}$")
POLICY_PATH = re.compile(r"^policies/([a-f0-9]{40})[.]policy$")
MAX_STATIC_BYTES = 256 * 1024
MAX_POLICY_BYTES = 16 * 1024

STATIC_FILES = {
    ".github/CODEOWNERS",
    ".github/workflows/bootstrap-signing-key.yml",
    ".github/workflows/seal-signing-policy.yml",
    ".github/workflows/sign-release.yml",
    ".github/workflows/verify-template.yml",
    ".gitignore",
    "README.md",
    "config/github.com.known_hosts",
    "policies/README.md",
    "scripts/bootstrap-signing-key.sh",
    "scripts/extract-signer-handoff.py",
    "scripts/fetch-source-handoff.sh",
    "scripts/publish-immutable-release.sh",
    "scripts/publish-release-keyring.sh",
    "scripts/publish-signing-policy-ref.sh",
    "scripts/validate-r2-capability.py",
    "scripts/validate-release-policy.py",
    "scripts/validate-signing-policy-authority.py",
    "scripts/verify-and-sign-release.py",
    "scripts/verify-public-template.py",
}
EXECUTABLE_FILES = {
    relative for relative in STATIC_FILES if relative.startswith("scripts/")
}
ALLOWED_DIRECTORIES = {
    ".github",
    ".github/workflows",
    "config",
    "policies",
    "scripts",
}
WORKFLOW_POLICY = {
    ".github/workflows/bootstrap-signing-key.yml": (
        {"workflow_dispatch"},
        {"contents": "write"},
        "policy-tag",
        True,
    ),
    ".github/workflows/seal-signing-policy.yml": (
        {"workflow_dispatch"},
        {"contents": "write"},
        "main",
        False,
    ),
    ".github/workflows/sign-release.yml": (
        {"workflow_dispatch"},
        {"contents": "write"},
        "policy-tag",
        True,
    ),
    ".github/workflows/verify-template.yml": (
        {"pull_request", "push"},
        {"contents": "read"},
        "none",
        False,
    ),
}
POLICY_FIELDS = (
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
REQUIRED_EXTERNAL_CONTROL_TEXT = (
    "Branch protection and environment protection are external provisioning preconditions",
    "Verify signer template / verify-template",
    "force pushes, branch deletion and bypass",
    "immutable releases are enabled before bootstrap",
    "exactly one custom tag policy",
    "no independent human approval exists",
)
REQUIRED_MANUAL_BOOTSTRAP_TEXT = {
    ".github/workflows/bootstrap-signing-key.yml": (
        "bootstrap_phase:",
        "confirm_source_deploy_public_key_sha256:",
        "confirm_source_deploy_key_read_only:",
        "inputs.bootstrap_phase == 'prepare'",
    ),
    "scripts/bootstrap-signing-key.sh": (
        "write_manual_registration_summary",
        "finalize phase must not receive signer bootstrap authority",
        "bootstrap_cleanup_required=true",
        "source_deploy_key_read_only_operator_attested=true",
        "source_deploy_key_read_access_machine_verified=true",
    ),
}
FORBIDDEN_SOURCE_ADMIN_BOOTSTRAP_TEXT = (
    "SPY_SOURCE_DEPLOY_KEY_BOOTSTRAP_TOKEN",
    "/repos/${source_repository}/keys",
)


class TemplateError(ValueError):
    """One public-template contract violation."""


def fail(message: str) -> NoReturn:
    raise TemplateError(message)


def read_ascii(path: Path, limit: int = MAX_STATIC_BYTES) -> str:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > limit
    ):
        fail(f"'{path.name}' is not one bounded regular file")
    try:
        return path.read_text(encoding="ascii")
    except UnicodeDecodeError as error:
        raise TemplateError(f"'{path.name}' is not ASCII") from error


def inventory(root: Path) -> set[str]:
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        fail("template root must be one non-symbolic directory")

    files: set[str] = set()

    def walk(directory: Path, prefix: str = "") -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            if not prefix and entry.name == ".git":
                continue
            entry_metadata = entry.stat(follow_symlinks=False)
            mode = entry_metadata.st_mode
            if stat.S_ISDIR(mode):
                if relative not in ALLOWED_DIRECTORIES:
                    fail(f"unexpected directory '{relative}'")
                walk(Path(entry.path), relative)
                continue
            if not stat.S_ISREG(mode):
                fail(f"template entry '{relative}' is not a regular file")
            if entry_metadata.st_nlink != 1:
                fail(f"template file '{relative}' has multiple hard links")
            policy_match = POLICY_PATH.fullmatch(relative)
            if relative not in STATIC_FILES and policy_match is None:
                fail(f"unexpected public template file '{relative}'")
            size_limit = MAX_POLICY_BYTES if policy_match else MAX_STATIC_BYTES
            if not 0 < entry_metadata.st_size <= size_limit:
                fail(f"template file '{relative}' exceeds its size policy")
            expected_mode = 0o755 if relative in EXECUTABLE_FILES else 0o644
            if stat.S_IMODE(mode) != expected_mode:
                fail(
                    f"template file '{relative}' must use mode "
                    f"{expected_mode:04o}"
                )
            files.add(relative)

    walk(root)
    missing = sorted(STATIC_FILES.difference(files))
    if missing:
        fail(f"public template is missing '{missing[0]}'")
    return files


def parse_top_level_mapping(text: str, key: str) -> dict[str, str]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == f"{key}:"]
    if len(starts) != 1:
        fail(f"workflow must contain exactly one top-level '{key}' mapping")
    values: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        if line and not line.startswith((" ", "#")):
            break
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):(.*)", line)
        if match is None:
            continue
        name = match.group(1)
        if name in values:
            fail(f"workflow '{key}' mapping contains duplicate '{name}'")
        values[name] = match.group(2).strip()
    if not values:
        fail(f"workflow top-level '{key}' mapping is empty")
    return values


def validate_workflow(relative: str, path: Path) -> None:
    text = read_ascii(path)
    (
        expected_events,
        expected_permissions,
        ref_policy,
        requires_environment,
    ) = WORKFLOW_POLICY[relative]
    events = parse_top_level_mapping(text, "on")
    if set(events) != expected_events:
        fail(f"workflow '{relative}' has an unauthorized event set")
    permissions = parse_top_level_mapping(text, "permissions")
    if permissions != expected_permissions:
        fail(f"workflow '{relative}' has unauthorized permissions")
    if re.search(r"^[ \t]+permissions:", text, re.MULTILINE):
        fail(f"workflow '{relative}' contains job-level permission drift")
    if "runs-on: ubuntu-24.04" not in text:
        fail(f"workflow '{relative}' does not pin the runner image")

    uses = re.findall(r"^\s*uses:\s*(\S+)\s*$", text, re.MULTILINE)
    if uses != [f"actions/checkout@{CHECKOUT_SHA}"]:
        fail(f"workflow '{relative}' has an unapproved or unpinned action")
    if "persist-credentials: false" not in text:
        fail(f"workflow '{relative}' retains checkout credentials")
    if ref_policy == "main":
        if "if: github.ref == 'refs/heads/main'" not in text:
            fail(f"workflow '{relative}' is not restricted to main")
    elif ref_policy == "policy-tag":
        for required in (
            "'refs/tags/spy-sign-policy-{0}'",
            "github.sha == inputs.signer_sha",
        ):
            if required not in text:
                fail(
                    f"workflow '{relative}' is not bound to one policy tag"
                )
    if requires_environment:
        if "environment: production-signing" not in text:
            fail(f"workflow '{relative}' does not use the signing environment")
    elif re.search(
        r"^[ \t]+environment:\s*production-signing\s*$",
        text,
        re.MULTILINE,
    ):
        fail(f"workflow '{relative}' unexpectedly uses the signing environment")


def validate_policy(path: Path, release_sha: str) -> None:
    text = read_ascii(path, MAX_POLICY_BYTES)
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail(f"policy '{path.name}' is not canonical line-oriented text")
    lines = text.removesuffix("\n").split("\n")
    if len(lines) != len(POLICY_FIELDS):
        fail(f"policy '{path.name}' has an unexpected field count")
    policy: dict[str, str] = {}
    for expected, line in zip(POLICY_FIELDS, lines, strict=True):
        name, separator, value = line.partition("=")
        if separator != "=" or name != expected or not value:
            fail(f"policy '{path.name}' has invalid field '{expected}'")
        policy[name] = value
    if (
        policy["format"] != "spy-release-signing-policy-v2"
        or policy["git_commit"] != release_sha
        or policy["node_version"] != "v24.15.0"
        or REPOSITORY.fullmatch(policy["source_repository"]) is None
        or GIT_ID.fullmatch(policy["git_tree"]) is None
        or SHA256.fullmatch(policy["release_archive_sha256"]) is None
        or SHA256.fullmatch(policy["release_manifest_sha256"]) is None
        or OCI_DIGEST.fullmatch(policy["builder_image_digest"]) is None
        or KEY_GENERATION.fullmatch(policy["signing_key_generation"]) is None
    ):
        fail(f"policy '{path.name}' violates the canonical v2 contract")


def validate_programs(root: Path) -> None:
    for relative in sorted(EXECUTABLE_FILES):
        path = root / relative
        if path.suffix == ".py":
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            except (SyntaxError, UnicodeError) as error:
                raise TemplateError(
                    f"Python program '{relative}' does not parse"
                ) from error
        elif path.suffix == ".sh":
            result = subprocess.run(
                ["/usr/bin/bash", "-n", str(path)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode != 0:
                fail(f"shell program '{relative}' does not parse")


def validate_manual_bootstrap(root: Path) -> None:
    for relative, required_fragments in REQUIRED_MANUAL_BOOTSTRAP_TEXT.items():
        text = read_ascii(root / relative)
        for required in required_fragments:
            if required not in text:
                fail(f"manual bootstrap contract drifted in '{relative}'")
        for forbidden in FORBIDDEN_SOURCE_ADMIN_BOOTSTRAP_TEXT:
            if forbidden in text:
                fail(f"source admin bootstrap authority returned in '{relative}'")


def verify(root: Path) -> None:
    files = inventory(root)
    for relative in sorted(WORKFLOW_POLICY):
        validate_workflow(relative, root / relative)
    for relative in sorted(files):
        match = POLICY_PATH.fullmatch(relative)
        if match is not None:
            validate_policy(root / relative, match.group(1))
    validate_programs(root)
    validate_manual_bootstrap(root)

    verify_workflow = read_ascii(
        root / ".github/workflows/verify-template.yml"
    )
    for required in (
        "scripts/verify-public-template.py --root .",
        "scripts/verify-public-template.py --root . --self-test",
    ):
        if required not in verify_workflow:
            fail("template verification workflow is not self-contained")
    readme = read_ascii(root / "README.md")
    for required in REQUIRED_EXTERNAL_CONTROL_TEXT:
        if required not in readme:
            fail("README omits an external branch-protection assumption")


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="ascii")
    if old not in content:
        raise RuntimeError(f"self-test fixture lacks {old!r}")
    path.write_text(content.replace(old, new, 1), encoding="ascii")
    path.chmod(0o644)


def run_self_test(root: Path) -> None:
    mutations: list[tuple[str, Callable[[Path], None]]] = [
        (
            "unexpected-file",
            lambda candidate: (
                candidate.joinpath("unexpected-secret.txt").write_text(
                    "forbidden\n",
                    encoding="ascii",
                ),
                candidate.joinpath("unexpected-secret.txt").chmod(0o644),
            ),
        ),
        (
            "symbolic-link",
            lambda candidate: (
                candidate.joinpath("README.md").unlink(),
                candidate.joinpath("README.md").symlink_to("/etc/passwd"),
            ),
        ),
        (
            "fifo",
            lambda candidate: (
                candidate.joinpath("config/github.com.known_hosts").unlink(),
                os.mkfifo(candidate / "config/github.com.known_hosts", 0o644),
            ),
        ),
        (
            "oversized-policy",
            lambda candidate: (
                candidate.joinpath(
                    f"policies/{'a' * 40}.policy"
                ).write_bytes(b"x" * (MAX_POLICY_BYTES + 1)),
                candidate.joinpath(
                    f"policies/{'a' * 40}.policy"
                ).chmod(0o644),
            ),
        ),
        (
            "unpinned-action",
            lambda candidate: replace(
                candidate / ".github/workflows/verify-template.yml",
                f"actions/checkout@{CHECKOUT_SHA}",
                "actions/checkout@main",
            ),
        ),
        (
            "forbidden-event",
            lambda candidate: replace(
                candidate / ".github/workflows/sign-release.yml",
                "on:\n  workflow_dispatch:",
                "on:\n  pull_request_target:\n  workflow_dispatch:",
            ),
        ),
        (
            "permission-escalation",
            lambda candidate: replace(
                candidate / ".github/workflows/verify-template.yml",
                "permissions:\n  contents: read",
                "permissions:\n  contents: read\n  id-token: write",
            ),
        ),
        (
            "mutable-signing-ref",
            lambda candidate: replace(
                candidate / ".github/workflows/sign-release.yml",
                "'refs/tags/spy-sign-policy-{0}'",
                "'refs/heads/{0}'",
            ),
        ),
        (
            "seal-environment-escalation",
            lambda candidate: replace(
                candidate / ".github/workflows/seal-signing-policy.yml",
                "  seal:\n",
                "  seal:\n    environment: production-signing\n",
            ),
        ),
        (
            "source-admin-bootstrap",
            lambda candidate: replace(
                candidate / "scripts/bootstrap-signing-key.sh",
                'source_deploy_key_title="spy-release-signer-read-only"',
                "SPY_SOURCE_DEPLOY_KEY_BOOTSTRAP_TOKEN"
                '="forbidden"\n'
                'source_deploy_key_title="spy-release-signer-read-only"',
            ),
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="spy-public-template-test-") as temp:
        baseline = Path(temp) / "baseline"
        shutil.copytree(
            root,
            baseline,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        verify(baseline)
        for name, mutate in mutations:
            candidate = Path(temp) / name
            shutil.copytree(baseline, candidate, symlinks=True)
            mutate(candidate)
            try:
                verify(candidate)
            except TemplateError:
                continue
            fail(f"negative self-test '{name}' was not rejected")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()

    root = arguments.root.resolve(strict=True)
    verify(root)
    if arguments.self_test:
        run_self_test(root)
    print("Public signer template contract verified.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TemplateError) as error:
        print(f"Public signer template verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
