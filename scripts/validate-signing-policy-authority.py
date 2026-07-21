#!/usr/bin/env python3
"""Validate the immutable signer-policy authority and exact dispatched run."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn

GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
POLICY_TAG = re.compile(r"^spy-sign-policy-([a-f0-9]{40})$")
ASSET_NAMES = {
    "SIGNING_POLICY_REF",
    "SIGNING_POLICY_REF_MANIFEST.sha256",
}
EVIDENCE_FIELDS = (
    "format",
    "source_release_sha",
    "signer_repository",
    "signer_commit",
    "policy_path",
    "policy_sha256",
    "sign_workflow_path",
    "sign_workflow_sha256",
    "template_contract_path",
    "template_contract_sha256",
)
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
MAX_JSON_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024
MAX_AUTHORITY_FILE_BYTES = 256 * 1024


class AuthorityError(ValueError):
    """One signer authority contract violation."""


def fail(message: str) -> NoReturn:
    raise AuthorityError(message)


def read_bytes(path: Path, limit: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > limit
    ):
        fail(f"'{path.name}' is not one bounded regular file")
    return path.read_bytes()


def read_ascii(path: Path, limit: int) -> str:
    try:
        return read_bytes(path, limit).decode("ascii")
    except UnicodeDecodeError as error:
        raise AuthorityError(f"'{path.name}' is not ASCII") from error


def read_json(path: Path) -> Any:
    try:
        return json.loads(read_ascii(path, MAX_JSON_BYTES))
    except json.JSONDecodeError as error:
        raise AuthorityError(f"'{path.name}' is not valid JSON") from error


def parse_canonical_lines(
    path: Path,
    fields: tuple[str, ...],
    limit: int,
) -> dict[str, str]:
    text = read_ascii(path, limit)
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        fail(f"'{path.name}' is not canonical line-oriented text")
    lines = text.removesuffix("\n").split("\n")
    if len(lines) != len(fields):
        fail(f"'{path.name}' has an unexpected field count")
    values: dict[str, str] = {}
    for expected, line in zip(fields, lines, strict=True):
        name, separator, value = line.partition("=")
        if separator != "=" or name != expected or not value:
            fail(f"'{path.name}' has invalid field '{expected}'")
        values[name] = value
    return values


def sha256(path: Path, limit: int) -> str:
    return hashlib.sha256(read_bytes(path, limit)).hexdigest()


def validate_asset(
    release: dict[str, Any],
    name: str,
    local_path: Path,
) -> None:
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("policy release has no asset inventory")
    matches = [
        asset
        for asset in assets
        if isinstance(asset, dict)
        and asset.get("name") == name
        and asset.get("state") == "uploaded"
    ]
    if len(matches) != 1:
        fail(f"policy release does not have one uploaded '{name}'")
    asset = matches[0]
    asset_id = asset.get("id")
    asset_size = asset.get("size")
    digest = asset.get("digest")
    if (
        not isinstance(asset_id, int)
        or isinstance(asset_id, bool)
        or asset_id <= 0
        or not isinstance(asset_size, int)
        or isinstance(asset_size, bool)
        or asset_size <= 0
        or asset_size > MAX_EVIDENCE_BYTES
        or digest != f"sha256:{sha256(local_path, MAX_EVIDENCE_BYTES)}"
        or asset_size != local_path.stat().st_size
    ):
        fail(f"policy release asset '{name}' metadata differs")


def validate_authority(arguments: argparse.Namespace) -> None:
    release_sha = arguments.release_sha
    repository = arguments.repository
    signer_tag = arguments.signer_tag
    signer_sha = arguments.signer_sha
    expected_tag = f"spy-sign-policy-{release_sha}"
    if (
        GIT_ID.fullmatch(release_sha) is None
        or GIT_ID.fullmatch(signer_sha) is None
        or REPOSITORY.fullmatch(repository) is None
        or POLICY_TAG.fullmatch(signer_tag) is None
        or signer_tag != expected_tag
    ):
        fail("requested signer policy identity is not canonical")

    release = read_json(arguments.release_json)
    tag_ref = read_json(arguments.tag_ref_json)
    environment = read_json(arguments.environment_json)
    policies = read_json(arguments.policies_json)
    if not all(
        isinstance(value, dict)
        for value in (release, tag_ref, environment, policies)
    ):
        fail("signer authority APIs did not return JSON objects")

    if (
        release.get("tag_name") != signer_tag
        or release.get("target_commitish") != signer_sha
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
        or not isinstance(release.get("id"), int)
        or isinstance(release.get("id"), bool)
        or release["id"] <= 0
    ):
        fail("policy release is not exact, published, and immutable")
    assets = release.get("assets")
    if not isinstance(assets, list) or {
        asset.get("name")
        for asset in assets
        if isinstance(asset, dict)
    } != ASSET_NAMES or len(assets) != len(ASSET_NAMES):
        fail("policy release has an unexpected asset inventory")

    tag_object = tag_ref.get("object")
    if (
        tag_ref.get("ref") != f"refs/tags/{signer_tag}"
        or not isinstance(tag_object, dict)
        or tag_object.get("type") != "commit"
        or tag_object.get("sha") != signer_sha
    ):
        fail("policy tag is not one lightweight reference to the signer commit")

    deployment_policy = environment.get("deployment_branch_policy")
    if (
        environment.get("name") != "production-signing"
        or not isinstance(deployment_policy, dict)
        or deployment_policy.get("protected_branches") is not False
        or deployment_policy.get("custom_branch_policies") is not True
    ):
        fail("production-signing does not require custom tag policies only")
    branch_policies = policies.get("branch_policies")
    if (
        policies.get("total_count") != 1
        or not isinstance(branch_policies, list)
        or len(branch_policies) != 1
        or not isinstance(branch_policies[0], dict)
        or branch_policies[0].get("name") != signer_tag
        or branch_policies[0].get("type") != "tag"
    ):
        fail("production-signing does not select the one exact policy tag")

    evidence = parse_canonical_lines(
        arguments.evidence,
        EVIDENCE_FIELDS,
        MAX_EVIDENCE_BYTES,
    )
    expected_policy_path = f"policies/{release_sha}.policy"
    if (
        evidence["format"] != "spy-signing-policy-ref-v1"
        or evidence["source_release_sha"] != release_sha
        or evidence["signer_repository"] != repository
        or evidence["signer_commit"] != signer_sha
        or evidence["policy_path"] != expected_policy_path
        or evidence["sign_workflow_path"]
        != ".github/workflows/sign-release.yml"
        or evidence["template_contract_path"]
        != "scripts/verify-public-template.py"
        or evidence["policy_sha256"]
        != sha256(arguments.policy, MAX_AUTHORITY_FILE_BYTES)
        or evidence["sign_workflow_sha256"]
        != sha256(arguments.sign_workflow, MAX_AUTHORITY_FILE_BYTES)
        or evidence["template_contract_sha256"]
        != sha256(arguments.template_contract, MAX_AUTHORITY_FILE_BYTES)
    ):
        fail("immutable policy-reference evidence differs from tagged bytes")
    manifest_text = read_ascii(arguments.manifest, MAX_EVIDENCE_BYTES)
    expected_manifest = (
        f"{sha256(arguments.evidence, MAX_EVIDENCE_BYTES)}"
        "  SIGNING_POLICY_REF\n"
    )
    if manifest_text != expected_manifest:
        fail("policy-reference manifest differs")

    policy = parse_canonical_lines(
        arguments.policy,
        POLICY_FIELDS,
        MAX_AUTHORITY_FILE_BYTES,
    )
    if (
        policy["format"] != "spy-release-signing-policy-v2"
        or policy["git_commit"] != release_sha
        or REPOSITORY.fullmatch(policy["source_repository"]) is None
        or GIT_ID.fullmatch(policy["git_tree"]) is None
        or SHA256.fullmatch(policy["release_archive_sha256"]) is None
        or SHA256.fullmatch(policy["release_manifest_sha256"]) is None
        or re.fullmatch(r"sha256:[a-f0-9]{64}", policy["builder_image_digest"])
        is None
        or policy["node_version"] != "v24.15.0"
        or re.fullmatch(
            r"[a-z0-9][a-z0-9_-]{0,22}",
            policy["signing_key_generation"],
        )
        is None
    ):
        fail("tagged release policy violates the canonical v2 contract")

    validate_asset(release, "SIGNING_POLICY_REF", arguments.evidence)
    validate_asset(
        release,
        "SIGNING_POLICY_REF_MANIFEST.sha256",
        arguments.manifest,
    )


def validate_run(arguments: argparse.Namespace) -> None:
    release_sha = arguments.release_sha
    handoff_sha256 = arguments.handoff_sha256
    signer_tag = arguments.signer_tag
    signer_sha = arguments.signer_sha
    if (
        GIT_ID.fullmatch(release_sha) is None
        or SHA256.fullmatch(handoff_sha256) is None
        or signer_tag != f"spy-sign-policy-{release_sha}"
        or GIT_ID.fullmatch(signer_sha) is None
        or arguments.baseline_run_id < 0
    ):
        fail("expected signer run identity is not canonical")
    payload = read_json(arguments.run_json)
    if isinstance(payload, dict) and "workflow_runs" in payload:
        runs = payload.get("workflow_runs")
    elif isinstance(payload, dict):
        runs = [payload]
    else:
        fail("workflow run API did not return a JSON object")
    if not isinstance(runs, list):
        fail("workflow run API has no run inventory")

    title = (
        f"spy-sign-{release_sha}-{handoff_sha256}-{signer_sha}"
    )
    relevant: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            fail("workflow run inventory contains a non-object")
        run_id = run.get("id")
        if (
            isinstance(run_id, int)
            and not isinstance(run_id, bool)
            and run_id > arguments.baseline_run_id
            and run.get("display_title") == title
        ):
            relevant.append(run)
    if not relevant and arguments.allow_none:
        return
    if len(relevant) != 1:
        fail("exact dispatch did not resolve to one new workflow run")
    run = relevant[0]
    if (
        run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != signer_tag
        or run.get("head_sha") != signer_sha
        or run.get("path") != ".github/workflows/sign-release.yml"
        or not isinstance(run.get("run_attempt"), int)
        or isinstance(run.get("run_attempt"), bool)
        or run["run_attempt"] < 1
    ):
        fail("dispatched run is not bound to the exact policy tag and commit")
    print(run["id"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    authority = subparsers.add_parser("authority")
    authority.add_argument("--release-sha", required=True)
    authority.add_argument("--repository", required=True)
    authority.add_argument("--signer-tag", required=True)
    authority.add_argument("--signer-sha", required=True)
    authority.add_argument("--release-json", type=Path, required=True)
    authority.add_argument("--tag-ref-json", type=Path, required=True)
    authority.add_argument("--environment-json", type=Path, required=True)
    authority.add_argument("--policies-json", type=Path, required=True)
    authority.add_argument("--evidence", type=Path, required=True)
    authority.add_argument("--manifest", type=Path, required=True)
    authority.add_argument("--policy", type=Path, required=True)
    authority.add_argument("--sign-workflow", type=Path, required=True)
    authority.add_argument("--template-contract", type=Path, required=True)
    authority.set_defaults(handler=validate_authority)

    run = subparsers.add_parser("run")
    run.add_argument("--release-sha", required=True)
    run.add_argument("--handoff-sha256", required=True)
    run.add_argument("--signer-tag", required=True)
    run.add_argument("--signer-sha", required=True)
    run.add_argument("--baseline-run-id", type=int, required=True)
    run.add_argument("--run-json", type=Path, required=True)
    run.add_argument("--allow-none", action="store_true")
    run.set_defaults(handler=validate_run)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    arguments.handler(arguments)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        print(
            f"Signer policy authority validation failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
