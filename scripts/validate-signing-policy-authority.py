#!/usr/bin/env python3
"""Validate the immutable signer-policy authority and exact dispatched run."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any, NoReturn

GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
POLICY_TAG = re.compile(r"^spy-sign-policy-([a-f0-9]{40})$")
SIGN_RUN_TITLE = re.compile(
    r"^spy-sign-([a-f0-9]{40})-([a-f0-9]{64})-([a-f0-9]{40})$"
)
SIGNER_REPOSITORY = "sudiakov/spy-release-signer"
SOURCE_REPOSITORY = "sudiakov/spy"
SIGN_WORKFLOW_NAME = "Sign exact Spy release"
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
MAX_GITHUB_INVENTORY_ITEMS = 100


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


def complete_inventory(
    payload: Any,
    field: str,
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get(field), list):
        fail(f"{label} API has no inventory")
    items = payload[field]
    total_count = payload.get("total_count")
    if (
        not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count < 0
        or total_count > MAX_GITHUB_INVENTORY_ITEMS
        or total_count != len(items)
        or any(not isinstance(item, dict) for item in items)
    ):
        fail(f"{label} API inventory is incomplete or malformed")
    return items


def validate_run_binding(
    run: dict[str, Any],
    repository: str,
    signer_tag: str,
    signer_sha: str,
    *,
    require_first_attempt: bool,
    allow_pending_path: bool = False,
) -> int:
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    repository_metadata = run.get("repository")
    workflow_path = ".github/workflows/sign-release.yml"
    allowed_workflow_paths = {
        workflow_path,
        f"{workflow_path}@{signer_tag}",
        f"{workflow_path}@refs/tags/{signer_tag}",
    }
    path = run.get("path")
    path_is_exact = isinstance(path, str) and path in allowed_workflow_paths
    path_is_pending = allow_pending_path and (path is None or path == "")
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id <= 0
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != signer_tag
        or run.get("head_sha") != signer_sha
        or not (path_is_exact or path_is_pending)
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or (require_first_attempt and run_attempt != 1)
        or run.get("url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
        or run.get("html_url")
        != f"https://github.com/{repository}/actions/runs/{run_id}"
        or run.get("jobs_url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs"
        or not isinstance(repository_metadata, dict)
        or repository_metadata.get("full_name") != repository
    ):
        fail("dispatched run is not bound to the exact policy tag and commit")
    return run_id


def expected_run_title(
    release_sha: str,
    handoff_sha256: str,
    signer_sha: str,
) -> str:
    return f"spy-sign-{release_sha}-{handoff_sha256}-{signer_sha}"


def validate_inventory_run_binding(
    run: dict[str, Any],
    repository: str,
    signer_sha: str,
) -> int:
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    repository_metadata = run.get("repository")
    inventory_tag = run.get("head_branch")
    workflow_path = ".github/workflows/sign-release.yml"
    allowed_workflow_paths = {
        workflow_path,
        f"{workflow_path}@{inventory_tag}",
        f"{workflow_path}@refs/tags/{inventory_tag}",
    }
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id <= 0
        or run.get("event") != "workflow_dispatch"
        or not isinstance(inventory_tag, str)
        or POLICY_TAG.fullmatch(inventory_tag) is None
        or run.get("head_sha") != signer_sha
        or run.get("path") not in allowed_workflow_paths
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or run.get("url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
        or run.get("html_url")
        != f"https://github.com/{repository}/actions/runs/{run_id}"
        or run.get("jobs_url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/jobs"
        or not isinstance(repository_metadata, dict)
        or repository_metadata.get("full_name") != repository
    ):
        fail("workflow run inventory is outside the canonical signer authority")
    return run_id


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
        or repository != SIGNER_REPOSITORY
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
        or policy["source_repository"] != SOURCE_REPOSITORY
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


def validate_baseline(arguments: argparse.Namespace) -> None:
    repository = arguments.repository
    signer_tag = arguments.signer_tag
    signer_sha = arguments.signer_sha
    if (
        repository != SIGNER_REPOSITORY
        or POLICY_TAG.fullmatch(signer_tag) is None
        or GIT_ID.fullmatch(signer_sha) is None
    ):
        fail("expected signer baseline identity is not canonical")
    runs = complete_inventory(
        read_json(arguments.runs_json),
        "workflow_runs",
        "workflow run",
    )
    run_ids = [
        validate_inventory_run_binding(
            run,
            repository,
            signer_sha,
        )
        for run in runs
    ]
    if len(set(run_ids)) != len(run_ids):
        fail("workflow run baseline contains duplicate run IDs")
    print(max(run_ids, default=0))


def validate_run(arguments: argparse.Namespace) -> None:
    release_sha = arguments.release_sha
    handoff_sha256 = arguments.handoff_sha256
    repository = arguments.repository
    signer_tag = arguments.signer_tag
    signer_sha = arguments.signer_sha
    if (
        GIT_ID.fullmatch(release_sha) is None
        or SHA256.fullmatch(handoff_sha256) is None
        or repository != SIGNER_REPOSITORY
        or signer_tag != f"spy-sign-policy-{release_sha}"
        or GIT_ID.fullmatch(signer_sha) is None
        or arguments.baseline_run_id < 0
    ):
        fail("expected signer run identity is not canonical")
    payload = read_json(arguments.run_json)
    if isinstance(payload, dict) and "workflow_runs" in payload:
        runs = complete_inventory(payload, "workflow_runs", "workflow run")
        for run in runs:
            validate_inventory_run_binding(
                run,
                repository,
                signer_sha,
            )
    elif isinstance(payload, dict):
        runs = [payload]
    else:
        fail("workflow run API did not return a JSON object")

    title = expected_run_title(release_sha, handoff_sha256, signer_sha)
    relevant: list[dict[str, Any]] = []
    for run in runs:
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
    run_id = validate_run_binding(
        run,
        repository,
        signer_tag,
        signer_sha,
        require_first_attempt=True,
    )
    print(run_id)


def validate_direct_run(arguments: argparse.Namespace) -> None:
    """Classify one run ID returned by the canonical dispatch response.

    GitHub's dispatch endpoint returns the authoritative run ID before every
    eventually-consistent run projection is necessarily populated. Core
    authority mismatches remain fatal; only the title and an empty path may be
    reported as pending until the bounded dispatcher observation converges.
    """

    release_sha = arguments.release_sha
    handoff_sha256 = arguments.handoff_sha256
    repository = arguments.repository
    signer_tag = arguments.signer_tag
    signer_sha = arguments.signer_sha
    expected_run_id = arguments.expected_run_id
    if (
        GIT_ID.fullmatch(release_sha) is None
        or SHA256.fullmatch(handoff_sha256) is None
        or repository != SIGNER_REPOSITORY
        or signer_tag != f"spy-sign-policy-{release_sha}"
        or GIT_ID.fullmatch(signer_sha) is None
        or arguments.baseline_run_id < 0
        or expected_run_id <= arguments.baseline_run_id
    ):
        fail("expected direct signer run identity is not canonical")

    payload = read_json(arguments.run_json)
    if not isinstance(payload, dict) or "workflow_runs" in payload:
        fail("direct workflow run API did not return one JSON object")
    observed_run_id = validate_run_binding(
        payload,
        repository,
        signer_tag,
        signer_sha,
        require_first_attempt=True,
        allow_pending_path=True,
    )
    if observed_run_id != expected_run_id:
        fail("direct workflow run ID differs from the dispatch response")

    workflow_path = ".github/workflows/sign-release.yml"
    allowed_workflow_paths = {
        workflow_path,
        f"{workflow_path}@{signer_tag}",
        f"{workflow_path}@refs/tags/{signer_tag}",
    }
    expected_title = expected_run_title(
        release_sha,
        handoff_sha256,
        signer_sha,
    )
    observed_name = payload.get("name")
    if observed_name is not None and not isinstance(observed_name, str):
        fail("direct workflow run name is malformed")
    if observed_name not in {None, "", SIGN_WORKFLOW_NAME, expected_title}:
        if isinstance(observed_name, str) and SIGN_RUN_TITLE.fullmatch(
            observed_name
        ):
            fail("direct workflow run name conflicts with dispatch inputs")
        fail("direct workflow run has an unknown pending name")
    observed_title = payload.get("display_title")
    if observed_title is not None and not isinstance(observed_title, str):
        fail("direct workflow run title is malformed")
    if observed_title not in {None, "", SIGN_WORKFLOW_NAME, expected_title}:
        if isinstance(observed_title, str) and SIGN_RUN_TITLE.fullmatch(
            observed_title
        ):
            fail("direct workflow run title conflicts with dispatch inputs")
        fail("direct workflow run has an unknown pending title")
    exact_projection = (
        observed_name in {SIGN_WORKFLOW_NAME, expected_title}
        and observed_title == expected_title
        and isinstance(payload.get("path"), str)
        and payload.get("path") in allowed_workflow_paths
    )
    print(
        json.dumps(
            {
                "classification": (
                    "exact" if exact_projection else "pending_projection"
                ),
                "run_id": observed_run_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def valid_started_at(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=datetime.UTC)
    except ValueError:
        return False
    return parsed.year >= 2020


def validate_job(arguments: argparse.Namespace) -> None:
    repository = arguments.repository
    signer_sha = arguments.signer_sha
    run_id = arguments.run_id
    if (
        repository != SIGNER_REPOSITORY
        or GIT_ID.fullmatch(signer_sha) is None
        or run_id <= 0
    ):
        fail("expected signer job identity is not canonical")
    jobs = complete_inventory(
        read_json(arguments.jobs_json),
        "jobs",
        "workflow jobs",
    )
    relevant = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("name") == "sign"
    ]
    if len(relevant) > 1:
        fail("exact signer run contains duplicate sign jobs")
    if not relevant:
        print(
            json.dumps(
                {
                    "classification": "absent",
                    "job_id": 0,
                    "status": "absent",
                    "conclusion": "",
                    "start_proven": False,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return

    job = relevant[0]
    job_id = job.get("id")
    status = job.get("status")
    conclusion = job.get("conclusion")
    if (
        not isinstance(job_id, int)
        or isinstance(job_id, bool)
        or job_id <= 0
        or job.get("run_id") != run_id
        or job.get("head_sha") != signer_sha
        or job.get("run_url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
        or job.get("url")
        != f"https://api.github.com/repos/{repository}/actions/jobs/{job_id}"
        or status
        not in {
            "requested",
            "waiting",
            "pending",
            "queued",
            "in_progress",
            "completed",
        }
    ):
        fail("signer job is not bound to the exact run and repository")

    runner_id = job.get("runner_id")
    runner_name = job.get("runner_name")
    start_proven = (
        valid_started_at(job.get("started_at"))
        and isinstance(runner_id, int)
        and not isinstance(runner_id, bool)
        and runner_id > 0
        and isinstance(runner_name, str)
        and bool(runner_name)
        and all(32 <= ord(character) <= 126 for character in runner_name)
    )
    if status == "completed":
        if (
            not isinstance(conclusion, str)
            or not conclusion
            or not re.fullmatch(r"[a-z_]+", conclusion)
        ):
            fail("completed signer job has no canonical conclusion")
        classification = (
            "started"
            if start_proven and conclusion not in {"cancelled", "skipped"}
            else "terminal"
        )
    elif status == "in_progress":
        if conclusion is not None or not start_proven:
            fail("in-progress signer job has no canonical runner-start evidence")
        classification = "started"
        conclusion = ""
    else:
        if conclusion is not None or start_proven:
            fail("pre-start signer job contains contradictory execution evidence")
        classification = "prestart"
        conclusion = ""

    print(
        json.dumps(
            {
                "classification": classification,
                "job_id": job_id,
                "status": status,
                "conclusion": conclusion,
                "start_proven": start_proven,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


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

    baseline = subparsers.add_parser("baseline")
    baseline.add_argument("--repository", required=True)
    baseline.add_argument("--signer-tag", required=True)
    baseline.add_argument("--signer-sha", required=True)
    baseline.add_argument("--runs-json", type=Path, required=True)
    baseline.set_defaults(handler=validate_baseline)

    run = subparsers.add_parser("run")
    run.add_argument("--release-sha", required=True)
    run.add_argument("--handoff-sha256", required=True)
    run.add_argument("--repository", required=True)
    run.add_argument("--signer-tag", required=True)
    run.add_argument("--signer-sha", required=True)
    run.add_argument("--baseline-run-id", type=int, required=True)
    run.add_argument("--run-json", type=Path, required=True)
    run.add_argument("--allow-none", action="store_true")
    run.set_defaults(handler=validate_run)

    direct_run = subparsers.add_parser("direct-run")
    direct_run.add_argument("--release-sha", required=True)
    direct_run.add_argument("--handoff-sha256", required=True)
    direct_run.add_argument("--repository", required=True)
    direct_run.add_argument("--signer-tag", required=True)
    direct_run.add_argument("--signer-sha", required=True)
    direct_run.add_argument("--baseline-run-id", type=int, required=True)
    direct_run.add_argument("--expected-run-id", type=int, required=True)
    direct_run.add_argument("--run-json", type=Path, required=True)
    direct_run.set_defaults(handler=validate_direct_run)

    job = subparsers.add_parser("job")
    job.add_argument("--repository", required=True)
    job.add_argument("--signer-sha", required=True)
    job.add_argument("--run-id", type=int, required=True)
    job.add_argument("--jobs-json", type=Path, required=True)
    job.set_defaults(handler=validate_job)
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
