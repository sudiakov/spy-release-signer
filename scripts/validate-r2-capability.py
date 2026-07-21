#!/usr/bin/env python3
"""Validate one exact EU R2 GetObject capability without disclosing it."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NoReturn
from urllib.parse import parse_qsl, unquote, urlsplit

ACCOUNT_ENDPOINT = re.compile(
    r"^[a-f0-9]{32}[.]eu[.]r2[.]cloudflarestorage[.]com$"
)
BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$")
GIT_ID = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
AWS_SIGNATURE = re.compile(r"^[a-f0-9]{64}$")
AWS_CREDENTIAL = re.compile(
    r"^[A-Za-z0-9]+/[0-9]{8}/auto/s3/aws4_request$"
)
MAX_EXPIRY_SECONDS = 900
MAX_CLOCK_SKEW_SECONDS = 300
MAX_URL_BYTES = 16 * 1024

REQUIRED_QUERY_FIELDS = {
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders",
}
OPTIONAL_QUERY_FIELDS = {
    "X-Amz-Content-Sha256",
    "X-Amz-Security-Token",
    "x-amz-checksum-mode",
    "x-id",
}


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-endpoint-host", required=True)
    parser.add_argument("--expected-bucket", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--handoff-sha256", required=True)
    parser.add_argument("--curl-config", required=True, type=Path)
    return parser.parse_args()


def canonical_query(url: str) -> dict[str, str]:
    parsed = urlsplit(url)
    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
        )
    except ValueError as error:
        raise ValueError("R2 capability has an invalid query string") from error

    query: dict[str, str] = {}
    for name, value in pairs:
        if name in query:
            fail("R2 capability contains a duplicate query parameter")
        if (
            not value
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in value
            )
        ):
            fail("R2 capability contains an invalid query value")
        query[name] = value
    if not REQUIRED_QUERY_FIELDS.issubset(query):
        fail("R2 capability is missing a required SigV4 parameter")
    if set(query).difference(REQUIRED_QUERY_FIELDS | OPTIONAL_QUERY_FIELDS):
        fail("R2 capability contains an unsupported query parameter")
    return query


def validate_expiry(query: dict[str, str]) -> None:
    try:
        signed_at = datetime.strptime(
            query["X-Amz-Date"],
            "%Y%m%dT%H%M%SZ",
        ).replace(tzinfo=timezone.utc)
        expiry_seconds = int(query["X-Amz-Expires"], 10)
    except (ValueError, OverflowError) as error:
        raise ValueError("R2 capability has invalid expiry metadata") from error

    if (
        str(expiry_seconds) != query["X-Amz-Expires"]
        or not 1 <= expiry_seconds <= MAX_EXPIRY_SECONDS
    ):
        fail("R2 capability lifetime exceeds the fixed 15-minute policy")
    now = datetime.now(timezone.utc)
    if signed_at > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        fail("R2 capability signing time is too far in the future")
    if now >= signed_at + timedelta(seconds=expiry_seconds):
        fail("R2 capability is already expired")


def validate_url(
    url: str,
    expected_endpoint_host: str,
    expected_bucket: str,
    release_sha: str,
    handoff_sha256: str,
) -> None:
    if (
        not url
        or len(url.encode("utf-8")) > MAX_URL_BYTES
        or any(ord(character) < 33 or ord(character) > 126 for character in url)
        or '"' in url
        or "\\" in url
    ):
        fail("R2 capability is not one canonical printable URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        fail("R2 capability must be one direct HTTPS URL")
    host = (parsed.hostname or "").lower()
    endpoint = expected_endpoint_host.lower()
    if ACCOUNT_ENDPOINT.fullmatch(endpoint) is None:
        fail("configured R2 EU endpoint host is invalid")
    if BUCKET_NAME.fullmatch(expected_bucket) is None:
        fail("configured R2 handoff bucket name is invalid")

    expected_key = (
        f"signer-handoff/{release_sha}/{handoff_sha256}.tar"
    )
    path = unquote(parsed.path, errors="strict")
    if host == endpoint:
        expected_path = f"/{expected_bucket}/{expected_key}"
    elif host == f"{expected_bucket}.{endpoint}":
        expected_path = f"/{expected_key}"
    else:
        fail("R2 capability host is outside the configured EU bucket")
    if path != expected_path:
        fail("R2 capability does not identify the exact handoff object")

    query = canonical_query(url)
    if query["X-Amz-Algorithm"] != "AWS4-HMAC-SHA256":
        fail("R2 capability uses an unsupported signing algorithm")
    if AWS_CREDENTIAL.fullmatch(query["X-Amz-Credential"]) is None:
        fail("R2 capability has invalid SigV4 credential scope")
    if query["X-Amz-Credential"].split("/")[1] != query["X-Amz-Date"][:8]:
        fail("R2 capability credential date differs from its signing date")
    if query["X-Amz-SignedHeaders"] != "host":
        fail("R2 capability must sign only the canonical host header")
    if AWS_SIGNATURE.fullmatch(query["X-Amz-Signature"]) is None:
        fail("R2 capability signature is invalid")
    if query.get("x-id", "GetObject") != "GetObject":
        fail("R2 capability is not scoped to GetObject")
    if query.get("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") != (
        "UNSIGNED-PAYLOAD"
    ):
        fail("R2 capability has an unsupported payload policy")
    if query.get("x-amz-checksum-mode", "ENABLED") != "ENABLED":
        fail("R2 capability has an unsupported checksum mode")
    validate_expiry(query)


def write_curl_config(path: Path, url: str) -> None:
    if path.exists() or path.is_symlink():
        fail("curl capability config target must not already exist")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
        handle.write(f'url = "{url}"\n')
        handle.flush()
        os.fsync(handle.fileno())
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != (
        0o600
    ):
        fail("curl capability config was not created safely")


def main() -> int:
    arguments = parse_arguments()
    if GIT_ID.fullmatch(arguments.release_sha) is None:
        fail("release SHA is invalid")
    if SHA256.fullmatch(arguments.handoff_sha256) is None:
        fail("handoff SHA-256 is invalid")

    capability = os.environ.get("SPY_R2_HANDOFF_PRESIGNED_URL", "")
    validate_url(
        capability,
        arguments.expected_endpoint_host,
        arguments.expected_bucket,
        arguments.release_sha,
        arguments.handoff_sha256,
    )
    write_curl_config(arguments.curl_config, capability)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValueError) as error:
        print(
            f"R2 handoff capability validation failed: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
