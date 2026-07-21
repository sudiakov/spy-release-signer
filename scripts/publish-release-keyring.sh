#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/local/bin
export LC_ALL=C
export PATH

private_key_argument="${1:-}"
signing_policy_id="${2:-}"
approved_builder_image="${3:-}"
approved_git_tree="${4:-}"
approved_release_archive_sha256="${5:-}"
approved_release_manifest_sha256="${6:-}"
source_release_sha="${7:-}"
release_target="${8:-}"
repository="${GITHUB_REPOSITORY:-}"
repository_token="${SPY_SIGNER_REPOSITORY_TOKEN:-}"
api_url="${GITHUB_API_URL:-https://api.github.com}"
api_version="2026-03-10"

fail() {
  echo "Release keyring publication failed: $*" >&2
  exit 1
}

[[ "$#" == "8" ]] ||
  fail "usage: publish-release-keyring.sh <private-key> <policy-id> <builder-image> <git-tree> <archive-sha256> <manifest-sha256> <source-sha> <workflow-sha>"
[[ -f "${private_key_argument}" && ! -L "${private_key_argument}" ]] ||
  fail "signing private key is missing or symbolic"
[[ "${signing_policy_id}" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]] ||
  fail "signing policy ID is invalid"
[[ "${approved_builder_image}" =~ ^sha256:[a-f0-9]{64}$ ]] ||
  fail "approved builder image is invalid"
[[ "${approved_git_tree}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "approved Git tree is invalid"
[[ "${approved_release_archive_sha256}" =~ ^[a-f0-9]{64}$ ]] ||
  fail "approved release archive SHA-256 is invalid"
[[ "${approved_release_manifest_sha256}" =~ ^[a-f0-9]{64}$ ]] ||
  fail "approved release manifest SHA-256 is invalid"
[[ "${source_release_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "source release SHA is invalid"
[[ "${signing_policy_id}" == *"-${source_release_sha}" ]] ||
  fail "signing policy ID is not tied to the full source release SHA"
[[ "${release_target}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "workflow SHA is invalid"
[[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "signer repository is invalid"
[[ -n "${repository_token}" ]] ||
  fail "signer repository token is unavailable"
[[ "${GITHUB_REF:-}" == \
  "refs/tags/spy-sign-policy-${source_release_sha}" ]] ||
  fail "release keyring may publish only from the exact immutable policy tag"
[[ "${GITHUB_SHA:-}" == "${release_target}" ]] ||
  fail "release keyring target must equal the workflow commit"

for command in \
  bash \
  chmod \
  cmp \
  curl \
  cut \
  dirname \
  grep \
  jq \
  mktemp \
  openssl \
  rm \
  sha256sum \
  stat
do
  command -v "${command}" >/dev/null 2>&1 ||
    fail "required command '${command}' is unavailable"
done

temporary_root="$(mktemp -d)"
cleanup() {
  local exit_status="$?"
  trap - EXIT
  chmod -R u+w "${temporary_root}" 2>/dev/null || true
  rm -rf -- "${temporary_root}"
  exit "${exit_status}"
}
trap cleanup EXIT
umask 077

public_key="${temporary_root}/${signing_policy_id}.pem"
builder_policy="${temporary_root}/${signing_policy_id}.builder-image"
node_policy="${temporary_root}/${signing_policy_id}.node-version"
tree_policy="${temporary_root}/${signing_policy_id}.git-tree"
archive_policy="${temporary_root}/${signing_policy_id}.release-archive-sha256"
manifest_policy="${temporary_root}/${signing_policy_id}.release-manifest-sha256"
manifest="${temporary_root}/SIGNER_KEYRING_MANIFEST.sha256"

openssl pkey \
  -in "${private_key_argument}" \
  -pubout \
  -out "${public_key}" \
  >/dev/null 2>&1
public_key_detail="$(
  openssl pkey \
    -pubin \
    -in "${public_key}" \
    -text \
    -noout \
    2>/dev/null
)"
grep -Fq "ED25519 Public-Key" <<<"${public_key_detail}" ||
  fail "release signing key is not Ed25519"
unset public_key_detail

signing_generation="${signing_policy_id%-${source_release_sha}}"
[[ "${signing_generation}" =~ ^[a-z0-9][a-z0-9_-]{0,22}$ ]] ||
  fail "signing policy ID has no canonical key generation"
generation_tag="spy-signer-generation-${signing_generation}"
curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --request GET \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer ${repository_token}" \
  --header "X-GitHub-Api-Version: ${api_version}" \
  --output "${temporary_root}/generation-release.json" \
  "${api_url}/repos/${repository}/releases/tags/${generation_tag}"
[[ "$(jq -er '.tag_name' "${temporary_root}/generation-release.json")" == \
  "${generation_tag}" ]] ||
  fail "signing generation release tag drifted"
[[ "$(jq -r '.draft' "${temporary_root}/generation-release.json")" == "false" ]] ||
  fail "signing generation release is still a draft"
[[ "$(jq -r '.prerelease' "${temporary_root}/generation-release.json")" == \
  "false" ]] ||
  fail "signing generation release must not be a prerelease"
[[ "$(jq -r '.immutable' "${temporary_root}/generation-release.json")" == \
  "true" ]] ||
  fail "signing generation release is not immutable"
[[ "$(jq -er '.assets | length' \
  "${temporary_root}/generation-release.json")" == "3" ]] ||
  fail "signing generation release asset inventory drifted"
generation_public_asset_name="${signing_generation}.pem"
[[ "$(
  jq \
    --arg name "${generation_public_asset_name}" \
    '[.assets[] | select(.name == $name and .state == "uploaded")] | length' \
    "${temporary_root}/generation-release.json"
)" == "1" ]] ||
  fail "signing generation release has no exact public key asset"
generation_public_asset_id="$(
  jq -er \
    --arg name "${generation_public_asset_name}" \
    '.assets[] | select(.name == $name) | .id' \
    "${temporary_root}/generation-release.json"
)"
generation_public_asset_size="$(
  jq -er \
    --arg name "${generation_public_asset_name}" \
    '.assets[] | select(.name == $name) | .size' \
    "${temporary_root}/generation-release.json"
)"
generation_public_asset_digest="$(
  jq -er \
    --arg name "${generation_public_asset_name}" \
    '.assets[] | select(.name == $name) | .digest' \
    "${temporary_root}/generation-release.json"
)"
[[ "${generation_public_asset_id}" =~ ^[0-9]+$ ]] ||
  fail "signing generation public key asset ID is invalid"
[[
  "${generation_public_asset_size}" =~ ^[0-9]+$ &&
  "${generation_public_asset_size}" -ge 1 &&
  "${generation_public_asset_size}" -le 65536
]] ||
  fail "signing generation public key asset size is invalid"
[[ "${generation_public_asset_digest}" =~ ^sha256:[a-f0-9]{64}$ ]] ||
  fail "signing generation public key has no provider SHA-256"
curl \
  --fail \
  --silent \
  --show-error \
  --location \
  --request GET \
  --header "Accept: application/octet-stream" \
  --header "Authorization: Bearer ${repository_token}" \
  --header "X-GitHub-Api-Version: ${api_version}" \
  --output "${temporary_root}/generation-public.pem" \
  "${api_url}/repos/${repository}/releases/assets/${generation_public_asset_id}"
[[ "$(stat -c '%s' -- "${temporary_root}/generation-public.pem")" == \
  "${generation_public_asset_size}" ]] ||
  fail "downloaded signing generation public key length differs"
downloaded_generation_digest="$(
  sha256sum "${temporary_root}/generation-public.pem" |
    cut -d ' ' -f1
)"
[[ "sha256:${downloaded_generation_digest}" == \
  "${generation_public_asset_digest}" ]] ||
  fail "downloaded signing generation public key digest differs"
cmp --silent "${public_key}" "${temporary_root}/generation-public.pem" ||
  fail "environment private key differs from immutable signing generation"

printf '%s\n' "${approved_builder_image}" >"${builder_policy}"
printf '%s\n' "v24.15.0" >"${node_policy}"
printf '%s\n' "${approved_git_tree}" >"${tree_policy}"
printf '%s\n' "${approved_release_archive_sha256}" >"${archive_policy}"
printf '%s\n' "${approved_release_manifest_sha256}" >"${manifest_policy}"
chmod 0444 \
  "${public_key}" \
  "${builder_policy}" \
  "${node_policy}" \
  "${tree_policy}" \
  "${archive_policy}" \
  "${manifest_policy}"
(
  cd "${temporary_root}"
  sha256sum \
    "${signing_policy_id}.pem" \
    "${signing_policy_id}.builder-image" \
    "${signing_policy_id}.node-version" \
    "${signing_policy_id}.git-tree" \
    "${signing_policy_id}.release-archive-sha256" \
    "${signing_policy_id}.release-manifest-sha256"
) >"${manifest}"
chmod 0444 "${manifest}"

bash \
  "$(dirname "${BASH_SOURCE[0]}")/publish-immutable-release.sh" \
  "spy-signer-key-${signing_policy_id}" \
  "${release_target}" \
  "Spy release policy ${signing_policy_id}" \
  "${temporary_root}" \
  "${signing_policy_id}.pem" \
  "${signing_policy_id}.builder-image" \
  "${signing_policy_id}.node-version" \
  "${signing_policy_id}.git-tree" \
  "${signing_policy_id}.release-archive-sha256" \
  "${signing_policy_id}.release-manifest-sha256" \
  "SIGNER_KEYRING_MANIFEST.sha256"
