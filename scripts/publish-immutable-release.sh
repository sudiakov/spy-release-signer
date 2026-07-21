#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/local/bin
export LC_ALL=C
export PATH

release_tag="${1:-}"
release_target="${2:-}"
release_title="${3:-}"
asset_root_argument="${4:-}"
shift "$(( $# < 4 ? $# : 4 ))"
asset_names=("$@")

repository="${GITHUB_REPOSITORY:-}"
repository_token="${SPY_SIGNER_REPOSITORY_TOKEN:-}"
api_url="${GITHUB_API_URL:-https://api.github.com}"
upload_url="https://uploads.github.com"
api_version="2026-03-10"

fail() {
  echo "Immutable signer release publication failed: $*" >&2
  exit 1
}

[[ -n "${release_tag}" && -n "${release_target}" && -n "${release_title}" ]] ||
  fail "usage: publish-immutable-release.sh <tag> <target-sha> <title> <asset-root> <asset-name>..."
[[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "GITHUB_REPOSITORY is invalid"
[[ "${release_target}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "release target must be one full lowercase Git commit ID"
[[ "${release_tag}" =~ ^spy-(sign-policy-[a-f0-9]{40}|signed-[a-f0-9]{40}|signer-(key-[a-z0-9][a-z0-9_-]{0,63}|generation-[a-z0-9][a-z0-9_-]{0,22}))$ ]] ||
  fail "release tag is outside the signer namespace"
[[ -n "${repository_token}" ]] ||
  fail "signer repository token is unavailable"
case "${GITHUB_REF:-}" in
  refs/heads/main)
    [[ "${release_tag}" == spy-sign-policy-* ]] ||
      fail "protected main may publish only an immutable policy reference"
    ;;
  refs/tags/spy-sign-policy-[a-f0-9][a-f0-9]*)
    [[ "${GITHUB_REF#refs/tags/spy-sign-policy-}" =~ ^[a-f0-9]{40}$ ]] ||
      fail "signer workflow policy tag is not canonical"
    [[ "${release_tag}" != spy-sign-policy-* ]] ||
      fail "a policy workflow cannot publish another policy reference"
    ;;
  *) fail "signer assets may publish only from protected main or an exact policy tag" ;;
esac
[[ "${GITHUB_SHA:-}" == "${release_target}" ]] ||
  fail "signer release target must equal the executing workflow commit"
[[ "${#asset_names[@]}" -ge 1 && "${#asset_names[@]}" -le 8 ]] ||
  fail "signer release must contain between one and eight fixed assets"
[[ -d "${asset_root_argument}" && ! -L "${asset_root_argument}" ]] ||
  fail "asset root must be a non-symbolic-link directory"
asset_root="$(cd "${asset_root_argument}" && pwd -P)"

for command in curl jq mktemp rm sha256sum; do
  command -v "${command}" >/dev/null 2>&1 ||
    fail "required command '${command}' is unavailable"
done

declare -A local_digests=()
declare -A seen_assets=()
for asset_name in "${asset_names[@]}"; do
  [[ "${asset_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
    fail "signer asset name is unsafe"
  [[ -z "${seen_assets["${asset_name}"]+present}" ]] ||
    fail "signer asset list contains a duplicate"
  seen_assets["${asset_name}"]=true
  asset_path="${asset_root}/${asset_name}"
  [[ -f "${asset_path}" && ! -L "${asset_path}" && -s "${asset_path}" ]] ||
    fail "signer asset '${asset_name}' is missing, symbolic, or empty"
  local_digests["${asset_name}"]="$(
    sha256sum "${asset_path}" |
      cut -d ' ' -f1
  )"
done

temporary_body="$(mktemp)"
cleanup() {
  local exit_status="$?"
  trap - EXIT
  rm -f -- "${temporary_body}"
  unset repository_token
  exit "${exit_status}"
}
trap cleanup EXIT

api_request() {
  local method="$1"
  local url="$2"
  local output="$3"
  local expected_status="$4"
  local body="${5:-}"
  local content_type="${6:-application/vnd.github+json}"
  local status
  local arguments=(
    --silent
    --show-error
    --request "${method}"
    --header "Accept: application/vnd.github+json"
    --header "Authorization: Bearer ${repository_token}"
    --header "X-GitHub-Api-Version: ${api_version}"
    --output "${output}"
    --write-out "%{http_code}"
  )

  if [[ -n "${body}" ]]; then
    arguments+=(
      --header "Content-Type: ${content_type}"
      --data-binary "@${body}"
    )
  fi
  status="$(curl "${arguments[@]}" "${url}")"
  [[ "${status}" == "${expected_status}" ]] ||
    fail "GitHub API returned HTTP ${status}; expected ${expected_status}"
}

ensure_exact_tag() {
  local status
  local create_ref_body

  status="$(
    curl \
      --silent \
      --show-error \
      --request GET \
      --header "Accept: application/vnd.github+json" \
      --header "Authorization: Bearer ${repository_token}" \
      --header "X-GitHub-Api-Version: ${api_version}" \
      --output "${temporary_body}" \
      --write-out '%{http_code}' \
      "${api_url}/repos/${repository}/git/ref/tags/${release_tag}"
  )"
  case "${status}" in
    200) ;;
    404)
      create_ref_body="$(mktemp)"
      jq -n \
        --arg ref "refs/tags/${release_tag}" \
        --arg sha "${release_target}" \
        '{ref: $ref, sha: $sha}' \
        >"${create_ref_body}"
      api_request \
        POST \
        "${api_url}/repos/${repository}/git/refs" \
        "${temporary_body}" \
        201 \
        "${create_ref_body}"
      rm -f -- "${create_ref_body}"
      ;;
    *) fail "GitHub API returned HTTP ${status} while reading the signer tag" ;;
  esac

  [[ "$(jq -er '.ref' "${temporary_body}")" == "refs/tags/${release_tag}" ]] ||
    fail "signer release tag reference drifted"
  [[ "$(jq -er '.object.type' "${temporary_body}")" == "commit" ]] ||
    fail "signer release tag must be a lightweight commit reference"
  [[ "$(jq -er '.object.sha' "${temporary_body}")" == "${release_target}" ]] ||
    fail "signer release tag points to another workflow revision"
}

get_release() {
  local status

  status="$(
    curl \
      --silent \
      --show-error \
      --request GET \
      --header "Accept: application/vnd.github+json" \
      --header "Authorization: Bearer ${repository_token}" \
      --header "X-GitHub-Api-Version: ${api_version}" \
      --output "${temporary_body}" \
      --write-out '%{http_code}' \
      "${api_url}/repos/${repository}/releases/tags/${release_tag}"
  )"
  case "${status}" in
    200) return 0 ;;
    404) return 1 ;;
    *) fail "GitHub API returned HTTP ${status} while reading the signer release" ;;
  esac
}

ensure_exact_tag

validate_release_identity() {
  local expected_draft="$1"

  [[ "$(jq -er '.tag_name' "${temporary_body}")" == "${release_tag}" ]] ||
    fail "signer release tag drifted"
  [[ "$(jq -er '.target_commitish' "${temporary_body}")" == "${release_target}" ]] ||
    fail "signer release target drifted"
  [[ "$(jq -er '.name' "${temporary_body}")" == "${release_title}" ]] ||
    fail "signer release title drifted"
  [[ "$(jq -r '.draft' "${temporary_body}")" == "${expected_draft}" ]] ||
    fail "signer release draft state drifted"
  [[ "$(jq -r '.prerelease' "${temporary_body}")" == "false" ]] ||
    fail "signer output must not be a prerelease"
}

if ! get_release; then
  create_body="$(mktemp)"
  jq -n \
    --arg tag_name "${release_tag}" \
    --arg target_commitish "${release_target}" \
    --arg name "${release_title}" \
    '{
      tag_name: $tag_name,
      target_commitish: $target_commitish,
      name: $name,
      body: "Canonical Spy signer output. Assets are security evidence.",
      draft: true,
      prerelease: false,
      make_latest: "false"
    }' \
    >"${create_body}"
  api_request \
    POST \
    "${api_url}/repos/${repository}/releases" \
    "${temporary_body}" \
    201 \
    "${create_body}"
  rm -f -- "${create_body}"
fi

release_is_draft="$(jq -r '.draft' "${temporary_body}")"
if [[ "${release_is_draft}" == "true" ]]; then
  validate_release_identity true
else
  validate_release_identity false
fi
release_id="$(jq -er '.id' "${temporary_body}")" ||
  fail "signer release has no ID"
[[ "${release_id}" =~ ^[0-9]+$ ]] ||
  fail "signer release ID is invalid"

compare_published_assets() {
  local asset_name
  local asset_count
  local provider_digest

  asset_count="$(jq -er '.assets | length' "${temporary_body}")" ||
    fail "signer release has no asset inventory"
  [[ "${asset_count}" == "${#asset_names[@]}" ]] ||
    fail "published signer release has an unexpected asset count"
  for asset_name in "${asset_names[@]}"; do
    [[ "$(
      jq \
        --arg name "${asset_name}" \
        '[.assets[] | select(.name == $name and .state == "uploaded")] | length' \
        "${temporary_body}"
    )" == "1" ]] ||
      fail "published signer release is missing exact asset '${asset_name}'"
    provider_digest="$(
      jq -er \
        --arg name "${asset_name}" \
        '.assets[] | select(.name == $name) | .digest' \
        "${temporary_body}"
    )" ||
      fail "published signer asset has no provider digest"
    [[ "${provider_digest}" == "sha256:${local_digests["${asset_name}"]}" ]] ||
      fail "published signer asset differs from the idempotent local output"
  done
}

if [[ "${release_is_draft}" == "false" ]]; then
  ensure_exact_tag
  get_release ||
    fail "published signer release disappeared"
  validate_release_identity false
  [[ "$(jq -r '.immutable' "${temporary_body}")" == "true" ]] ||
    fail "published signer release is not immutable"
  compare_published_assets
  echo "Immutable signer release ${release_tag} already matches."
  exit 0
fi

for asset_name in "${asset_names[@]}"; do
  existing_count="$(
    jq \
      --arg name "${asset_name}" \
      '[.assets[] | select(.name == $name and .state == "uploaded")] | length' \
      "${temporary_body}"
  )"
  case "${existing_count}" in
    0)
      encoded_name="$(
        jq -rn --arg value "${asset_name}" '$value | @uri'
      )"
      api_request \
        POST \
        "${upload_url}/repos/${repository}/releases/${release_id}/assets?name=${encoded_name}" \
        "${temporary_body}" \
        201 \
        "${asset_root}/${asset_name}" \
        "application/octet-stream"
      ;;
    1)
      provider_digest="$(
        jq -er \
          --arg name "${asset_name}" \
          '.assets[] | select(.name == $name) | .digest' \
          "${temporary_body}"
      )" ||
        fail "existing draft asset has no provider digest"
      [[ "${provider_digest}" == "sha256:${local_digests["${asset_name}"]}" ]] ||
        fail "existing draft asset differs; refusing to overwrite"
      ;;
    *) fail "draft signer release contains duplicate asset names" ;;
  esac
  get_release ||
    fail "draft signer release disappeared during publication"
  validate_release_identity true
done

compare_published_assets
publish_body="$(mktemp)"
printf '%s\n' '{"draft":false}' >"${publish_body}"
api_request \
  PATCH \
  "${api_url}/repos/${repository}/releases/${release_id}" \
  "${temporary_body}" \
  200 \
  "${publish_body}"
rm -f -- "${publish_body}"
validate_release_identity false
ensure_exact_tag
get_release ||
  fail "published signer release disappeared"
validate_release_identity false
[[ "$(jq -r '.immutable' "${temporary_body}")" == "true" ]] ||
  fail "published signer release did not become immutable"
compare_published_assets

echo "Immutable signer release ${release_tag} published."
