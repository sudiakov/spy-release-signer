#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/local/bin
export LC_ALL=C
export PATH

release_sha="${1:-}"
handoff_sha256="${2:-}"
approved_git_tree="${3:-}"
output_argument="${4:-}"
source_repository="${SPY_SOURCE_REPOSITORY:-}"
source_deploy_key_b64="${SPY_SOURCE_DEPLOY_PRIVATE_KEY_B64:-}"
r2_handoff_capability="${SPY_R2_HANDOFF_PRESIGNED_URL:-}"
handoff_bucket="${SPY_R2_HANDOFF_BUCKET_NAME:-}"
handoff_endpoint_host="${SPY_R2_EU_ENDPOINT_HOST:-}"
expected_signer_sha="${SPY_EXPECTED_SIGNER_SHA:-}"
unset SPY_SOURCE_DEPLOY_PRIVATE_KEY_B64 SPY_R2_HANDOFF_PRESIGNED_URL

fail() {
  echo "Spy source handoff fetch failed: $*" >&2
  exit 1
}

[[ "$#" == "4" ]] ||
  fail "usage: fetch-source-handoff.sh <release-sha> <handoff-sha256> <approved-git-tree> <empty-output-directory>"
[[ "${release_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "release SHA must be one full lowercase GitHub commit ID"
[[ "${handoff_sha256}" =~ ^[a-f0-9]{64}$ ]] ||
  fail "handoff SHA-256 must be one lowercase digest"
[[ "${approved_git_tree}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "approved Git tree must be one full lowercase GitHub tree ID"
[[ "${source_repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "SPY_SOURCE_REPOSITORY must identify one fixed GitHub repository"
[[ "${source_deploy_key_b64}" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
  fail "the read-only source deploy key is unavailable"
[[ "${handoff_bucket}" =~ ^[a-z0-9][a-z0-9.-]{1,62}$ ]] ||
  fail "SPY_R2_HANDOFF_BUCKET_NAME is invalid"
[[ "${handoff_endpoint_host}" =~ ^[a-f0-9]{32}[.]eu[.]r2[.]cloudflarestorage[.]com$ ]] ||
  fail "SPY_R2_EU_ENDPOINT_HOST is invalid"
[[ "${expected_signer_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "SPY_EXPECTED_SIGNER_SHA is invalid"
[[ "${GITHUB_SHA:-}" == "${expected_signer_sha}" ]] ||
  fail "signing workflow SHA differs from the selected signer commit"
[[ "${GITHUB_REF:-}" == "refs/tags/spy-sign-policy-${release_sha}" ]] ||
  fail "signing may run only from the exact immutable policy tag"

for command in \
  base64 \
  cat \
  chmod \
  curl \
  cut \
  dirname \
  env \
  find \
  git \
  grep \
  install \
  mktemp \
  rm \
  sha256sum \
  ssh \
  ssh-keygen \
  stat \
  wc
do
  command -v "${command}" >/dev/null 2>&1 ||
    fail "required command '${command}' is unavailable"
done
[[ -x /usr/bin/python3 ]] ||
  fail "isolated system Python is unavailable"

[[ -d "${output_argument}" && ! -L "${output_argument}" ]] ||
  fail "output directory must be a non-symbolic-link directory"
output_dir="$(cd "${output_argument}" && pwd -P)"
if find "${output_dir}" -mindepth 1 -print -quit | grep -q .; then
  fail "output directory must be empty"
fi

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd "${script_root}/.." && pwd -P)"
known_hosts="${repository_root}/config/github.com.known_hosts"
[[ -f "${known_hosts}" && ! -L "${known_hosts}" ]] ||
  fail "pinned GitHub SSH host key file is unavailable"

temporary_root="$(mktemp -d /tmp/spy-signer-fetch.XXXXXX)"
deploy_key="${temporary_root}/source-deploy-key"
ssh_config="${temporary_root}/ssh-config"
curl_config="${temporary_root}/curl-capability.conf"
handoff_bundle="${temporary_root}/spy-signer-handoff-${release_sha}.tar"
git_repository="${temporary_root}/source.git"

cleanup() {
  local exit_status="$?"
  trap - EXIT
  unset source_deploy_key_b64 r2_handoff_capability
  chmod -R u+w "${temporary_root}" 2>/dev/null || true
  rm -rf -- "${temporary_root}"
  exit "${exit_status}"
}
trap cleanup EXIT
umask 077

SPY_R2_HANDOFF_PRESIGNED_URL="${r2_handoff_capability}" /usr/bin/python3 -I \
  "${script_root}/validate-r2-capability.py" \
  workflow \
  --expected-endpoint-host "${handoff_endpoint_host}" \
  --expected-bucket "${handoff_bucket}" \
  --release-sha "${release_sha}" \
  --handoff-sha256 "${handoff_sha256}" \
  --curl-config "${curl_config}"
unset r2_handoff_capability

download_status="$(
  curl \
  --disable \
  --config "${curl_config}" \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --silent \
  --show-error \
  --connect-timeout 10 \
  --max-time 600 \
  --max-filesize 2148534272 \
  --output "${handoff_bundle}" \
  --write-out '%{http_code} %{num_redirects}'
)" ||
  fail "the exact private R2 handoff could not be downloaded"
[[ "${download_status}" == "200 0" ]] ||
  fail "the exact private R2 handoff returned a redirect or non-200 status"
rm -f -- "${curl_config}"
[[ -f "${handoff_bundle}" && ! -L "${handoff_bundle}" ]] ||
  fail "downloaded R2 handoff is not one regular file"
[[ "$(stat -c '%s' -- "${handoff_bundle}")" -le 2148534272 ]] ||
  fail "downloaded R2 handoff exceeds its fixed size limit"
downloaded_handoff_sha256="$(
  sha256sum "${handoff_bundle}" |
    cut -d ' ' -f1
)"
[[ "${downloaded_handoff_sha256}" == "${handoff_sha256}" ]] ||
  fail "downloaded R2 handoff differs from the dispatched SHA-256"

printf '%s' "${source_deploy_key_b64}" |
  base64 --decode >"${deploy_key}"
chmod 0600 "${deploy_key}"
unset source_deploy_key_b64 SPY_SOURCE_DEPLOY_PRIVATE_KEY_B64
ssh-keygen -y -f "${deploy_key}" 2>/dev/null |
  grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' ||
  fail "source deploy key is not one canonical Ed25519 key"

cat >"${ssh_config}" <<EOF
Host github.com
  HostName github.com
  User git
  IdentityFile ${deploy_key}
  IdentitiesOnly yes
  BatchMode yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  StrictHostKeyChecking yes
  UserKnownHostsFile ${known_hosts}
  GlobalKnownHostsFile /dev/null
  LogLevel ERROR
EOF
chmod 0600 "${ssh_config}"

source_url="ssh://git@github.com/${source_repository}.git"
git_environment=(
  env
  -i
  HOME="${temporary_root}"
  LANG=C
  LC_ALL=C
  PATH=/usr/bin:/bin
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_NOSYSTEM=1
  GIT_SSH_COMMAND="/usr/bin/ssh -F ${ssh_config}"
  GIT_SSH_VARIANT=ssh
)

read_main_ref() {
  local main_line
  main_line="$(
    "${git_environment[@]}" \
      git ls-remote --exit-code --refs "${source_url}" refs/heads/main
  )" ||
    fail "read-only deploy key could not read source refs/heads/main"
  [[ "$(wc -l <<<"${main_line}")" == "1" ]] ||
    fail "source refs/heads/main did not resolve exactly once"
  [[ "${main_line}" == "${release_sha}"$'\trefs/heads/main' ]] ||
    fail "requested release is not the exact source refs/heads/main commit"
}

read_main_ref
"${git_environment[@]}" git init --bare --quiet "${git_repository}"
"${git_environment[@]}" \
  git \
  -C "${git_repository}" \
  fetch \
  --quiet \
  --no-tags \
  --depth=1 \
  --filter=blob:none \
  "${source_url}" \
  refs/heads/main
fetched_sha="$(
  "${git_environment[@]}" \
    git -C "${git_repository}" rev-parse --verify FETCH_HEAD^{commit}
)"
[[ "${fetched_sha}" == "${release_sha}" ]] ||
  fail "fetched source main commit differs from the requested release"
git_tree="$(
  "${git_environment[@]}" \
    git -C "${git_repository}" rev-parse --verify "${release_sha}^{tree}"
)"
[[ "${git_tree}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "fetched source commit has no canonical tree"
[[ "${git_tree}" == "${approved_git_tree}" ]] ||
  fail "fetched source tree differs from the protected release policy"

/usr/bin/python3 -I \
  "${script_root}/extract-signer-handoff.py" \
  --bundle "${handoff_bundle}" \
  --output-directory "${output_dir}" \
  --release-sha "${release_sha}"

request_name="spy-signer-request-${release_sha}.txt"
archive_name="spy-application-${release_sha}.tar.gz"
request_sha256="$(
  sha256sum "${output_dir}/${request_name}" |
    cut -d ' ' -f1
)"
archive_sha256="$(
  sha256sum "${output_dir}/${archive_name}" |
    cut -d ' ' -f1
)"
read_main_ref
printf '%s\n' \
  "format=spy-signer-source-evidence-v2" \
  "source_transport=private-r2-eu-presigned-get" \
  "source_repository=${source_repository}" \
  "source_ref=refs/heads/main" \
  "git_commit=${release_sha}" \
  "git_tree=${git_tree}" \
  "handoff_bundle_sha256=${handoff_sha256}" \
  "request_sha256=${request_sha256}" \
  "archive_sha256=${archive_sha256}" \
  >"${output_dir}/SOURCE_EVIDENCE"

chmod 0440 \
  "${output_dir}/${request_name}" \
  "${output_dir}/${archive_name}" \
  "${output_dir}/SOURCE_EVIDENCE"

echo "Private source handoff verified for ${release_sha}."
