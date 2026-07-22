#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/local/bin
export LC_ALL=C
export PATH

release_sha="${1:-}"
repository="${GITHUB_REPOSITORY:-}"
workflow_sha="${GITHUB_SHA:-}"
source_repository="${SPY_SOURCE_REPOSITORY:-}"
repository_token="${SPY_SIGNER_REPOSITORY_TOKEN:-}"

fail() {
  echo "Signing policy reference publication failed: $*" >&2
  exit 1
}

[[ "$#" == "1" && "${release_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "usage: publish-signing-policy-ref.sh <source-release-sha>"
[[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "GITHUB_REPOSITORY is invalid"
[[ "${source_repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "SPY_SOURCE_REPOSITORY is invalid"
[[ "${workflow_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "GITHUB_SHA is invalid"
[[ "${GITHUB_REF:-}" == "refs/heads/main" ]] ||
  fail "policy references may be sealed only from protected main"
[[ -n "${repository_token}" ]] ||
  fail "signer repository token is unavailable"

for command in bash chmod cut dirname mktemp rm sha256sum; do
  command -v "${command}" >/dev/null 2>&1 ||
    fail "required command '${command}' is unavailable"
done
[[ -x /usr/bin/python3 ]] ||
  fail "isolated system Python is unavailable"

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd "${script_root}/.." && pwd -P)"
policy_path="${repository_root}/policies/${release_sha}.policy"
sign_workflow="${repository_root}/.github/workflows/sign-release.yml"
template_contract="${repository_root}/scripts/verify-public-template.py"
[[ -f "${policy_path}" && ! -L "${policy_path}" ]] ||
  fail "reviewed release policy is unavailable"

temporary_root="$(mktemp -d)"
cleanup() {
  local exit_status="$?"
  trap - EXIT
  chmod -R u+w -- "${temporary_root}" 2>/dev/null || true
  rm -rf -- "${temporary_root}" || {
    if ((exit_status == 0)); then
      exit_status=1
    fi
  }
  exit "${exit_status}"
}
trap cleanup EXIT
umask 077
: >"${temporary_root}/policy-output"

/usr/bin/python3 -I \
  "${script_root}/validate-release-policy.py" \
  --policy "${policy_path}" \
  --release-sha "${release_sha}" \
  --source-repository "${source_repository}" \
  --github-output "${temporary_root}/policy-output"

evidence="${temporary_root}/SIGNING_POLICY_REF"
manifest="${temporary_root}/SIGNING_POLICY_REF_MANIFEST.sha256"
printf '%s\n' \
  "format=spy-signing-policy-ref-v1" \
  "source_release_sha=${release_sha}" \
  "signer_repository=${repository}" \
  "signer_commit=${workflow_sha}" \
  "policy_path=policies/${release_sha}.policy" \
  "policy_sha256=$(sha256sum "${policy_path}" | cut -d ' ' -f1)" \
  "sign_workflow_path=.github/workflows/sign-release.yml" \
  "sign_workflow_sha256=$(sha256sum "${sign_workflow}" | cut -d ' ' -f1)" \
  "template_contract_path=scripts/verify-public-template.py" \
  "template_contract_sha256=$(sha256sum "${template_contract}" | cut -d ' ' -f1)" \
  >"${evidence}"
(
  cd "${temporary_root}"
  sha256sum SIGNING_POLICY_REF
) >"${manifest}"
chmod 0444 "${evidence}" "${manifest}"

bash \
  "${script_root}/publish-immutable-release.sh" \
  "spy-sign-policy-${release_sha}" \
  "${workflow_sha}" \
  "Spy signing policy ${release_sha}" \
  "${temporary_root}" \
  SIGNING_POLICY_REF \
  SIGNING_POLICY_REF_MANIFEST.sha256

echo "Immutable signing policy ref published for ${release_sha}."
