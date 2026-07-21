#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/bin:/bin:/usr/local/bin
export LC_ALL=C
export PATH

repository="${GITHUB_REPOSITORY:-}"
workflow_sha="${GITHUB_SHA:-}"
bootstrap_token="${SPY_SIGNER_BOOTSTRAP_TOKEN:-}"
repository_token="${SPY_SIGNER_REPOSITORY_TOKEN:-}"
existing_signing_private_key_b64="${SPY_EXISTING_SIGNING_PRIVATE_KEY_B64:-}"
existing_source_deploy_key_b64="${SPY_EXISTING_SOURCE_DEPLOY_PRIVATE_KEY_B64:-}"
signing_key_id="${SPY_SIGNING_KEY_ID:-}"
source_repository="${SPY_SOURCE_REPOSITORY:-}"
bootstrap_phase="${SPY_BOOTSTRAP_PHASE:-}"
confirmed_key_id="${SPY_CONFIRM_SIGNING_KEY_ID:-}"
confirmed_source_public_digest="${SPY_CONFIRM_SOURCE_DEPLOY_PUBLIC_KEY_SHA256:-}"
confirmed_source_read_only="${SPY_CONFIRM_SOURCE_DEPLOY_KEY_READ_ONLY:-}"
policy_source_release_sha="${SPY_POLICY_SOURCE_RELEASE_SHA:-}"
expected_signer_sha="${SPY_EXPECTED_SIGNER_SHA:-}"
api_url="${GITHUB_API_URL:-https://api.github.com}"
api_version="2026-03-10"
signing_environment="production-signing"
signing_secret_name="SPY_RELEASE_SIGNING_PRIVATE_KEY_B64"
source_deploy_secret_name="SPY_SOURCE_DEPLOY_PRIVATE_KEY_B64"
handoff_capability_secret_name="SPY_R2_HANDOFF_PRESIGNED_URL"
bootstrap_secret_name="SPY_SIGNER_BOOTSTRAP_TOKEN"
source_deploy_key_title="spy-release-signer-read-only"
generation_tag="spy-signer-generation-${signing_key_id}"
gh_token_environment_name="GH_TOKEN"
bootstrap_cleanup_required=false
temporary_root=""
source_public_digest=""

fail() {
  echo "Spy signer bootstrap failed: $*" >&2
  exit 1
}

[[ "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "GITHUB_REPOSITORY is invalid"
[[ "${workflow_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "signer workflow SHA is invalid"
[[ "${policy_source_release_sha}" =~ ^[a-f0-9]{40}$ ]] ||
  fail "SPY_POLICY_SOURCE_RELEASE_SHA is invalid"
[[ "${expected_signer_sha}" == "${workflow_sha}" ]] ||
  fail "selected signer SHA differs from the executing workflow"
[[ "${GITHUB_REF:-}" == \
  "refs/tags/spy-sign-policy-${policy_source_release_sha}" ]] ||
  fail "bootstrap may run only from the exact immutable policy tag"
[[ "${signing_key_id}" =~ ^[a-z0-9][a-z0-9_-]{0,22}$ ]] ||
  fail "SPY_SIGNING_KEY_ID is invalid"
[[ "${confirmed_key_id}" == "${signing_key_id}" ]] ||
  fail "workflow confirmation does not match SPY_SIGNING_KEY_ID"
[[ "${source_repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "SPY_SOURCE_REPOSITORY is invalid"
[[ -n "${repository_token}" ]] ||
  fail "signer repository token is unavailable"
case "${bootstrap_phase}" in
  prepare)
    [[ -z "${confirmed_source_public_digest}" ]] ||
      fail "prepare phase must not pre-confirm an unknown deploy-key digest"
    [[ "${confirmed_source_read_only}" == "false" ]] ||
      fail "prepare phase must leave the read-only confirmation unchecked"
    ;;
  finalize)
    [[ "${confirmed_source_public_digest}" =~ ^[a-f0-9]{64}$ ]] ||
      fail "finalize phase requires the exact deploy public-key SHA-256"
    [[ "${confirmed_source_read_only}" == "true" ]] ||
      fail "finalize phase requires an explicit read-only operator confirmation"
    [[ -z "${bootstrap_token}" ]] ||
      fail "finalize phase must not receive signer bootstrap authority"
    ;;
  *) fail "SPY_BOOTSTRAP_PHASE must be prepare or finalize" ;;
esac

for command in \
  base64 \
  bash \
  cat \
  chmod \
  cmp \
  curl \
  cut \
  dirname \
  env \
  git \
  gh \
  grep \
  jq \
  mkdir \
  mktemp \
  openssl \
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

delete_repository_secret() {
  local secret_name="$1"
  local delete_status

  delete_status="$(
    curl \
      --silent \
      --show-error \
      --request DELETE \
      --header "Accept: application/vnd.github+json" \
      --header "Authorization: Bearer ${bootstrap_token}" \
      --header "X-GitHub-Api-Version: ${api_version}" \
      --output /dev/null \
      --write-out '%{http_code}' \
      "${api_url}/repos/${repository}/actions/secrets/${secret_name}"
  )" || return 1
  case "${delete_status}" in
    204 | 404) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_immutable_releases() {
  local attempt
  local immutable_enabled
  local immutable_status

  for attempt in 1 2; do
    immutable_status="$(
      curl \
        --silent \
        --show-error \
        --request GET \
        --header "Accept: application/vnd.github+json" \
        --header "Authorization: Bearer ${bootstrap_token}" \
        --header "X-GitHub-Api-Version: ${api_version}" \
        --output "${temporary_root}/immutable.json" \
        --write-out '%{http_code}' \
        "${api_url}/repos/${repository}/immutable-releases"
    )"
    case "${immutable_status}" in
      200)
        immutable_enabled="$(
          jq -r \
            'if (.enabled | type) == "boolean" then .enabled else "invalid" end' \
            "${temporary_root}/immutable.json"
        )"
        case "${immutable_enabled}" in
          true) return 0 ;;
          false) ;;
          *) fail "immutable release policy response is malformed" ;;
        esac
        ;;
      404) ;;
      *) fail "immutable release policy check returned HTTP ${immutable_status}" ;;
    esac
    ((attempt == 1)) ||
      fail "signer repository immutable releases remain disabled"
    immutable_status="$(
      curl \
        --silent \
        --show-error \
        --request PUT \
        --header "Accept: application/vnd.github+json" \
        --header "Authorization: Bearer ${bootstrap_token}" \
        --header "X-GitHub-Api-Version: ${api_version}" \
        --output /dev/null \
        --write-out '%{http_code}' \
        "${api_url}/repos/${repository}/immutable-releases"
    )"
    [[ "${immutable_status}" == "204" ]] ||
      fail "immutable releases could not be enabled"
  done
  fail "signer repository immutable releases are not enabled"
}

cleanup() {
  local exit_status="$?"
  local signer_delete_status=0

  trap - EXIT HUP INT TERM
  if [[ "${bootstrap_cleanup_required}" == "true" ]]; then
    if [[ -n "${bootstrap_token}" ]]; then
      delete_repository_secret "${bootstrap_secret_name}" ||
        signer_delete_status=1
      if ((signer_delete_status != 0)); then
        echo \
          "Spy signer bootstrap failed: attested bootstrap completed, but its transient repository secret requires cleanup." \
          >&2
        if ((exit_status == 0)); then
          exit_status=1
        fi
      fi
    fi
  fi
  unset \
    bootstrap_token \
    repository_token \
    existing_signing_private_key_b64 \
    existing_source_deploy_key_b64
  if [[ -n "${temporary_root}" ]]; then
    chmod -R u+w "${temporary_root}" 2>/dev/null || true
    if ! rm -rf -- "${temporary_root}"; then
      if ((exit_status == 0)); then
        exit_status=1
      fi
    fi
  fi
  exit "${exit_status}"
}

exit_for_signal() {
  local signal_name="$1"
  local signal_status

  case "${signal_name}" in
    HUP) signal_status=129 ;;
    INT) signal_status=130 ;;
    TERM) signal_status=143 ;;
    *) signal_status=1 ;;
  esac
  trap - HUP INT TERM
  exit "${signal_status}"
}

trap cleanup EXIT
trap 'exit_for_signal HUP' HUP
trap 'exit_for_signal INT' INT
trap 'exit_for_signal TERM' TERM

temporary_root="$(mktemp -d)"
signing_private_key="${temporary_root}/signing-private.pem"
source_deploy_private_key="${temporary_root}/source-deploy-private"
source_deploy_public_key="${temporary_root}/source-deploy-public.pub"
source_deploy_public_canonical="${temporary_root}/source-deploy-public.canonical"
asset_root="${temporary_root}/keyring-assets"
known_hosts="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)/config/github.com.known_hosts"
umask 077
mkdir -m 0700 "${asset_root}"
[[ -f "${known_hosts}" && ! -L "${known_hosts}" ]] ||
  fail "pinned GitHub SSH host key is unavailable"

decode_existing_keys() {
  [[ "${existing_signing_private_key_b64}" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
    fail "attested signing key is unavailable for bootstrap recovery"
  [[ "${existing_source_deploy_key_b64}" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
    fail "attested source deploy key is unavailable for bootstrap recovery"
  printf '%s' "${existing_signing_private_key_b64}" |
    base64 --decode >"${signing_private_key}"
  printf '%s' "${existing_source_deploy_key_b64}" |
    base64 --decode >"${source_deploy_private_key}"
  chmod 0600 "${signing_private_key}" "${source_deploy_private_key}"
}

derive_source_public_key() {
  ssh-keygen -y -f "${source_deploy_private_key}" \
    >"${source_deploy_public_key}" 2>/dev/null
  grep -Eq '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' \
    "${source_deploy_public_key}" ||
    fail "source deploy key is not canonical Ed25519"
  cut -d ' ' -f1-2 "${source_deploy_public_key}" \
    >"${source_deploy_public_canonical}"
}

calculate_source_public_digest() {
  source_public_digest="$(
    sha256sum "${source_deploy_public_canonical}" |
      cut -d ' ' -f1
  )"
  [[ "${source_public_digest}" =~ ^[a-f0-9]{64}$ ]] ||
    fail "source deploy public-key SHA-256 is invalid"
}

verify_operator_confirmation() {
  [[ "${bootstrap_phase}" == "finalize" ]] ||
    fail "an immutable signing generation requires the finalize phase"
  [[ "${confirmed_source_public_digest}" == "${source_public_digest}" ]] ||
    fail "operator-confirmed deploy public-key digest differs from the environment key"
  [[ "${confirmed_source_read_only}" == "true" ]] ||
    fail "operator did not attest that write access is disabled"
}

write_manual_registration_summary() {
  local summary_path="${GITHUB_STEP_SUMMARY:-}"

  [[ -n "${summary_path}" ]] ||
    fail "GITHUB_STEP_SUMMARY is unavailable for the manual deploy-key gate"
  [[ ! -L "${summary_path}" && ( ! -e "${summary_path}" || -f "${summary_path}" ) ]] ||
    fail "GITHUB_STEP_SUMMARY is not a regular file"
  {
    printf '%s\n' \
      '## Manual source deploy-key gate' \
      '' \
      "Repository: \`${source_repository}\`" \
      "Title: \`${source_deploy_key_title}\`" \
      "Canonical public-key SHA-256: \`${source_public_digest}\`" \
      '' \
      'Paste exactly this public key into Settings -> Deploy keys and leave Allow write access unchecked:' \
      '' \
      '```text'
    cat "${source_deploy_public_canonical}"
    printf '%s\n' \
      '```' \
      '' \
      'Then dispatch the same immutable tag with phase `finalize`, the exact SHA-256 above,' \
      'and `confirm_source_deploy_key_read_only=true`.'
  } >>"${summary_path}"
  echo "Manual source deploy-key registration evidence was written to the job summary."
}

verify_source_read_access() {
  local ssh_config="${temporary_root}/ssh-config"
  local source_line

  cat >"${ssh_config}" <<EOF
Host github.com
  HostName github.com
  User git
  IdentityFile ${source_deploy_private_key}
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
  source_line="$(
    env -i \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_SSH_COMMAND="/usr/bin/ssh -F ${ssh_config}" \
      GIT_SSH_VARIANT=ssh \
      HOME="${temporary_root}" \
      LANG=C \
      LC_ALL=C \
      PATH=/usr/bin:/bin \
      git ls-remote \
      --exit-code \
      --refs \
      "ssh://git@github.com/${source_repository}.git" \
      refs/heads/main
  )" ||
    fail "attested read-only source deploy key cannot read refs/heads/main"
  [[ "$(wc -l <<<"${source_line}")" == "1" ]] ||
    fail "source refs/heads/main did not resolve exactly once"
  [[ "${source_line}" =~ ^[a-f0-9]{40}$'\t'refs/heads/main$ ]] ||
    fail "source refs/heads/main is not one canonical GitHub commit"
}

download_release_asset() {
  local release_json="$1"
  local asset_name="$2"
  local output="$3"
  local asset_id
  local asset_size
  local asset_digest

  [[ "$(
    jq \
      --arg name "${asset_name}" \
      '[.assets[] | select(.name == $name and .state == "uploaded")] | length' \
      "${release_json}"
  )" == "1" ]] ||
    fail "attested generation release is missing asset '${asset_name}'"
  asset_id="$(
    jq -er \
      --arg name "${asset_name}" \
      '.assets[] | select(.name == $name) | .id' \
      "${release_json}"
  )"
  asset_size="$(
    jq -er \
      --arg name "${asset_name}" \
      '.assets[] | select(.name == $name) | .size' \
      "${release_json}"
  )"
  asset_digest="$(
    jq -er \
      --arg name "${asset_name}" \
      '.assets[] | select(.name == $name) | .digest' \
      "${release_json}"
  )"
  [[ "${asset_id}" =~ ^[0-9]+$ && "${asset_size}" =~ ^[0-9]+$ ]] ||
    fail "attested generation asset metadata is invalid"
  [[ "${asset_size}" -ge 1 && "${asset_size}" -le 65536 ]] ||
    fail "attested generation asset exceeds its size limit"
  [[ "${asset_digest}" =~ ^sha256:[a-f0-9]{64}$ ]] ||
    fail "attested generation asset has no provider SHA-256"
  curl \
    --fail \
    --silent \
    --show-error \
    --location \
    --request GET \
    --header "Accept: application/octet-stream" \
    --header "Authorization: Bearer ${repository_token}" \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --output "${output}" \
    "${api_url}/repos/${repository}/releases/assets/${asset_id}"
  [[ "$(stat -c '%s' -- "${output}")" == "${asset_size}" ]] ||
    fail "downloaded generation asset length differs"
  [[ "sha256:$(
    sha256sum "${output}" |
      cut -d ' ' -f1
  )" == "${asset_digest}" ]] ||
    fail "downloaded generation asset digest differs"
}

verify_generation_release() {
  local release_json="$1"
  local generation_public="${temporary_root}/generation-public.pem"
  local generation_evidence="${temporary_root}/generation-evidence"
  local generation_manifest="${temporary_root}/generation-manifest.sha256"
  local derived_public="${temporary_root}/derived-signing-public.pem"
  local source_public_digest

  [[ "$(jq -er '.tag_name' "${release_json}")" == "${generation_tag}" ]] ||
    fail "attested signing generation tag drifted"
  [[ "$(jq -r '.draft' "${release_json}")" == "false" ]] ||
    fail "attested signing generation is still a draft"
  [[ "$(jq -r '.prerelease' "${release_json}")" == "false" ]] ||
    fail "attested signing generation must not be a prerelease"
  [[ "$(jq -r '.immutable' "${release_json}")" == "true" ]] ||
    fail "attested signing generation is not immutable"
  [[ "$(jq -er '.assets | length' "${release_json}")" == "3" ]] ||
    fail "attested signing generation asset inventory drifted"

  download_release_asset \
    "${release_json}" \
    "${signing_key_id}.pem" \
    "${generation_public}"
  download_release_asset \
    "${release_json}" \
    "SIGNING_KEY_GENERATION" \
    "${generation_evidence}"
  download_release_asset \
    "${release_json}" \
    "SIGNING_KEY_GENERATION_MANIFEST.sha256" \
    "${generation_manifest}"

  (
    cd "${temporary_root}"
    cp "${generation_public}" "${signing_key_id}.pem"
    cp "${generation_evidence}" SIGNING_KEY_GENERATION
    sha256sum --check --quiet --strict "${generation_manifest}"
    rm -f -- "${signing_key_id}.pem" SIGNING_KEY_GENERATION
  ) ||
    fail "attested signing generation manifest differs"
  openssl pkey \
    -in "${signing_private_key}" \
    -pubout \
    -out "${derived_public}" \
    >/dev/null 2>&1
  cmp --silent "${derived_public}" "${generation_public}" ||
    fail "environment signing key differs from immutable generation"

  source_public_digest="$(
    sha256sum "${source_deploy_public_canonical}" |
      cut -d ' ' -f1
  )"
  expected_generation="${temporary_root}/expected-generation"
  printf '%s\n' \
    "format=spy-signing-key-generation-v3" \
    "signing_key_generation=${signing_key_id}" \
    "source_repository=${source_repository}" \
    "source_deploy_public_key_sha256=${source_public_digest}" \
    "source_deploy_key_read_only_operator_attested=true" \
    "source_deploy_key_read_access_machine_verified=true" \
    >"${expected_generation}"
  cmp --silent "${expected_generation}" "${generation_evidence}" ||
    fail "immutable signing generation evidence differs from environment keys"
}

generation_release="${temporary_root}/generation-release.json"
generation_status="$(
  curl \
    --silent \
    --show-error \
    --request GET \
    --header "Accept: application/vnd.github+json" \
    --header "Authorization: Bearer ${repository_token}" \
    --header "X-GitHub-Api-Version: ${api_version}" \
    --output "${generation_release}" \
    --write-out '%{http_code}' \
    "${api_url}/repos/${repository}/releases/tags/${generation_tag}"
)"
case "${generation_status}" in
  200)
    if [[ "${bootstrap_phase}" == "prepare" && -n "${bootstrap_token}" ]]; then
      bootstrap_cleanup_required=true
    fi
    decode_existing_keys
    derive_source_public_key
    calculate_source_public_digest
    write_manual_registration_summary
    if [[ "${bootstrap_phase}" == "prepare" ]]; then
      echo "The immutable generation already exists; finalize it to verify and clean up bootstrap authority."
      exit 0
    fi
    verify_operator_confirmation
    verify_generation_release "${generation_release}"
    verify_source_read_access
    echo "Immutable signer generation ${signing_key_id} already attests the environment keys."
    echo "Transient bootstrap-secret cleanup is idempotently complete."
    exit 0
    ;;
  404) ;;
  *) fail "signing generation lookup returned HTTP ${generation_status}" ;;
esac

if [[ "${bootstrap_phase}" == "finalize" ]]; then
  [[ -n "${existing_signing_private_key_b64}" ]] ||
    fail "finalize requires the signing private key persisted by prepare"
  [[ -n "${existing_source_deploy_key_b64}" ]] ||
    fail "finalize requires the source deploy private key persisted by prepare"
  decode_existing_keys
  derive_source_public_key
  calculate_source_public_digest
  write_manual_registration_summary
  verify_operator_confirmation
  verify_source_read_access
else
  if [[
    -z "${bootstrap_token}" &&
    -n "${existing_signing_private_key_b64}" &&
    -n "${existing_source_deploy_key_b64}"
  ]]; then
    decode_existing_keys
    derive_source_public_key
    calculate_source_public_digest
    write_manual_registration_summary
    echo "Prepare is already durable; no generation release was published."
    exit 0
  fi
  [[ -n "${bootstrap_token}" ]] ||
    fail "prepare requires its one-time signer bootstrap token"

  ensure_immutable_releases

  environment_secret_count() {
    local secret_name="$1"

    env "${gh_token_environment_name}=${bootstrap_token}" \
      gh secret list \
      --repo "${repository}" \
      --env "${signing_environment}" \
      --json name \
      --jq \
      "[.[] | select(.name == \"${secret_name}\")] | length"
  }

for transient_secret_name in \
  "${handoff_capability_secret_name}" \
  "${bootstrap_secret_name}"
do
  [[ "$(environment_secret_count "${transient_secret_name}")" == "0" ]] ||
    fail "transient repository secret must never exist in the environment"
done

signing_secret_exists="$(environment_secret_count "${signing_secret_name}")"
case "${signing_secret_exists}" in
  0)
    [[ -z "${existing_signing_private_key_b64}" ]] ||
      fail "workflow exposed an unregistered signing key"
    openssl genpkey \
      -algorithm ED25519 \
      -out "${signing_private_key}" \
      >/dev/null 2>&1
    chmod 0600 "${signing_private_key}"
    base64 -w 0 "${signing_private_key}" |
      env "${gh_token_environment_name}=${bootstrap_token}" \
        gh secret set \
        "${signing_secret_name}" \
        --repo "${repository}" \
        --env "${signing_environment}" \
        >/dev/null
    ;;
  1)
    [[ "${existing_signing_private_key_b64}" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
      fail "registered signing key is unavailable for bootstrap recovery"
    printf '%s' "${existing_signing_private_key_b64}" |
      base64 --decode >"${signing_private_key}"
    chmod 0600 "${signing_private_key}"
    ;;
  *) fail "signing environment secret inventory is inconsistent" ;;
esac

source_secret_exists="$(environment_secret_count "${source_deploy_secret_name}")"
case "${source_secret_exists}" in
  0)
    [[ -z "${existing_source_deploy_key_b64}" ]] ||
      fail "workflow exposed an unregistered source deploy key"
    ssh-keygen \
      -q \
      -t ed25519 \
      -N '' \
      -C "${repository}:read-only:${source_repository}" \
      -f "${source_deploy_private_key}"
    chmod 0600 "${source_deploy_private_key}"
    base64 -w 0 "${source_deploy_private_key}" |
      env "${gh_token_environment_name}=${bootstrap_token}" \
        gh secret set \
        "${source_deploy_secret_name}" \
        --repo "${repository}" \
        --env "${signing_environment}" \
        >/dev/null
    ;;
  1)
    [[ "${existing_source_deploy_key_b64}" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] ||
      fail "registered source deploy key is unavailable for bootstrap recovery"
    printf '%s' "${existing_source_deploy_key_b64}" |
      base64 --decode >"${source_deploy_private_key}"
    chmod 0600 "${source_deploy_private_key}"
    ;;
  *) fail "source deploy environment secret inventory is inconsistent" ;;
esac
derive_source_public_key
calculate_source_public_digest
write_manual_registration_summary
bootstrap_cleanup_required=true
echo "Private keys are persisted in the protected environment; no generation release was published."
echo "The transient signer bootstrap repository secret is deleted idempotently on exit."
exit 0
fi

public_key="${asset_root}/${signing_key_id}.pem"
generation_evidence="${asset_root}/SIGNING_KEY_GENERATION"
manifest="${asset_root}/SIGNING_KEY_GENERATION_MANIFEST.sha256"
openssl pkey \
  -in "${signing_private_key}" \
  -pubout \
  -out "${public_key}" \
  >/dev/null 2>&1
grep -Fq "ED25519 Public-Key" <(
  openssl pkey -pubin -in "${public_key}" -text -noout 2>/dev/null
) ||
  fail "generated signing key is not Ed25519"
printf '%s\n' \
  "format=spy-signing-key-generation-v3" \
  "signing_key_generation=${signing_key_id}" \
  "source_repository=${source_repository}" \
  "source_deploy_public_key_sha256=${source_public_digest}" \
  "source_deploy_key_read_only_operator_attested=true" \
  "source_deploy_key_read_access_machine_verified=true" \
  >"${generation_evidence}"
chmod 0444 "${public_key}" "${generation_evidence}"
(
  cd "${asset_root}"
  sha256sum \
    "${signing_key_id}.pem" \
    "SIGNING_KEY_GENERATION"
) >"${manifest}"
chmod 0444 "${manifest}"

bash \
  "$(dirname "${BASH_SOURCE[0]}")/publish-immutable-release.sh" \
  "${generation_tag}" \
  "${workflow_sha}" \
  "Spy signing key generation ${signing_key_id}" \
  "${asset_root}" \
  "${signing_key_id}.pem" \
  "SIGNING_KEY_GENERATION" \
  "SIGNING_KEY_GENERATION_MANIFEST.sha256"

curl \
  --fail \
  --silent \
  --show-error \
  --request GET \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer ${repository_token}" \
  --header "X-GitHub-Api-Version: ${api_version}" \
  --output "${generation_release}" \
  "${api_url}/repos/${repository}/releases/tags/${generation_tag}"
verify_generation_release "${generation_release}"

echo "Signer key ${signing_key_id} and read-only source deploy key bootstrapped."
echo "The transient signer bootstrap repository secret is deleted idempotently on exit."
echo "Revoke the external signer bootstrap credential now."
