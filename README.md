# Spy release signer

Public GitHub Actions signing boundary for one private Spy application repository.

This repository contains only:

- fixed manual bootstrap and signing workflows;
- non-secret verification and immutable-release programs;
- a pinned official GitHub SSH host key;
- CODEOWNERS and public policy documentation.

It never contains or publishes Spy application source, unsigned application bytes, an R2 capability,
private keys, a reusable workflow, or a generic signing API.

Required repository variables:

```text
SPY_SOURCE_REPOSITORY
SPY_SIGNING_KEY_ID
SPY_R2_EU_ENDPOINT_HOST
SPY_R2_HANDOFF_BUCKET_NAME
```

Persistent `production-signing` environment secrets:

```text
SPY_RELEASE_SIGNING_PRIVATE_KEY_B64
SPY_SOURCE_DEPLOY_PRIVATE_KEY_B64
```

Transient `production-signing` environment secret:

```text
SPY_R2_HANDOFF_PRESIGNED_URL
```

Transient repository bootstrap secret:

```text
SPY_SIGNER_BOOTSTRAP_TOKEN
```

The R2 capability is created only after `production-signing` selects one exact immutable
`spy-sign-policy-<source-sha>` tag. GitHub reads an environment secret only when the job referencing
that environment starts. The dispatcher verifies the exact tag, signer commit, immutable release,
tagged policy/workflow bytes, environment tag policy and exact workflow run ID, then deletes the
capability as soon as that one job starts. It never dispatches mutable `main`.

Bootstrap is intentionally two-phase on the same immutable policy tag. `prepare` persists both
private keys in the protected environment, writes only the canonical SSH public key and SHA-256 to
the job summary, publishes no generation release, and deletes the signer bootstrap repository
secret. Its external credential must then be revoked. The operator manually adds that exact public
key to the private source repository with `Allow write access` unchecked. `finalize` receives no
admin token; it requires the already injected private keys, the exact digest and an explicit
read-only confirmation, verifies SSH read access, and only then publishes immutable generation v3
evidence. The evidence distinguishes operator-attested read-only policy from machine-verified read
access. There is no persistent PAT, OAuth token, GitHub App private key, or API-created deploy key
for private source access.

Every source commit has one protected-main `policies/<full-sha>.policy`. It binds the exact
source commit/tree, release archive, canonical manifest, release-specific builder image and stable
signing-key generation. After review, `seal-signing-policy.yml` publishes
`spy-sign-policy-<source-sha>` as an immutable release/tag bound to the exact reviewed signer
commit. Bootstrap and signing are dispatched only at that tag. The signing workflow derives a
policy ID containing the full source SHA and publishes a public immutable keyring alias before
signing. A mutable repository variable or branch never authorizes a release.

## Required external controls

Branch protection and environment protection are external provisioning preconditions; repository
bytes cannot enforce or attest them. Before bootstrap or signing, an operator must record evidence
that protected `main` requires pull requests, signed commits, linear history, the required status
check `Verify signer template / verify-template`, and that force pushes, branch deletion and bypass
are disabled. Before every bootstrap or signing dispatch, the `production-signing` environment
must use custom policies, disable protected-branch selection and contain exactly one custom tag policy;
its name is the selected `spy-sign-policy-<source-sha>` tag and its type is `tag`.
Repository Actions defaults remain read-only; only GitHub-owned actions pinned by full commit SHA
are allowed; and immutable releases are enabled before bootstrap.

Bootstrap accepts both GitHub disabled states (`404` and `200` with `enabled=false`), enables the
setting, then requires a fresh `200` response with boolean `enabled=true`. Release publication is
restart-safe: an existing draft is recovered from the bounded release inventory and all subsequent
operations remain bound to its numeric release ID. A failed upload may recover only one expected,
zero-byte `starter` asset with a numeric ID; ambiguous, non-empty, unknown or mismatched state fails
closed.

CODEOWNERS routes sensitive changes, but no independent human approval exists until a second
trusted reviewer is configured. That limitation must remain explicit in provisioning evidence.

Public immutable releases contain only signing-key generation evidence, release-specific keyring
policy aliases, or detached signing response files. See the owner document `ops/signer/README.md`
in the private Spy repository before provisioning, dispatch, rotation, or recovery.
