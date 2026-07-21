# Per-release signing policies

Every private Spy source release requires exactly one public reviewed file:

```text
policies/<40-character-source-commit>.policy
```

Canonical format:

```text
format=spy-release-signing-policy-v2
source_repository=sudiakov/spy
git_commit=<40-character-source-commit>
git_tree=<40-character-source-tree>
release_archive_sha256=<64-lowercase-hex>
release_manifest_sha256=<64-lowercase-hex>
builder_image_digest=sha256:<64-lowercase-hex>
node_version=v24.15.0
signing_key_generation=<stable-id-up-to-23-characters>
```

The tree, archive, canonical manifest and builder image are source-specific. A mutable repository
variable must never authorize them. Protected `main` review of this file is the signing
authorization. The signer independently fetches the tree, hashes the archive and hashes the
manifest before deriving a unique policy ID
`<generation>-<full-40-character-source-commit>`. Its immutable keyring alias and detached
application attestation bind every value above.
