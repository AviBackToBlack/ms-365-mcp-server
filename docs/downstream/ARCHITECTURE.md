# Downstream Security Distribution Architecture

## Purpose

This repository is a security-sensitive downstream distribution of `Softeria/ms-365-mcp-server`.

The production trust boundary is not the upstream npm package. An approved runtime must be traceable through this chain:

```text
upstream source commit
  -> controlled downstream integration
  -> reviewed downstream source commit
  -> pinned build inputs
  -> audited build
  -> attested immutable artifact
  -> approved runtime installation
```

The project must always be able to answer:

- Which exact source commit is running?
- Which exact upstream commit is it based on?
- What downstream delta exists on top of that upstream commit?
- Which Graph permissions can the runtime request?
- Which outbound destinations can receive data?
- Which dependencies and generated inputs were used?
- Which security checks passed for the exact source and artifact?
- Which immutable artifact is installed?
- What changed from the previous approved release?

## Trust model

Upstream is an input, not a trust root.

No upstream branch, tag, npm dist-tag, package, generated file, dependency update, or release is promoted automatically into the downstream runtime.

The initial approved upstream baseline is recorded in `downstream/baseline.json`.

## Git topology

Local working copies use two remotes:

```text
origin   https://github.com/AviBackToBlack/ms-365-mcp-server.git
upstream https://github.com/Softeria/ms-365-mcp-server.git
```

`main` is the approved downstream source history. Direct automated upstream sync into `main` is forbidden.

### Why merge-based upstream integration

Canonical downstream history uses controlled merge-based upstream sync rather than rebasing the long-lived approved branch.

For an upstream update:

1. Fetch `upstream`.
2. Resolve an exact upstream release tag and commit.
3. Create `sync/upstream-vX.Y.Z` from the current downstream `main`.
4. Merge the exact upstream commit with `--no-ff`.
5. Resolve conflicts explicitly.
6. Update downstream baseline metadata.
7. Run security, dependency, MCP-specific, build, and test gates.
8. Review the pull request.
9. Merge only through the normal project merge gate.

This preserves approved history, avoids force-pushing trusted commits, and keeps GitHub pull-request review semantics intact.

A linear rebase/cherry-pick stack is useful for short-lived local experiments, but is not the canonical long-lived history because repeated rebases would rewrite previously approved commits or require non-fast-forward promotion.

`git rerere` may be used as a local conflict-resolution convenience, but its cache is not trusted evidence and is never a substitute for review.

## Downstream delta and patchset identity

The effective downstream patchset is the canonical source diff between the recorded upstream base commit and the approved downstream source commit.

For releases, the pipeline will generate a normalized patch artifact and hash it. That digest becomes `DOWNSTREAM_PATCHSET_ID`.

Generated patch files are evidence, not the source of truth. The repository history plus the exact upstream base define the source of truth. This avoids maintaining a second hand-edited patch series that can silently drift from the source actually built.

## Branch and release model

Planned branch roles:

```text
main                     approved downstream source
sm-N/*                   milestone implementation branches
sync/upstream-vX.Y.Z      controlled upstream-update candidates
```

Planned downstream release versioning:

```text
v<upstream-version>-abtb.<revision>
```

Example: `v0.156.2-abtb.1`.

This scheme is provisional until the downstream release pipeline is implemented. Under SemVer, `0.156.2-abtb.1` is a prerelease of `0.156.2` and therefore sorts below the upstream release. The release milestone must explicitly validate the chosen versioning scheme against every distribution mechanism we use (including npm dist-tags/ranges, if npm publication is retained) rather than relying on intuitive ordering.

A release tag identifies an exact approved downstream source commit. Runtime installation must use an immutable downstream artifact by digest, never `npx ...@latest` and never runtime npm dependency resolution.

## Build model

A downstream release build must be closed over immutable inputs:

- exact downstream source commit;
- exact upstream base commit;
- exact dependency lockfile;
- pinned toolchain;
- pinned or vendored generated-code inputs;
- no mutable live network inputs during the release build.

In particular, upstream `npm run generate` currently consumes live Microsoft Graph OpenAPI data. That is not acceptable as an unpinned release-build input. A later milestone will pin or vendor the audited OpenAPI input and verify its digest before generation.

## Release evidence

The release process will eventually emit and bind at least:

```text
SOURCE_COMMIT
UPSTREAM_BASE_COMMIT
DOWNSTREAM_PATCHSET_ID
PACKAGE_VERSION
LOCKFILE_SHA256
GENERATED_INPUT_SHA256
SBOM_SHA256
NPM_TARBALL_SHA256
NPM_TARBALL_SHA512
BUILD_PROVENANCE
AUDIT_RESULT
```

GitHub OIDC artifact attestations are preferred for CI artifact provenance. Developer commit signing and CI artifact attestation are separate controls.

Package contents are also part of the release contract. Before the first downstream package is published, the release milestone must replace accidental npm inclusion behavior with an explicit package-content allowlist/verification step. Evidence that is intended to travel with the artifact must be deliberately included; repository-only architecture material must not be included merely because npm's default file selection happens to pick it up.

## Security gates

The downstream pipeline will be layered instead of treating generic scanners as sufficient:

1. Static code security: CodeQL, Semgrep, secret scanning/Gitleaks.
2. Dependency and supply chain: OSV, npm audit, registry signatures and provenance, SBOM, dependency review.
3. Repository security: immutable action pinning, minimal workflow permissions, Scorecard, protected merge gates.
4. MCP-specific policy checks:
   - MCP instructions and tool-description changes;
   - tool schemas and endpoint definitions;
   - Graph permission changes;
   - outbound hostname changes;
   - process execution;
   - filesystem writes;
   - dynamic code;
   - arbitrary URL construction;
   - OAuth/token handling;
   - logging and redaction.

New Graph write permissions are fail-closed until explicitly approved. New outbound destinations require explicit review.

## Fork bootstrap invariants

Repository-level operational trust configuration is not assumed to be inherited from upstream when the fork is created.

Before the downstream repository is treated as operational, verify explicitly that:

- GitHub Actions is enabled for the fork;
- inherited upstream publisher workflows are prevented from publishing from the downstream repository;
- the automated reviewer identity has the access required by the repository ownership model;
- the signed `pull_request` webhook for the automated reviewer is configured and healthy;
- no webhook secret or other operational credential is committed to the repository.

For a repository owned by a GitHub personal account, collaborator access is not a granular read-only reviewer role: collaborators are write-capable. That makes branch/ruleset protection of the approved branch a required control before production acceptance, even though the full governance configuration is introduced separately.

## Upstream release workflow safety

The upstream release workflow is not our release mechanism.

Until it is replaced by the downstream release pipeline, this fork carries a repository-identity guard so the upstream publisher jobs cannot run in `AviBackToBlack/ms-365-mcp-server`.

That guard is currently per job, so controlled upstream sync must treat publisher-workflow changes as a fail-closed security surface. The security/upstream-sync gates must reject or require explicit approval for any inherited workflow that introduces a publishing-capable job or sensitive write permission (for example `id-token: write`, `packages: write`, or equivalent) without the downstream repository-identity guard. This is intentionally stronger than assuming today's three guarded jobs remain the complete publishing surface forever.

The downstream release pipeline will be introduced separately and will build, attest, hash, and publish only approved downstream artifacts.

## Runtime target

The first production target is local stdio on macOS with a deliberately narrow capability profile:

```text
--org-mode
--read-only
--allowed-scopes "User.Read Mail.Read Calendars.Read Chat.Read Team.ReadBasic.All"
```

The runtime hardening milestone will additionally address account pinning, token-cache handling, disabled auth modes, filesystem boundaries, audit logging, PII redaction, and network egress restrictions.

## Promotion rule

Passing scanners is necessary but not sufficient.

```text
candidate
  -> automated gates
  -> explicit human review
  -> approved source
  -> deterministic/pinned build
  -> artifact verification
  -> attestation + hashes
  -> release
  -> explicit runtime upgrade
```

Review approval and merge are separate gates. Release approval and runtime promotion are separate gates.
