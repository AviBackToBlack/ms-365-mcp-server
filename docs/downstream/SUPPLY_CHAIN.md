# Supply-chain baseline

SM-2 establishes a fail-closed dependency baseline for the downstream distribution. It is intentionally narrower than the later SBOM, provenance, and reproducible-build milestones.

## What is gated

The supply-chain workflow verifies the exact `package-lock.json` against `downstream/supply-chain-policy.json` and fails if:

- the approved lockfile SHA-256 changes without an explicit baseline update;
- the lockfile format or package count changes unexpectedly;
- a non-bundled package resolves outside `https://registry.npmjs.org/`;
- a registry-resolved package lacks SHA-512 integrity metadata;
- the set of packages declaring install scripts changes;
- the pinned verification Node or npm version changes;
- `npm audit` reports any advisory not explicitly listed in the policy;
- a registry package signature or available provenance attestation fails verification.

The gate runs on pull requests and again on pushes to `main`, so the merged state is re-verified rather than assuming the PR test result still describes the post-merge tree. Dependency installation for this gate uses `npm ci --ignore-scripts`. The gate therefore downloads the locked dependency tree without executing dependency lifecycle scripts before it has checked the approved install-script surface.

## Registry signatures and attestations

The workflow runs `npm audit signatures` with the npm CLI version pinned by the lockfile and policy rather than relying on the npm version bundled with the GitHub runner's Node installation.

npm documents that `npm audit signatures` verifies registry signatures and also verifies provenance attestations when packages provide them. A missing or invalid registry signature from a registry that supports signatures is treated as an error.

References:

- https://docs.npmjs.com/cli/v11/commands/npm-audit/
- https://docs.npmjs.com/verifying-registry-signatures/
- https://docs.npmjs.com/generating-provenance-statements/

This is verification of upstream package evidence, not proof that every dependency was published with provenance. Downstream artifact provenance is a separate release milestone.

## Accepted vulnerability

The baseline currently accepts exactly one known advisory:

- `esbuild@0.27.4` - `GHSA-g7r4-m6w7-qqqr` - low severity, development scope.

The advisory concerns esbuild's development server on Windows. The project does not invoke the esbuild serve API in approved build, test, or runtime paths. The fixed esbuild line starts at 0.28.1, while current `tsup@8.5.1` declares `esbuild ^0.27.0`. Forcing an override solely to make an audit counter reach zero would put the dependency tree outside the tool's declared compatibility range.

This exception is therefore explicit, machine-readable, and temporary. It must be revisited when any trigger listed in `downstream/supply-chain-policy.json` occurs.

## Updating the baseline

A dependency update is not complete merely because `package-lock.json` changed.

The change must intentionally update the policy when necessary, explain any new install-script package or vulnerability exception, pass registry signature verification, and pass the normal project build/test workflow.

SBOM generation, downstream artifact attestation, and release provenance remain out of scope for SM-2 and are handled by their later milestones.

## Gate self-tests

The repository test suite includes negative fixtures for the supply-chain verifiers. The tests require a tampered lockfile hash, an unapproved advisory, and a Node-version policy mismatch to fail closed. This is intentionally minimal coverage of the security boundary rather than exhaustive testing of npm itself.
