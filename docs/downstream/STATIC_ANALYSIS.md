# Static security analysis

SM-3 adds three independent static-analysis layers to the downstream distribution.

## CodeQL

GitHub CodeQL runs JavaScript/TypeScript analysis with the `security-extended` query suite.

Pinned action:

- `github/codeql-action` v4.38.2
- commit `88585263c0627ee42c0e1c5143a112c8d6f4aa18`

The extended suite contains the default security queries plus additional lower-precision
security queries. CodeQL scans the repository independently from Semgrep and publishes
code-scanning results through GitHub.

## Semgrep

The blocking Semgrep gate is intentionally deterministic:

- Semgrep CLI image: `semgrep/semgrep:1.178.0`
- OCI index digest: `sha256:32e459968daabe7ab86968184a29109b9564aa00392401156f9788452b42786b`
- rules repository: `semgrep/semgrep-rules`
- rules commit: `311ca4e9ba59d700624539bf658e3d29b134ee77`

Blocking scan scope is runtime source under `src/`, excluding test fixtures. It runs
ERROR-severity rules from:

- `javascript/lang/security`
- `javascript/express/security`
- `javascript/node-crypto/security`

The broader audit/WARNING families are not a merge gate in SM-3 because the baseline
contains many heuristic findings that require semantic triage. They remain useful review
input rather than being converted into blanket allowlists.

Experimental MCP-specific Semgrep rules are also not a blocking SM-3 input. A discovery
run against Semgrep rules commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` found that
the current MCP SSRF rule has an unconstrained `$AXIOS($URL, ...)` sink that matches
arbitrary function calls, including non-network calls. MCP-specific policy therefore
remains a separate SM-6 concern where those rules can be validated or adapted before
enforcement.

## Secret and entropy scanning

Gitleaks scans the complete imported Git history, not only the current tree.

Pinned release:

- Gitleaks v8.30.1
- Linux x64 tarball SHA-256: `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`

The default Gitleaks rules provide token, key, credential, and entropy-based heuristics.

The imported upstream history currently has four known false positives. `.gitleaks.toml`
allows them only when the detector rule, historical commit, and file path all match. The
exceptions are for a synthetic JWT fixture, Azure built-in role definition GUIDs, a
Microsoft public client application identifier, and a synthetic bearer token in
documentation. Future occurrences in those files are not exempt.

## Runtime hardening found during baseline establishment

The initial Semgrep discovery scan identified AES-GCM decryption without an explicit
`authTagLength` option. The code already rejected tags whose decoded length was not 16
bytes, but SM-3 also pins the expected 16-byte tag length at the Node crypto API boundary
for both encryption and decryption.

A build-time generator also uses shell-string `execSync`. It is outside the blocking
runtime Semgrep scope because its input paths are constructed by the build generator
rather than MCP/runtime callers. CodeQL still sees repository build code, and deterministic
generation/build hardening is handled in SM-5.

## Trigger and promotion behavior

Static Security runs on pull requests, pushes to `main`, and explicit manual dispatch.

Passing this workflow is necessary but not sufficient for promotion. Automated review,
downstream policy review, deterministic build evidence, artifact attestation, and explicit
runtime promotion remain separate gates.
