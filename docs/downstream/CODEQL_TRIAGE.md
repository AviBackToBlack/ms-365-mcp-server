# CodeQL baseline triage

The first CodeQL `security-extended` analysis of the downstream default branch completed successfully and then populated GitHub code scanning with 28 alerts. This is an important distinction: a successful CodeQL Action run proves that analysis and SARIF upload succeeded; it does not mean that the analyzed branch has zero findings.

SM-3.1 triages that initial default-branch backlog before SM-4 is allowed to merge.

## Disposition

### Fixed in SM-3.1

**Alert 1 — `js/incomplete-sanitization`**

`remove-recursive-refs.js` removed only the first quote from an already matched reference string. The diagnostic extraction now removes all quote delimiters.

**Alerts 11–16, 21–22 — `js/clear-text-logging`**

The findings point at authentication/account/cache paths. The downstream hardening does two things:

- operational logs no longer include selected account IDs, account usernames, or raw upstream authentication error text at the flagged sites;
- credential redaction is now unconditional. `MS365_MCP_REDACT_PII=false` may disable optional email/UPN masking, but it can no longer disable JWT, Bearer, OAuth token, authorization-code, or client-secret scrubbing.

Keychain findings 21–22 also contain CodeQL data-flow false positives: the logged value was an exception message, not the value returned by `getPassword`. The generic logging change nevertheless removes the ambiguity.

**Alerts 23–24 — `js/insecure-helmet-configuration`**

The MCP HTTP application and the dedicated attachment listener now send a deny-all CSP (`default-src 'none'`, with restrictive base/form/frame directives) instead of disabling CSP. Integration tests assert the header on both listeners.

**Alerts 19–20 — startup diagnostic output**

Startup stderr is now passed through the same credential-safe redaction policy before it is emitted. Whether CodeQL recognizes the project sanitizer is a tooling/model question; the runtime invariant is covered by tests.

### False positive / safe by design after review

**Alerts 2–6 — `js/regex-injection`**

`--enabled-tools` / `ENABLED_TOOLS` is operator configuration, not remote MCP/request input. The expression is evaluated only against the repository's fixed tool-name catalog: 334 names, with a current maximum length of 57 characters. This is not an attacker-controlled long-string ReDoS sink. Invalid regular expressions already fail startup.

**Alerts 7–10 — `js/missing-rate-limiting`**

The OAuth mutation endpoints are protected before route registration by `app.use('/authorize', authLimiter)`, `app.use('/token', authLimiter)`, and `app.use('/register', authLimiter)`. CodeQL does not model this middleware arrangement. The other highlighted routes are read-only OAuth discovery metadata.

**Alerts 17–18 — `js/clear-text-logging`**

These are explicit CLI command results for `--login` / `--verify-login`, written to stdout for the invoking operator. They are not operational log-file writes. The output is the requested command result.

**Alert 26 — `js/file-access-to-http`**

`fetchWithResilience` is a generic wrapper, but its only production caller is `GraphClient.performRequest`, which constructs the URL from the reviewed Microsoft cloud Graph base plus API version and endpoint. No filesystem value supplies the production URL. The remaining call sites are tests.

**Alert 27 — `js/user-controlled-bypass`**

The apparent bypass is an intentional pair of operator-controlled HTTP modes:

- `--trust-proxy-auth` delegates authentication to an upstream proxy and is off by default;
- `--allow-unauthenticated-discovery` permits only the explicit discovery-method allowlist and never permits unauthenticated `tools/call`.

Request data cannot enable either mode. The server also rejects dangerous combinations such as proxy-auth with local-file tools or OBO.

### Deferred to SM-5 reproducible/build hardening

**Alert 25 — `js/file-system-race`**

**Alert 28 — `js/http-to-file-access`**

Both findings are in `bin/modules/download-openapi.mjs`, the build-time downloader that currently fetches mutable Microsoft Graph OpenAPI from `master` and writes it to a local generation input. This is already the central SM-5 defect: the source is mutable and the download/write process is not yet a sealed deterministic input path.

These alerts remain open until SM-5 replaces the mutable download with pinned/vendored, hash-verified generation inputs. They are not runtime behavior of the first production stdio profile.

## Merge-protection semantics

GitHub code scanning has a separate merge-protection mechanism from the CodeQL analysis job. The CodeQL Action can succeed while publishing findings.

After the initial backlog is fixed or explicitly triaged, the repository should require CodeQL results at the chosen security threshold so that future PRs cannot silently introduce new qualifying alerts. This is a repository governance control, separate from scanner execution itself.

## Evidence required before closing SM-3.1

- normal Build matrix remains green;
- Supply Chain and Static Security workflows remain green;
- focused logging/CSP tests pass;
- full test suite passes;
- CodeQL rerun on the branch shows the expected fixed-alert delta;
- each remaining default-branch alert has a documented disposition above;
- no alert is bulk-dismissed merely to make the dashboard green.
