# MCP-specific security gates

SM-4 turns the MCP threat model into a deterministic, reviewable source-level contract.

The gate is deliberately separate from generic CodeQL/Semgrep/Gitleaks scanning. It asks a different question: **did this change expand what the MCP server can ask for, describe, contact, execute, load, or write?**

## Checked-in security artifacts

Two files are authoritative:

- `downstream/mcp-security-baseline.json` is generated from the reviewed source tree.
- `downstream/mcp-security-policy.json` records which capability classes are currently approved.

Run:

```text
node scripts/mcp-security-snapshot.mjs --check
```

to verify the source against both files.

When an intentional source change modifies a security surface, regenerate the baseline with:

```text
node scripts/mcp-security-snapshot.mjs --write
```

and review the resulting JSON diff. A capability expansion may also require an explicit policy change; changing only the baseline is not enough for scopes, cloud network hosts, URL-bearing or dynamically-computed environment access, process execution, filesystem writes, dynamic code, or dynamic imports.

## Tool and instruction drift

The baseline contains:

- SHA-256 for `src/mcp-instructions.ts`;
- SHA-256 for `src/endpoints.json`;
- one stable fingerprint per Graph tool, keyed by tool name + HTTP method + path;
- endpoint count and the complete write-capable tool-name set;
- SHA-256 for every scanned code file under `src/`, `bin/`, and `scripts/`, plus `src/endpoints.json`. The only code exclusion is mutable, untracked `src/generated/client.ts`; tracked runtime siblings such as `client-beta.ts`, `endpoint-types.ts`, and `hack.ts` are hashed and capability-scanned.

A description, scope, path, method, request-body override, `llmTip`, preset, or other tracked endpoint metadata therefore changes the affected tool fingerprint. CI reports that tool key in the security delta.

The source walker includes `.ts`, `.mts`, `.cts`, `.js`, `.mjs`, and `.cjs` files and skips test directories. This keeps CJS/CTS additions inside the same capability boundary instead of silently falling outside the analyzer.

The MCP verifier itself is inside the capability scan as well as the critical-file hash surface. Its existing `writeFileSync` use for baseline/step-summary output is an explicit approved filesystem-write capability; adding execution, dynamic code, or network-style environment access to the verifier would therefore require policy review like any other source file.

Complete generated parameter-schema fingerprinting is intentionally marked `deferred-to-SM-5`. Specifically, mutable `src/generated/client.ts` is untracked and currently produced from live Microsoft Graph OpenAPI input, so that file is excluded until SM-5 pins the generation inputs. Other tracked files under `src/generated/` are normal reviewed runtime source and remain inside the SM-4 hash/capability boundary.

The single-file exclusion is deliberately explicit while that generated surface is exactly one known mutable file. SM-5 replaces this temporary name-keyed boundary with pinned generation inputs and deterministic generated-output evidence rather than teaching the SM-4 verifier to infer Git tracking state.

## Graph permission surface

The baseline inventories every `scopes` and `workScopes` value in `src/endpoints.json`.

The current source contains 71 distinct endpoint scopes. The policy allowlist means a newly introduced Graph permission fails CI until the policy is intentionally updated in a reviewed PR.

OAuth-layer scopes are inventoried separately by following the `Set` whose value is serialized into the OAuth `scope` query parameter; the extractor does not depend on the local variable name. The current HTTP/OAuth path implicitly adds:

- `User.Read`
- `offline_access`

This separation prevents an auth-layer permission change from hiding behind an unchanged endpoint catalog. The policy is exact for this inventory: additions and removals both require an intentional policy update, and an unexpectedly empty implicit-scope inventory fails closed.

Literal scopes added later through `Set.add('Scope')` are inventoried as well. A non-literal implicit scope value is emitted as an explicit dynamic marker, which is unapproved by default and therefore fails closed instead of disappearing from the inventory.

The approved **first production profile** remains narrower than the capabilities present in source:

```text
stdio
--org-mode
--read-only
--allowed-scopes "User.Read Mail.Read Calendars.Read Chat.Read Team.ReadBasic.All"
```

The broad source-level scope allowlist does **not** authorize those scopes for production. It only says that their presence in the codebase has been reviewed. Runtime promotion remains constrained by the production profile.

The first-production profile is intentionally represented twice: declaratively in policy and independently as a verifier invariant. This is deliberate dual control rather than accidental duplication; changing the production contract requires changing both under review. The `reason` and `productionProfileAllowed` fields on capability entries are documentary review metadata, not runtime enforcement switches.

## Network destination surface

The gate distinguishes three concepts:

- `cloudNetworkHosts`: the `authority` and `graphApi` destinations from cloud configuration; these are fail-closed policy.
- `networkUrlEnvVars`: a deliberately conservative name-pattern inventory of URL/URI/endpoint/host/origin-looking identifiers across all scanned source files. It intentionally over-includes matching property names even when the owner is not proven to be `process.env`, so helper-parameter reads cannot silently escape. Direct `process.env.X`, string element access, imported/destructured env objects, aliases/default parameters, and matching non-env owners are all visible. Computed or wholesale env access emits the explicit `<dynamic>` marker, including non-literal element reads, object/rest spread, `for-in`, `Object.*` descriptor/enumeration helpers, `JSON.stringify`, `Reflect.ownKeys`, `Reflect.get`, and `Reflect.getOwnPropertyDescriptor`. `<dynamic>` is unapproved by default and therefore fails closed.
- `staticUrlHosts`: a conservative inventory of URL literals in network-critical files, including non-destination literals such as localhost callbacks or Azure portal references. Changes are review-visible baseline drift but are not mislabeled as confirmed outbound traffic.

The current approved cloud network hosts are the Microsoft global and China login/Graph endpoints. The reviewed environment-controlled network surface currently includes `MS365_MCP_KEYVAULT_URL`, `MS365_MCP_PUBLIC_URL`, `MS365_MCP_BASE_URL`, `MS365_MCP_ALLOWED_REDIRECT_URIS`, `MS365_MCP_ATTACHMENT_URL_BASE`, `MS365_MCP_ATTACHMENT_HOST`, and `MS365_MCP_CORS_ORIGIN`. Their presence in source does not make them part of the first production profile.

Existing source intentionally avoids computed environment reads for reviewed finite key sets. `.env` import bindings and positive-integer configuration readers use `satisfies Record<...>` dispatch maps, so adding a new key without adding its corresponding binding/reader is a TypeScript error rather than a silent fallback. Regression tests also exercise every current `.env` allowlisted binding.

## Process execution, dynamic code, and dynamic imports

Any named, namespace, default, or TypeScript import-equals acquisition of `child_process` / `node:child_process` is treated as a process-execution capability. CommonJS-style `require()`, ESM `createRequire()` (named or module-namespace forms), `process.getBuiltinModule()` and aliases/destructured aliases of it, ordinary and namespace re-exports, casted/parenthesized acquisitions, and require-alias chains are inventoried too. `worker_threads` / `node:worker_threads` is treated equally conservatively: acquiring the module is itself a new execution capability and fails closed unless explicitly approved.

Current reviewed capabilities are:

- build-time `execSync` in `bin/modules/generate-mcp-tools.mjs` — to be hardened further under SM-5;
- runtime `spawn` in `src/token-cache-storage.ts` for the explicitly configured external auth-cache command.

Neither process-execution capability is part of the first production runtime profile.

Literal dynamic imports are allowlisted by file + package specifier. Non-literal dynamic imports fail unconditionally. Direct `eval` / `Function` calls and constructors, `globalThis.eval` / `globalThis.Function`, string element access on `globalThis`, comma-indirect calls, simple aliases/assignments, `.call` / `.apply` / `.bind`, `Reflect.apply` / `Reflect.construct`, and `Function.prototype.constructor` are classified as forbidden dynamic code. Any acquisition of `vm` / `node:vm` is also classified as forbidden dynamic code rather than trying to enumerate every string-evaluating VM entry point. Generic static analysis remains a backstop for more exotic indirection.

## Filesystem write surface

The snapshot records filesystem write-capability pairs by source file and callee, including Graph downloads, token-cache persistence, logging/audit files, and build-generation writes.

A new file/callee write surface fails policy until explicitly reviewed. Security-critical file hashes make semantic changes to existing write paths review-visible even when the same API call remains in place.

## PR security delta

On pull requests, the workflow compares the checked-in baseline against the base commit and writes the MCP security delta to the GitHub Step Summary.

This makes upstream sync review answer concrete questions such as:

- which tools changed metadata;
- which Graph scopes were added or removed;
- whether implicit auth scopes changed;
- whether a cloud host or URL-bearing network input appeared;
- whether process execution, filesystem writes, or dynamic imports expanded;
- which security-critical source files changed.

The baseline itself is version-controlled evidence, so the same delta is visible in the PR even without the workflow summary.

## Relationship to later milestones

SM-4 establishes source-level MCP security gates.

SM-5 pins mutable Graph OpenAPI inputs and closes deterministic generated-schema/build evidence.
SM-6 seals and attests the approved artifact.
SM-7 implements controlled upstream-sync automation.
SM-8 defines and validates the hardened macOS runtime profile.
SM-9 is final production acceptance.
