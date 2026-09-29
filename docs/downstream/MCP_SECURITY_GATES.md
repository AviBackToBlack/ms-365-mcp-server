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
- SHA-256 for every reviewed code file under `src/`, `bin/`, and `scripts/`, plus `src/endpoints.json`. Test/spec-named source files remain in this hash boundary even though they are omitted from capability scanning. The only code exclusion is mutable, untracked `src/generated/client.ts`; tracked runtime siblings such as `client-beta.ts`, `endpoint-types.ts`, and `hack.ts` are hashed and capability-scanned.

A description, scope, path, method, request-body override, `llmTip`, preset, or other tracked endpoint metadata therefore changes the affected tool fingerprint. CI reports that tool key in the security delta.

The source walker includes `.ts`, `.mts`, `.cts`, `.js`, `.mjs`, and `.cjs` files. Capability scanning excludes files named `*.test.*` or `*.spec.*`, not directories named `__tests__`; critical-file hashing is broader and still includes those test/spec-named files. A normal runtime/source filename placed under `__tests__/` therefore remains inside both the hash and capability boundary, while even a misleadingly named runtime-imported `x.test.ts` remains review-visible through its SHA-256.

The MCP verifier itself is inside the capability scan as well as the critical-file hash surface. Its existing `writeFileSync` use for baseline/step-summary output is an explicit approved filesystem-write capability; adding execution, dynamic code, or network-style environment access to the verifier would therefore require policy review like any other source file.

Complete generated parameter-schema fingerprinting is intentionally marked `deferred-to-SM-5`. Specifically, mutable `src/generated/client.ts` is untracked and currently produced from live Microsoft Graph OpenAPI input, so that file is excluded until SM-5 pins the generation inputs. Other tracked files under `src/generated/` are normal reviewed runtime source and remain inside the SM-4 hash/capability boundary.

The single-file exclusion is deliberately explicit while that generated surface is exactly one known mutable file. SM-5 replaces this temporary name-keyed boundary with pinned generation inputs and deterministic generated-output evidence rather than teaching the SM-4 verifier to infer Git tracking state.

## Graph permission surface

The baseline inventories every `scopes` and `workScopes` value in `src/endpoints.json`.

The current source contains 71 distinct endpoint scopes. The policy allowlist means a newly introduced Graph permission fails CI until the policy is intentionally updated in a reviewed PR.

OAuth-layer scopes are inventoried separately at the OAuth `scope` serialization sinks; the extractor does not depend on the local `Set` variable name or on `Array.from(...)` as the only serialization spelling. The current HTTP/OAuth path implicitly adds:

- `User.Read`
- `offline_access`

The runtime-provided base collection that is passed through that sink is tracked independently as an exact passthrough source (`baseScopes`). Replacing it or adding another spread/passthrough source changes `implicitAuthScopePassthroughs` and fails policy validation until explicitly reviewed. This keeps the runtime-selected base scopes distinct from literals that the auth layer itself adds while still making passthrough drift visible.

The extractor also recognizes direct literal scope strings, spread-array serialization, `Array.from(...)`, `.concat(...)`, both `set('scope', ...)` and `append('scope', ...)`, and object-form `new URLSearchParams({ scope: ... })`. Literal scopes added later through `Set.add('Scope')` are inventoried as well. Any unrecognized sink value or non-literal added value is emitted as an explicit dynamic marker. Dynamic implicit-scope markers are reserved and cannot be policy-approved, so unsupported serialization fails closed instead of disappearing from the inventory.

This separation prevents an auth-layer permission change from hiding behind an unchanged endpoint catalog. The policy is exact for both the implicit-scope inventory and its passthrough sources: additions and removals require an intentional policy update, and an unexpectedly empty implicit-scope inventory fails closed.

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
- `networkUrlEnvVars`: a deliberately conservative name-pattern inventory of URL/URI/endpoint/host/origin-looking identifiers across all scanned source files. It intentionally over-includes matching property names even when the owner is not proven to be `process.env`, so helper-parameter reads cannot silently escape. Direct `process.env.X`, string element access, imported/destructured env objects, common aliases/default parameters, and matching non-env owners are visible. Computed or wholesale env access emits the explicit `<dynamic>` marker, including non-literal element reads, object/rest spread, `for-in`, `Object.*` descriptor/enumeration helpers, `JSON.stringify`, `structuredClone`, `Reflect.ownKeys`, `Reflect.get`, and `Reflect.getOwnPropertyDescriptor`; equivalent `globalThis`/`global` builtin spellings are normalized too. `<dynamic>` is unapproved by default and therefore fails closed. More exotic renamed env-object dataflow remains in the documented whole-program-analysis boundary rather than being claimed as exhaustively modeled here.
- `staticUrlHosts`: a conservative inventory of URL literals in network-critical files, including non-destination literals such as localhost callbacks or Azure portal references. Changes are review-visible baseline drift but are not mislabeled as confirmed outbound traffic.

The current approved cloud network hosts are the Microsoft global and China login/Graph endpoints. The reviewed environment-controlled network surface currently includes `MS365_MCP_KEYVAULT_URL`, `MS365_MCP_PUBLIC_URL`, `MS365_MCP_BASE_URL`, `MS365_MCP_ALLOWED_REDIRECT_URIS`, `MS365_MCP_ATTACHMENT_URL_BASE`, `MS365_MCP_ATTACHMENT_HOST`, and `MS365_MCP_CORS_ORIGIN`. Their presence in source does not make them part of the first production profile.

Existing source intentionally avoids computed environment reads for reviewed finite key sets. `.env` import bindings and positive-integer configuration readers use `satisfies Record<...>` dispatch maps, so adding a new key without adding its corresponding binding/reader is a TypeScript error rather than a silent fallback. Regression tests also exercise every current `.env` allowlisted binding.

## Process execution, dynamic code, and dynamic imports

Any named, namespace, default, or TypeScript import-equals acquisition of `child_process` / `node:child_process` is treated as a process-execution capability. CommonJS-style `require()`, ESM `createRequire()` (named, module-namespace, or `require('node:module').createRequire` forms), `process.getBuiltinModule()` and aliases/destructured aliases of it, including process objects acquired via `require('process')` / `require('node:process')`, ordinary and namespace re-exports, casted/parenthesized acquisitions, require-alias chains, comma-indirect calls, `.call`/`.apply`, and `Reflect.apply` are inventoried too. `worker_threads` / `node:worker_threads` is treated equally conservatively: acquiring the module is itself a new execution capability and fails closed unless explicitly approved. Require-like acquisition with a non-literal module specifier is recorded separately and fails unconditionally; it is not policy-approvable. This keeps computed `require(name)`, `createRequire(...)(name)`, `getBuiltinModule(name)`, and non-literal TypeScript import-equals acquisitions from bypassing module-specific process, filesystem, or `vm` classification.

Current reviewed capabilities are:

- build-time `execSync` in `bin/modules/generate-mcp-tools.mjs` — to be hardened further under SM-5;
- runtime `spawn` in `src/token-cache-storage.ts` for the explicitly configured external auth-cache command.

Neither process-execution capability is part of the first production runtime profile.

Literal dynamic imports are allowlisted by file + package specifier. Non-literal dynamic imports and non-literal require-like module acquisitions fail unconditionally. Direct `eval` / `Function` calls and constructors, `globalThis.eval` / `globalThis.Function`, string element access on `globalThis`, comma-indirect calls, simple aliases/assignments, `.call` / `.apply` / `.bind`, `Reflect.apply` / `Reflect.construct`, and `Function.prototype.constructor` are classified as forbidden dynamic code. Any literal acquisition of `vm` / `node:vm` is classified as forbidden dynamic code rather than trying to enumerate every string-evaluating VM entry point; computed acquisition is rejected even earlier by the non-literal-module rule. Generic static analysis remains a backstop for more exotic indirection.

## Filesystem write surface

The snapshot records filesystem write-capability pairs by source file and callee, including Graph downloads, token-cache persistence, logging/audit files, and build-generation writes. The reviewed mutation vocabulary includes file/directory creation and deletion, copy/link/symlink/rename, truncate/write/writev/write-file/append, ownership/mode/time mutation, descriptor flush/write operations, and write-stream construction. Namespace/default/require/getBuiltinModule acquisitions, `fs.promises` / `fs['promises']`, dot or string-element write calls, destructured write bindings, local aliases, bare `new WriteStream()`, `.call`/`.apply`, and `Reflect.apply` / `Reflect.construct` of reviewed write callees are normalized into the same capability inventory. A non-literal `fs[k]()` call emits a reserved `<dynamic>` write marker and fails closed. The current source contains one explicit hard-link publication step (`src/token-cache-storage.ts|linkSync`), which is policy-approved rather than hidden behind another write.

A new file/callee write surface fails policy until explicitly reviewed. Security-critical file hashes make semantic changes to existing write paths review-visible even when the same API call remains in place. SM-4 deliberately stops short of whole-program taint analysis: more exotic rebinding/dataflow remains covered by the critical-file hash delta plus CodeQL/Semgrep review rather than being claimed as exhaustively modeled by this custom AST inventory.

Reserved fail-closed sentinels are not valid approvals: policy validation rejects `<dynamic>` in the network-env allowlist and rejects `*` / `<dynamic>` filesystem-write approvals. This prevents a future policy edit from accidentally neutralizing the detector.

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
