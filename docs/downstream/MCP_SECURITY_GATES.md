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

and review the resulting JSON diff. A capability expansion may also require an explicit policy change; changing only the baseline is not enough for scopes, cloud network hosts, URL-bearing network environment variables, process execution, filesystem writes, or dynamic imports.

## Tool and instruction drift

The baseline contains:

- SHA-256 for `src/mcp-instructions.ts`;
- SHA-256 for `src/endpoints.json`;
- one stable fingerprint per Graph tool, keyed by tool name + HTTP method + path;
- endpoint count and the complete write-capable tool-name set;
- SHA-256 for security-critical auth, network, logging, CLI, server, and token-cache source files.

A description, scope, path, method, request-body override, `llmTip`, preset, or other tracked endpoint metadata therefore changes the affected tool fingerprint. CI reports that tool key in the security delta.

Complete generated parameter-schema fingerprinting is intentionally marked `deferred-to-SM-5`. The generated Graph client is not tracked and is currently produced from mutable live Microsoft Graph OpenAPI input. Pretending that schema output is deterministic before those inputs are pinned would create false assurance.

## Graph permission surface

The baseline inventories every `scopes` and `workScopes` value in `src/endpoints.json`.

The current source contains 71 distinct endpoint scopes. The policy allowlist means a newly introduced Graph permission fails CI until the policy is intentionally updated in a reviewed PR.

OAuth-layer scopes are inventoried separately. The current HTTP/OAuth path implicitly adds:

- `User.Read`
- `offline_access`

This separation prevents an auth-layer permission change from hiding behind an unchanged endpoint catalog.

The approved **first production profile** remains narrower than the capabilities present in source:

```text
stdio
--org-mode
--read-only
--allowed-scopes "User.Read Mail.Read Calendars.Read Chat.Read Team.ReadBasic.All"
```

The broad source-level scope allowlist does **not** authorize those scopes for production. It only says that their presence in the codebase has been reviewed. Runtime promotion remains constrained by the production profile.

## Network destination surface

The gate distinguishes three concepts:

- `cloudNetworkHosts`: the `authority` and `graphApi` destinations from cloud configuration; these are fail-closed policy.
- `networkUrlEnvVars`: URL-bearing environment inputs in network-critical code; new ones are fail-closed policy.
- `staticUrlHosts`: a conservative inventory of URL literals in network-critical files, including non-destination literals such as localhost callbacks or Azure portal references. Changes are review-visible baseline drift but are not mislabeled as confirmed outbound traffic.

The current approved cloud network hosts are the Microsoft global and China login/Graph endpoints. The current dynamic URL input is `MS365_MCP_KEYVAULT_URL`, which is not part of the first production profile.

## Process execution, dynamic code, and dynamic imports

Any import of `child_process` / `node:child_process` is treated as a process-execution capability even when the imported function is dependency-injected or aliased.

Current reviewed capabilities are:

- build-time `execSync` in `bin/modules/generate-mcp-tools.mjs` — to be hardened further under SM-5;
- runtime `spawn` in `src/token-cache-storage.ts` for the explicitly configured external auth-cache command.

Neither process-execution capability is part of the first production runtime profile.

Literal dynamic imports are allowlisted by file + package specifier. Non-literal dynamic imports, `eval`, and `new Function` fail unconditionally.

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
