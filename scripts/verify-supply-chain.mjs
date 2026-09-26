#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const policyPath = 'downstream/supply-chain-policy.json';
const policy = JSON.parse(readFileSync(policyPath, 'utf8'));
const lockBytes = readFileSync(policy.lockfile.path);
const lock = JSON.parse(lockBytes.toString('utf8'));
const failures = [];

const fail = (message) => failures.push(message);
const lockSha256 = createHash('sha256').update(lockBytes).digest('hex');

const expectedNodeVersion = `v${policy.verificationToolchain.nodeVersion}`;
if (process.version !== expectedNodeVersion) {
  fail(`Node version ${process.version} != approved ${expectedNodeVersion}`);
}

if (lock.lockfileVersion !== policy.lockfile.lockfileVersion) {
  fail(`lockfileVersion ${lock.lockfileVersion} != expected ${policy.lockfile.lockfileVersion}`);
}
if (lockSha256 !== policy.lockfile.sha256) {
  fail(`package-lock SHA-256 ${lockSha256} != approved ${policy.lockfile.sha256}`);
}

const packages = Object.entries(lock.packages ?? {}).filter(
  ([path, entry]) => path && entry && !entry.link
);

if (packages.length !== policy.lockfile.packageCount) {
  fail(`package count ${packages.length} != approved ${policy.lockfile.packageCount}`);
}

const installScripts = [];
let resolvedCount = 0;
let bundledCount = 0;

for (const [path, entry] of packages) {
  if (entry.resolved) {
    resolvedCount += 1;
    if (!entry.resolved.startsWith(policy.lockfile.registryPrefix)) {
      fail(`${path} resolves outside approved registry: ${entry.resolved}`);
    }
    const expectedPrefix = `${policy.lockfile.integrityAlgorithm}-`;
    if (!entry.integrity?.startsWith(expectedPrefix)) {
      fail(`${path} does not have ${policy.lockfile.integrityAlgorithm} integrity`);
    }
  } else if (entry.inBundle) {
    bundledCount += 1;
  } else {
    fail(`${path} has neither a registry resolution nor inBundle=true`);
  }

  if (entry.hasInstallScript) {
    installScripts.push({
      path,
      name: path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length),
      version: entry.version,
      dev: Boolean(entry.dev),
      optional: Boolean(entry.optional),
    });
  }
}

const canonical = (value) =>
  JSON.stringify([...value].sort((a, b) => a.path.localeCompare(b.path)));
const approvedScripts = policy.allowedInstallScripts.map(
  ({ path, name, version, dev, optional }) => ({ path, name, version, dev, optional })
);

if (canonical(installScripts) !== canonical(approvedScripts)) {
  fail(
    'install-script package surface changed\n' +
      `actual:   ${JSON.stringify(installScripts, null, 2)}\n` +
      `approved: ${JSON.stringify(approvedScripts, null, 2)}`
  );
}

const npmEntry = lock.packages?.[policy.verificationToolchain.npmLockPath];
if (!npmEntry) {
  fail(`verification npm package missing at ${policy.verificationToolchain.npmLockPath}`);
} else if (npmEntry.version !== policy.verificationToolchain.npmVersion) {
  fail(
    `verification npm version ${npmEntry.version} != approved ` +
      policy.verificationToolchain.npmVersion
  );
}

if (failures.length) {
  console.error('Supply-chain baseline verification FAILED:');
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log('Supply-chain baseline verification PASS');
console.log(`package-lock SHA-256: ${lockSha256}`);
console.log(`packages: ${packages.length} (registry: ${resolvedCount}, bundled: ${bundledCount})`);
console.log(`approved install-script packages: ${installScripts.length}`);
console.log(`verification npm: ${npmEntry.version}`);
