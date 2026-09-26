#!/usr/bin/env node

import { readFileSync } from 'node:fs';

const reportPath = process.argv[2];
if (!reportPath) {
  console.error('usage: verify-npm-audit.mjs <npm-audit.json>');
  process.exit(2);
}

const policy = JSON.parse(readFileSync('downstream/supply-chain-policy.json', 'utf8'));
const report = JSON.parse(readFileSync(reportPath, 'utf8'));

if (report.error) {
  console.error('npm audit returned an error payload:', report.error);
  process.exit(1);
}

const vulnerabilities = report.vulnerabilities ?? {};
const allowed = policy.acceptedVulnerabilities ?? [];
const failures = [];
const seen = new Set();

for (const [packageName, finding] of Object.entries(vulnerabilities)) {
  const allowedForPackage = allowed.filter((item) => item.package === packageName);
  if (!allowedForPackage.length) {
    failures.push(`unapproved vulnerable package: ${packageName} (${finding.severity})`);
    continue;
  }

  const directAdvisories = (finding.via ?? []).filter((item) => typeof item === 'object');
  if (!directAdvisories.length) {
    failures.push(`${packageName} has no directly attributable advisory in npm audit output`);
    continue;
  }

  for (const advisory of directAdvisories) {
    const id = advisory.url?.split('/').pop();
    const match = allowedForPackage.find(
      (item) => item.advisory === id && item.url === advisory.url
    );

    if (!match) {
      failures.push(
        `unapproved advisory for ${packageName}: ${id ?? advisory.source ?? 'unknown'}`
      );
      continue;
    }

    if (match.severity !== advisory.severity) {
      failures.push(
        `${packageName} ${match.advisory} severity changed from ` +
          `${match.severity} to ${advisory.severity}`
      );
      continue;
    }

    seen.add(`${packageName}:${match.advisory}`);
  }
}

for (const item of allowed) {
  const key = `${item.package}:${item.advisory}`;
  if (!seen.has(key)) {
    failures.push(`accepted vulnerability is stale or missing from audit output: ${key}`);
  }
}

if (failures.length) {
  console.error('npm audit policy FAILED:');
  for (const message of failures) console.error(`- ${message}`);
  process.exit(1);
}

console.log('npm audit policy PASS');
for (const item of allowed) {
  console.log(
    `accepted exception: ${item.package} ${item.advisory} (${item.severity}, ${item.scope})`
  );
}
