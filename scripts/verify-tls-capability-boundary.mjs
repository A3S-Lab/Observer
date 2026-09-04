#!/usr/bin/env node

/**
 * Verify that the embedded Observer TLS registries keep the generic/version boundary explicit.
 * This is deliberately dependency-free so it can run in a clean checkout before Cargo builds.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const familyPath = resolve(root, 'a3s-observer-collector/src/tls-signature-families.json');
const hintPath = resolve(root, 'a3s-observer-collector/src/tls-runtime-selection-hints.json');

const family = JSON.parse(readFileSync(familyPath, 'utf8'));
const hints = JSON.parse(readFileSync(hintPath, 'utf8'));

const fail = (message) => {
  throw new Error(message);
};
const assert = (condition, message) => {
  if (!condition) fail(message);
};

assert(family.schemaVersion === 'anysentry.tls_signature_families.v2', 'unexpected TLS family schema');
assert(family.versionPolicy === 'implementation-family', 'TLS family registry must be implementation-family scoped');
assert(family.extensionPolicy === 'explicit-capability-registry', 'TLS family extension policy must be explicit');
assert(Array.isArray(family.families) && family.families.length > 0, 'TLS family registry is empty');

const forbidden = new Set([
  'product',
  'version',
  'versionRange',
  'minVersion',
  'maxVersion',
  'fileSize',
  'head64kSha256',
  'wholeFileSha256',
  'capabilityExtension',
]);
const knownAbi = new Set(['classic', 'openssl_ex', 'rustls_payload', 'rustls_outbound_chunks']);
const familyIds = new Set();
for (const entry of family.families) {
  assert(typeof entry.implementationFamily === 'string' && entry.implementationFamily.length > 0, 'family id missing');
  assert(!familyIds.has(entry.implementationFamily), `duplicate family ${entry.implementationFamily}`);
  familyIds.add(entry.implementationFamily);
  for (const key of forbidden) assert(!(key in entry), `version/product selector ${key} leaked into base registry`);
  assert(knownAbi.has(entry.readAbi) && knownAbi.has(entry.writeAbi), `unknown ABI in ${entry.implementationFamily}`);
  assert(Array.isArray(entry.writeAfterReadOffsets) && entry.writeAfterReadOffsets.length > 0, `missing relation in ${entry.implementationFamily}`);
}

assert(hints.schemaVersion === 'anysentry.tls_runtime_selection_hints.v1', 'unexpected runtime hint schema');
assert(hints.purpose === 'discovery-hint-only', 'runtime hints cannot authorize capture');
assert(hints.versionPolicy === 'implementation-family', 'runtime hints must not be version scoped');
assert(Array.isArray(hints.hints) && hints.hints.length > 0, 'runtime hint catalogue is empty');
const hintIds = new Set();
for (const hint of hints.hints) {
  assert(typeof hint.id === 'string' && /^[a-z0-9-]{1,128}$/.test(hint.id), `invalid runtime hint id ${hint.id}`);
  assert(!hintIds.has(hint.id), `duplicate runtime hint ${hint.id}`);
  hintIds.add(hint.id);
  assert(hint.role === 'agent_root', `runtime hint ${hint.id} may only select agent roots`);
  for (const key of forbidden) assert(!(key in hint), `version/product selector ${key} leaked into runtime hints`);
  assert(Array.isArray(hint.patterns) && hint.patterns.length > 0, `runtime hint ${hint.id} has no patterns`);
}

console.log(JSON.stringify({
  status: 'pass',
  familyCount: family.families.length,
  runtimeHintCount: hints.hints.length,
  versionPolicy: family.versionPolicy,
  extensionPolicy: family.extensionPolicy,
}));
