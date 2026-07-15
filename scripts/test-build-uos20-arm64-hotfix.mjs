#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const builderPath = path.join(root, 'scripts/build-uos20-arm64-hotfix.sh');
const builder = fs.existsSync(builderPath) ? fs.readFileSync(builderPath, 'utf8') : '';
const smokePath = path.join(root, 'scripts/run-target-hotfix3-smoke.sh');
const smoke = fs.existsSync(smokePath) ? fs.readFileSync(smokePath, 'utf8') : '';

test('hotfix builder targets the UOS 20 ABI', () => {
  assert.match(builder, /aarch64-unknown-linux-gnu\.2\.28/);
  assert.match(builder, /TARGET_PAGE_SIZE=65536/);
  assert.match(builder, /MAX_GLIBC=GLIBC_2\.28/);
  assert.match(builder, /hotfix3/);
  assert.match(builder, /kernel_version_code=0x0004135a/);
  assert.match(builder, /kernel_version=4\.19\.90/);
});

test('hotfix builder embeds only a verified legacy object', () => {
  assert.match(builder, /build-legacy-bpf-object\.sh/);
  assert.match(builder, /A3S_LEGACY_BPF_OBJECT/);
  assert.match(builder, /legacy-kernel-4-19/);
  assert.match(builder, /bpf_isa=v1/);
});

test('hotfix builder emits checksums and provenance', () => {
  assert.match(builder, /SHA256SUMS/);
  assert.match(builder, /PROVENANCE/);
  assert.match(builder, /linux-4\.19-hotfix-target-install\.md/);
  assert.match(builder, /a3s-observer-collector PROVENANCE TARGET_INSTALL\.md/);
  assert.match(builder, /git[^\n]*rev-parse HEAD/);
  assert.match(builder, /a3s-observer-collector --version/);
  assert.match(builder, /grep -aFq 'backend=perf-kprobe-legacy'/);
});

test('target smoke script is self-contained and non-installing', () => {
  assert.match(smoke, /BASH_SOURCE/);
  assert.match(smoke, /A3S_OBSERVER_HEARTBEAT/);
  assert.match(smoke, /legacy Observer probes attached/);
  assert.match(smoke, /BPF_PROG_LOAD/);
  assert.match(smoke, /systemctl stop anysentry-observer\.service/);
  assert.match(smoke, /trap cleanup EXIT/);
  assert.doesNotMatch(smoke, /\/opt\/anysentry\/observer\/bin/);
});

test('hotfix package includes the target smoke script in checksums', () => {
  assert.match(builder, /run-target-hotfix3-smoke\.sh/);
  assert.match(builder, /RUN_TARGET_SMOKE\.sh/);
  assert.match(builder, /TARGET_INSTALL\.md RUN_TARGET_SMOKE\.sh/);
  assert.match(builder, /chmod 0644 "\$OUTPUT_DIR\/PROVENANCE" "\$OUTPUT_DIR\/SHA256SUMS"/);
});
