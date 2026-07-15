#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
let failures = 0;

function source(relative) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file)) {
    console.error(`FAIL missing ${relative}`);
    failures += 1;
    return '';
  }
  console.log(`PASS exists ${relative}`);
  return fs.readFileSync(file, 'utf8');
}

function expect(text, pattern, label) {
  if (pattern.test(text)) console.log(`PASS ${label}`);
  else {
    console.error(`FAIL ${label}: ${pattern}`);
    failures += 1;
  }
}

const workspace = source('Cargo.toml');
const ebpfManifest = source('a3s-observer-ebpf-legacy/Cargo.toml');
const ebpf = source('a3s-observer-ebpf-legacy/src/main.rs');
const ebpfC = source('a3s-observer-ebpf-legacy/src/probes.c');
const collectorManifest = source('a3s-observer-collector/Cargo.toml');
const collectorBuild = source('a3s-observer-collector/build.rs');
const collectorMain = source('a3s-observer-collector/src/main.rs');
const collectorLegacy = source('a3s-observer-collector/src/legacy.rs');
const objectVerifier = source('scripts/verify-legacy-bpf-object.mjs');
const objectVerifierTest = source('scripts/test-verify-legacy-bpf-object.mjs');
const objectBuild = source('scripts/build-legacy-bpf-object.sh');

expect(workspace, /a3s-observer-ebpf-legacy/u, 'workspace includes the legacy eBPF crate');
expect(ebpfManifest, /aya-ebpf/u, 'legacy eBPF crate uses Aya');
expect(ebpf, /PerfEventArray/u, 'legacy backend emits through perf-event arrays');
expect(ebpf, /bpf_probe_read\b/u, 'legacy backend uses the Linux 4.19 probe-read helper');
expect(ebpf, /bpf_probe_read_str\b/u, 'legacy backend uses the Linux 4.19 string helper');
expect(ebpf, /#\[kprobe\]/u, 'legacy backend uses kprobes without syscall tracepoints');
expect(ebpf, /legacy_exec/u, 'legacy backend captures process execution');
expect(ebpf, /legacy_connect/u, 'legacy backend captures outbound connections');
expect(ebpf, /legacy_openat/u, 'legacy backend captures file access');
expect(ebpf, /legacy_setuid/u, 'legacy backend captures privilege changes');
expect(ebpf, /DROPS/u, 'legacy backend exposes lost-event accounting');
expect(ebpf, /SCRATCH/u, 'legacy backend avoids oversized BPF stack events');
if (/maps::[^;]*RingBuf|RingBuf::|bpf_probe_read_user(?:_buf|_str)?\s*\(/u.test(ebpf)) {
  console.error('FAIL legacy implementation references a RingBuf or post-4.19 user-read helper');
  failures += 1;
} else console.log('PASS legacy implementation avoids RingBuf and post-4.19 user-read helpers');
expect(ebpfC, /SEC\("kprobe"\)/u, 'Linux 4.19 probes use legacy kprobe ELF sections');
expect(ebpfC, /READ_EXEC_ARG\(11\)/u, 'exec argument capture is explicitly unrolled');
expect(ebpfC, /bpf_probe_read_str/u, 'C probes use the Linux 4.19 string helper');
expect(objectBuild, /-target bpfel/u, 'legacy object build selects little-endian BPF');
expect(objectBuild, /-mcpu=v1/u, 'legacy object build limits instructions to the Linux 4.19 BPF ISA');
expect(objectBuild, /-g0/u, 'legacy object build disables BTF-producing debug data');
expect(objectBuild, /verify-legacy-bpf-object\.mjs/u, 'legacy object build enforces object validation');

expect(collectorManifest, /legacy-kernel-4-19/u, 'collector exposes a legacy build feature');
expect(collectorBuild, /a3s-observer-ebpf-legacy/u, 'collector build embeds the legacy object');
expect(collectorBuild, /A3S_LEGACY_BPF_OBJECT/u, 'legacy collector consumes a verified external BPF object');
expect(collectorMain, /cfg\(feature = "legacy-kernel-4-19"\)/u, 'collector selects legacy runtime by build feature');
expect(collectorLegacy, /AsyncPerfEventArray/u, 'legacy userspace consumes per-CPU perf buffers');
expect(collectorLegacy, /__arm64_sys_execve/u, 'legacy collector tries the ARM64 exec syscall symbol');
expect(collectorLegacy, /__arm64_sys_connect/u, 'legacy collector tries the ARM64 connect syscall symbol');
expect(collectorLegacy, /perf-kprobe-legacy/u, 'legacy heartbeat identifies its backend');
expect(collectorLegacy, /effective_probes/u, 'legacy collector distinguishes effective probes');
expect(collectorLegacy, /no effective legacy probes/u, 'legacy collector fails instead of reporting blind health');
expect(objectVerifier, /expected EM_BPF object/u, 'legacy object verifier requires the BPF ELF machine');
expect(objectVerifier, /forbidden BTF section/u, 'legacy object verifier rejects kernel-incompatible BTF');
expect(objectVerifier, /backward jump/u, 'legacy object verifier rejects pre-5.3 loop instructions');
expect(objectVerifier, /JMP32 instruction unavailable on Linux 4\.19/u, 'legacy object verifier rejects post-4.19 JMP32 instructions');
expect(objectVerifierTest, /rejects BTF sections/u, 'legacy object verifier has a BTF regression test');
expect(objectVerifierTest, /rejects backward jumps/u, 'legacy object verifier has a loop regression test');
expect(objectVerifierTest, /rejects JMP32 instructions unavailable on Linux 4\.19/u, 'legacy object verifier has an ISA regression test');

if (failures) {
  console.error(`Legacy Observer verification failed with ${failures} issue(s)`);
  process.exit(1);
}
console.log('Legacy Observer verification passed');
