#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const scripts = path.dirname(fileURLToPath(import.meta.url));
const validator = path.join(scripts, 'verify-legacy-bpf-object.mjs');
const programs = [
  'legacy_exec', 'legacy_exit', 'legacy_connect', 'legacy_setuid',
  'legacy_ptrace', 'legacy_bind', 'legacy_openat', 'legacy_unlinkat',
];
const maps = [
  'EVENTS', 'EXIT_EVENTS', 'CONNECT_EVENTS', 'FILE_EVENTS', 'SEC_EVENTS',
  'EXEC_SCRATCH', 'EXIT_SCRATCH', 'CONNECT_SCRATCH', 'FILE_SCRATCH',
  'SEC_SCRATCH', 'DROPS',
];

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function strings(names) {
  const offsets = new Map();
  const chunks = [Buffer.from([0])];
  let offset = 1;
  for (const name of names) {
    offsets.set(name, offset);
    const chunk = Buffer.from(`${name}\0`);
    chunks.push(chunk);
    offset += chunk.length;
  }
  return { data: Buffer.concat(chunks), offsets };
}

function symbol(nameOffset, info, section, value, size) {
  const entry = Buffer.alloc(24);
  entry.writeUInt32LE(nameOffset, 0);
  entry.writeUInt8(info, 4);
  entry.writeUInt16LE(section, 6);
  entry.writeBigUInt64LE(BigInt(value), 8);
  entry.writeBigUInt64LE(BigInt(size), 16);
  return entry;
}

function fixture({ btf = false, backwardJump = false, missingSymbol = false } = {}) {
  const keptMaps = missingSymbol ? maps.slice(0, -1) : maps;
  const symbolNames = [...programs, ...keptMaps];
  const strtab = strings(symbolNames);
  const code = Buffer.alloc(8);
  if (backwardJump) {
    code.writeUInt8(0x05, 0); // BPF_JMP | BPF_JA
    code.writeInt16LE(-1, 2);
  } else {
    code.writeUInt8(0x95, 0); // BPF_JMP | BPF_EXIT
  }
  const mapData = Buffer.alloc(maps.length * 20);
  const sections = [
    { name: '', type: 0, flags: 0, align: 0, data: Buffer.alloc(0) },
    { name: 'kprobe', type: 1, flags: 6, align: 8, data: code },
    { name: 'maps', type: 1, flags: 3, align: 8, data: mapData },
  ];
  if (btf) sections.push({ name: '.BTF', type: 1, flags: 0, align: 4, data: Buffer.from('btf') });
  const strtabIndex = sections.length;
  sections.push({ name: '.strtab', type: 3, flags: 0, align: 1, data: strtab.data });
  const symtabIndex = sections.length;
  const symbols = [Buffer.alloc(24)];
  for (const name of programs) {
    symbols.push(symbol(strtab.offsets.get(name), 0x12, 1, 0, 8));
  }
  keptMaps.forEach((name, index) => {
    symbols.push(symbol(strtab.offsets.get(name), 0x11, 2, index * 20, 20));
  });
  sections.push({
    name: '.symtab', type: 2, flags: 0, align: 8, data: Buffer.concat(symbols),
    link: strtabIndex, info: 1, entsize: 24,
  });
  const shstrtabIndex = sections.length;
  const shstrtab = strings([...sections.map((section) => section.name).filter(Boolean), '.shstrtab']);
  sections.push({ name: '.shstrtab', type: 3, flags: 0, align: 1, data: shstrtab.data });

  let cursor = 64;
  for (const section of sections.slice(1)) {
    cursor = align(cursor, section.align || 1);
    section.offset = cursor;
    cursor += section.data.length;
  }
  const sectionOffset = align(cursor, 8);
  const output = Buffer.alloc(sectionOffset + sections.length * 64);
  output.set(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]), 0);
  output.writeUInt16LE(1, 16); // ET_REL
  output.writeUInt16LE(247, 18); // EM_BPF
  output.writeUInt32LE(1, 20);
  output.writeBigUInt64LE(BigInt(sectionOffset), 40);
  output.writeUInt16LE(64, 52);
  output.writeUInt16LE(64, 58);
  output.writeUInt16LE(sections.length, 60);
  output.writeUInt16LE(shstrtabIndex, 62);

  sections.slice(1).forEach((section) => section.data.copy(output, section.offset));
  sections.forEach((section, index) => {
    const header = sectionOffset + index * 64;
    output.writeUInt32LE(section.name ? shstrtab.offsets.get(section.name) : 0, header);
    output.writeUInt32LE(section.type, header + 4);
    output.writeBigUInt64LE(BigInt(section.flags), header + 8);
    output.writeBigUInt64LE(BigInt(section.offset || 0), header + 24);
    output.writeBigUInt64LE(BigInt(section.data.length), header + 32);
    output.writeUInt32LE(section.link || 0, header + 40);
    output.writeUInt32LE(section.info || 0, header + 44);
    output.writeBigUInt64LE(BigInt(section.align || 0), header + 48);
    output.writeBigUInt64LE(BigInt(section.entsize || 0), header + 56);
  });
  return output;
}

function verify(object) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'legacy-bpf-object-'));
  const objectPath = path.join(directory, 'probes.o');
  fs.writeFileSync(objectPath, object);
  const result = spawnSync(process.execPath, [validator, objectPath], { encoding: 'utf8' });
  fs.rmSync(directory, { recursive: true, force: true });
  return result;
}

test('accepts a Linux 4.19 compatible legacy object', () => {
  const result = verify(fixture());
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Legacy BPF object verification passed/);
});

test('rejects BTF sections', () => {
  const result = verify(fixture({ btf: true }));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /forbidden BTF section \.BTF/);
});

test('rejects backward jumps', () => {
  const result = verify(fixture({ backwardJump: true }));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /backward jump/);
});

test('rejects missing required symbols', () => {
  const result = verify(fixture({ missingSymbol: true }));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing required symbol DROPS/);
});
