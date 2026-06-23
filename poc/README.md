# a3s-observer PoC (bpftrace)

Validates the two **language-agnostic** chains before committing to the Aya
implementation. Linux only; **read-only tracing**.

## What it proves

- `exec.bt` — every `execve` (tool / subprocess) is captured with pid / ppid / comm /
  full argv at the syscall layer → works for **any** agent runtime, no instrumentation.
- `sni.bt` — the TLS **ClientHello** is detected on the outbound `sendto`/`write`
  syscall and the **SNI hostname** (the LLM provider) is recovered from its plaintext
  bytes → provider identification with **no per-language uprobe**.

## Result (validated 2026-06-23 · kernel 6.8.0 · bpftrace 0.20.2)

EXEC:

```
EXEC pid=273698 ppid=273563 comm=bash | uname -a
EXEC pid=273699 ppid=273563 comm=bash | id
```

SNI (`curl https://api.anthropic.com`) — ClientHello detected (517 B), server_name
extension recovered from the raw bytes:

```
... \x00\x00 \x00\x16 \x00\x14 \x00 \x00\x11 api.anthropic.com ...
     ^ext     ^len   ^list   ^nt ^len=17  ^hostname
   server_name
```

## Findings → the Aya implementation

1. **User-memory reads need `uptr()`** (bpftrace) / `bpf_probe_read_user` (Aya). A plain
   `*(uint8 *)args->buf` reads *kernel* memory and silently fails the byte match — this
   cost the first two runs.
2. **bpftrace caps strings/buf at ~200 B** (512-byte BPF stack). SNI landed at ~byte 180
   here (inside 200), but a larger ClientHello (more extensions / GREASE / ECH padding
   before SNI) can exceed it. The Aya probe must stage the **full record in a per-CPU
   array / ring buffer** (no stack cap) and parse SNI in-kernel.
3. **Hook the send family.** curl used `sendto` (also `write`, `sendmmsg`). The real
   probe hooks `sendto`/`write`/`sendmsg` (or a socket-layer hook) so it can't miss the
   ClientHello.
4. **SNI parse offsets** (for Aya): record(5) + handshake(4) + version(2) + random(32) +
   session_id(1+n) + cipher_suites(2+n) + compression(1+n) + extensions(2), then walk
   extensions for type `0x0000` → `server_name`.
5. **ECH risk confirmed in principle**: SNI is plaintext today; Encrypted ClientHello
   would hide it → fall back to IP/DNS correlation.

## Run

```bash
sudo bpftrace poc/exec.bt
BPFTRACE_MAX_STRLEN=200 sudo -E bpftrace poc/sni.bt   # scope with /comm == "..."/ on shared hosts
```

(Test env note: `api.openai.com` egress was blocked; `api.anthropic.com` + the daocloud
mirror completed TLS. Any HTTPS host produces a ClientHello.)
