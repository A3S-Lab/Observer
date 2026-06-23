# Security Policy

a3s-observer runs **privileged** — it loads eBPF and, opt-in, attaches uprobes / fanotify — so
it sits inside the trust boundary. Please report vulnerabilities responsibly.

## Reporting

Open a **private security advisory** on the repository (Security → Advisories → *Report a
vulnerability*). Do **not** file a public issue for a vulnerability. We aim to acknowledge
within 72 hours.

## Sensitive surfaces

- **Privileged probe load.** The collector needs root / `CAP_BPF`+`CAP_PERFMON`; treat the
  binary and image as privileged components.
- **Content capture (`A3S_OBSERVER_SSL=1`).** Off by default. When on, it captures TLS
  **plaintext** (prompts/completions) via OpenSSL uprobes — sensitive data. Enable only where
  capturing that content is acceptable, and secure the NDJSON sink accordingly.
- **Enforcement (`a3s-observer-enforce` / `a3s-observer-fileguard`).** Opt-in. A bad policy can
  block legitimate egress / file access; the default is fail-open, and policies should be
  validated on a non-prod box (`scripts/validate-enforcement.sh`).

## Supply chain

Release images are pushed to GHCR, scanned (Trivy), keyless-signed (cosign / Sigstore), and
carry SLSA build provenance + an SBOM. Verify a signature:

```bash
cosign verify ghcr.io/a3s-lab/observer:<tag> \
  --certificate-identity-regexp 'https://github.com/A3S-Lab/Observer/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
