# Changelog

All notable changes to a3s-observer will be documented in this file.

## [Unreleased]

### Added

- Initial project skeleton: stable extension contracts (`IdentityResolver`,
  `ServiceClassifier`, `Exporter`), the telemetry data model (`AgentEvent`,
  `EnrichedEvent`), and the design (see README). The eBPF probe set (Aya) is next.
- bpftrace PoC (`poc/`) validating the two language-agnostic chains on a live kernel
  (6.8, bpftrace 0.20.2): `execve`→tool capture, and TLS-ClientHello→SNI provider id
  (recovered `api.anthropic.com`, no uprobe). Findings documented for the Aya impl.
