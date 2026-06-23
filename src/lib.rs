//! `a3s-observer` — general-purpose, language-agnostic eBPF observability for AI agents.
//!
//! Turns kernel-level events (syscalls, socket flows, TLS SNI) into semantic agent
//! telemetry — which agent made which LLM call (provider, latency, bytes), ran which
//! tools, touched which files, reached which endpoints — with **zero changes to the
//! agent**, across languages.
//!
//! v1 uses only language-agnostic kernel hooks (no per-language uprobes), so it works on
//! any agent runtime. Trade-off: no LLM prompt / model / exact-token visibility — that
//! needs an opt-in TLS-payload extension. See the README for the full design.
//!
//! This crate defines the stable contracts ([`IdentityResolver`], [`ServiceClassifier`],
//! [`Exporter`]) and the data [`model`]; the eBPF probes live in `a3s-observer-ebpf` and
//! the collector that loads them in `a3s-observer-collector`.

pub mod model;
pub mod traits;

pub use model::{AgentEvent, EnrichedEvent};
pub use traits::{
    read_ppid, Exporter, Identity, IdentityResolver, JsonExporter, KubeResolver, LogExporter,
    ProcResolver, Provider, ServiceClassifier, SniClassifier,
};
