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
pub mod policy;
pub mod semantic;
pub mod traits;
pub mod workload;

pub use model::{
    AgentEvent, AgentPlaintextEvidence, CollectorCaptureProbeStats, CollectorCaptureProfileStats,
    CollectorFileFilterStats, CollectorIngressAccounting, CollectorInteractionReassemblyStats,
    CollectorPipelineAccounting, CollectorPipelineUnit, CollectorPipelineWindow,
    CollectorRingAccounting, ConnectionIdentity, CoverageGap, EnrichedEvent, EventCaptureDecision,
    EventTiming, LlmConversationAnchor, LlmInteraction, LlmInteractionContent,
    LlmInteractionMessage, LlmInteractionSemanticItem, LlmInteractionToolCall,
    LlmInteractionToolResult, LlmTokenUsage, ProcessContext, ProcessGenerationKey, RawObservation,
    RawObservationCaptureDecision, RawObservationPayload, RawObservationRuntime,
    RawObservationSource, SourceRef, COVERAGE_GAP_SCHEMA_V1, RAW_OBSERVATION_SCHEMA_V1,
};
pub use policy::{parse_egress_policy, AllowAll, Policy, ProviderPolicy, Verdict};
pub use semantic::{
    AdapterManifest, AgentAdapter, DefaultAgentAdapter, DefaultLlmFormatAdapter,
    DefaultRuntimeAdapter, HttpTransportManifest, IdentityHint, LlmFormatAdapter, Registry,
    RegistryMatch, RuntimeAdapter, RuntimeContext, ToolHint, TransportDecoder,
    ADAPTER_MANIFEST_SCHEMA_V1, LLM_FORMAT_MANIFEST_SCHEMA_V1, RUNTIME_MANIFEST_SCHEMA_V1,
    TRANSPORT_MANIFEST_SCHEMA_V1,
};
pub use traits::{
    read_ppid, ExportOutcome, ExportPriority, Exporter, Identity, IdentityResolver, JsonExporter,
    KubeResolver, LogExporter, ProcResolver, Provider, ServiceClassifier, SniClassifier,
};
pub use workload::{
    Freshness, ObservationMetadata, ObservationMetadataError, WorkloadIdentity,
    WorkloadIdentityValue, WorkloadIdentityValueError, MAX_WORKLOAD_IDENTITY_VALUE_LEN,
};
