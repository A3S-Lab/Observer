//! Orthogonal semantic extension points shared by the Observer collector and downstream
//! consumers.  Transport framing, LLM wire formats, and product-specific Agent hints are
//! intentionally separate registries: adding a product must not require changing HTTP framing,
//! and adding a provider format must not create a product branch.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub const ADAPTER_MANIFEST_SCHEMA_V1: &str = "anysentry.agent_adapter.v1";
pub const TRANSPORT_MANIFEST_SCHEMA_V1: &str = "anysentry.transport_decoder.v1";
pub const LLM_FORMAT_MANIFEST_SCHEMA_V1: &str = "anysentry.llm_format.v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdapterManifest {
    pub schema_version: String,
    pub id: String,
    pub family: String,
    pub version_policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeContext {
    pub environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_generation_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_context_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryMatch {
    pub confidence: String,
    pub reason: String,
}

impl RegistryMatch {
    pub fn confirmed(reason: impl Into<String>) -> Self {
        Self {
            confidence: "confirmed".to_string(),
            reason: reason.into(),
        }
    }

    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            confidence: "unknown".to_string(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IdentityHint {
    pub entity_type: String,
    pub value_hash: String,
    pub source_path: String,
    pub strength: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolHint {
    pub raw_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
    pub source_path: String,
}

/// A framing implementation.  It only identifies/decodes transport boundaries; it must not
/// inspect product names or decide whether a body is an LLM request.
pub trait TransportDecoder: Send + Sync {
    fn manifest(&self) -> &AdapterManifest;
    fn detect(&self, bytes: &[u8]) -> RegistryMatch;
}

/// A provider-neutral wire-format implementation.  It receives a framed exchange and returns a
/// match hint; identity and KernelFact correlation remain outside this trait.
pub trait LlmFormatAdapter: Send + Sync {
    fn manifest(&self) -> &AdapterManifest;
    fn detect(&self, method: &str, headers: &[(String, String)], body: &Value) -> RegistryMatch;
}

/// Product/application-specific extraction only.  Implementations return hints and never write
/// storage, judge risk, or correlate an OS effect.
pub trait AgentAdapter: Send + Sync {
    fn manifest(&self) -> &AdapterManifest;
    fn match_runtime(&self, runtime: &RuntimeContext) -> RegistryMatch;
    fn extract_identity(&self, exchange: &Value, runtime: &RuntimeContext) -> Vec<IdentityHint>;
    fn extract_tool(&self, exchange: &Value) -> Vec<ToolHint>;
}

/// Small bounded registry used by host-side extensions.  Registration is explicit and duplicate
/// IDs are rejected; no dynamic remote manifest loading is allowed.
pub struct Registry<T: ?Sized> {
    entries: Vec<Arc<T>>,
    max_entries: usize,
}

impl<T: ?Sized> std::fmt::Debug for Registry<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("entries", &self.entries.len())
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

impl<T: ?Sized> Registry<T> {
    pub fn with_limit(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries: max_entries.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<T>> {
        self.entries.iter()
    }
}

impl<T: ?Sized> Default for Registry<T> {
    fn default() -> Self {
        Self::with_limit(64)
    }
}

impl<T: ?Sized + 'static> Registry<T> {
    pub fn register_with_id(
        &mut self,
        id: &str,
        implementation: Arc<T>,
        existing_ids: impl Fn(&T) -> &str,
    ) -> Result<(), String> {
        if id.trim().is_empty() {
            return Err("registry id cannot be empty".to_string());
        }
        if self.entries.len() >= self.max_entries {
            return Err("registry capacity exceeded".to_string());
        }
        if self.entries.iter().any(|entry| existing_ids(entry.as_ref()) == id) {
            return Err("registry id already registered".to_string());
        }
        self.entries.push(implementation);
        Ok(())
    }
}

/// Default transport matcher used by the Collector until a richer decoder is registered.
#[derive(Debug, Default)]
pub struct HttpTransportManifest {
    manifest: AdapterManifest,
}

impl HttpTransportManifest {
    pub fn new() -> Self {
        Self {
            manifest: AdapterManifest {
                schema_version: TRANSPORT_MANIFEST_SCHEMA_V1.to_string(),
                id: "http1-default".to_string(),
                family: "http1".to_string(),
                version_policy: "protocol-family".to_string(),
                capabilities: vec!["http/1.1".to_string(), "chunked".to_string(), "sse".to_string()],
                limitations: vec!["http2-stream-multiplexing".to_string()],
            },
        }
    }
}

impl TransportDecoder for HttpTransportManifest {
    fn manifest(&self) -> &AdapterManifest {
        &self.manifest
    }

    fn detect(&self, bytes: &[u8]) -> RegistryMatch {
        if bytes.windows(5).any(|window| window == b"HTTP/")
            || bytes.starts_with(b"GET ")
            || bytes.starts_with(b"POST ")
        {
            RegistryMatch::confirmed("http/1.x framing")
        } else {
            RegistryMatch::unknown("transport prefix not recognized")
        }
    }
}

