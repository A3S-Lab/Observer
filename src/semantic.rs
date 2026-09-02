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
        if self
            .entries
            .iter()
            .any(|entry| existing_ids(entry.as_ref()) == id)
        {
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
                capabilities: vec![
                    "http/1.1".to_string(),
                    "chunked".to_string(),
                    "sse".to_string(),
                ],
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

/// Provider-neutral default format matcher.  It intentionally reports only a shape hint; the
/// Collector's existing parser remains responsible for decoding the concrete response stream.
#[derive(Debug, Default)]
pub struct DefaultLlmFormatAdapter {
    manifest: AdapterManifest,
}

impl DefaultLlmFormatAdapter {
    pub fn new() -> Self {
        Self {
            manifest: AdapterManifest {
                schema_version: LLM_FORMAT_MANIFEST_SCHEMA_V1.to_string(),
                id: "generic-llm-json".to_string(),
                family: "llm-wire".to_string(),
                version_policy: "shape".to_string(),
                capabilities: vec![
                    "openai-chat".to_string(),
                    "openai-responses".to_string(),
                    "anthropic-messages".to_string(),
                    "gemini".to_string(),
                ],
                limitations: vec!["provider-specific-stream-extensions".to_string()],
            },
        }
    }
}

impl LlmFormatAdapter for DefaultLlmFormatAdapter {
    fn manifest(&self) -> &AdapterManifest {
        &self.manifest
    }

    fn detect(&self, method: &str, _headers: &[(String, String)], body: &Value) -> RegistryMatch {
        if !matches!(
            method.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "PATCH"
        ) {
            return RegistryMatch::unknown("method is not a generation request");
        }
        let Some(object) = body.as_object() else {
            return RegistryMatch::unknown("body is not a JSON object");
        };
        if object.contains_key("messages")
            || object.contains_key("input")
            || object.contains_key("contents")
            || object.contains_key("prompt")
        {
            RegistryMatch::confirmed("generation-shaped JSON body")
        } else {
            RegistryMatch::unknown("generation fields are absent")
        }
    }
}

/// Product-neutral Agent adapter.  It is useful as an explicit fallback when no product manifest
/// is installed: KernelFact and transport records remain valid, while identity extraction yields
/// no fabricated Session/LogicalAgent values.
#[derive(Debug, Default)]
pub struct DefaultAgentAdapter {
    manifest: AdapterManifest,
}

impl DefaultAgentAdapter {
    pub fn new() -> Self {
        Self {
            manifest: AdapterManifest {
                schema_version: ADAPTER_MANIFEST_SCHEMA_V1.to_string(),
                id: "generic-unresolved-agent".to_string(),
                family: "unknown".to_string(),
                version_policy: "runtime-evidence".to_string(),
                capabilities: Vec::new(),
                limitations: vec!["no-product-session-identity".to_string()],
            },
        }
    }
}

impl AgentAdapter for DefaultAgentAdapter {
    fn manifest(&self) -> &AdapterManifest {
        &self.manifest
    }

    fn match_runtime(&self, _runtime: &RuntimeContext) -> RegistryMatch {
        RegistryMatch::unknown("no product manifest registered")
    }

    fn extract_identity(&self, _exchange: &Value, _runtime: &RuntimeContext) -> Vec<IdentityHint> {
        Vec::new()
    }

    fn extract_tool(&self, _exchange: &Value) -> Vec<ToolHint> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registries_are_orthogonal_and_fail_closed() {
        let transport = HttpTransportManifest::new();
        let format = DefaultLlmFormatAdapter::new();
        let agent = DefaultAgentAdapter::new();
        assert_eq!(transport.manifest().family, "http1");
        assert_eq!(format.manifest().family, "llm-wire");
        assert_eq!(
            agent.match_runtime(&RuntimeContext::default()).confidence,
            "unknown"
        );
        assert_eq!(
            agent.extract_identity(&Value::Null, &RuntimeContext::default()),
            Vec::new()
        );
        assert_eq!(agent.extract_tool(&Value::Null), Vec::new());
        assert_eq!(
            format
                .detect("GET", &[], &Value::Object(serde_json::Map::new()))
                .confidence,
            "unknown"
        );
    }

    #[test]
    fn registry_rejects_duplicates_and_bounds_growth() {
        let mut registry = Registry::<dyn TransportDecoder>::with_limit(1);
        let first: Arc<dyn TransportDecoder> = Arc::new(HttpTransportManifest::new());
        registry
            .register_with_id("http1-default", first, |entry| entry.manifest().id.as_str())
            .unwrap();
        let duplicate: Arc<dyn TransportDecoder> = Arc::new(HttpTransportManifest::new());
        assert!(registry
            .register_with_id("http1-default", duplicate, |entry| entry
                .manifest()
                .id
                .as_str())
            .is_err());
        let second: Arc<dyn TransportDecoder> = Arc::new(HttpTransportManifest::new());
        assert!(registry
            .register_with_id("other", second, |entry| entry.manifest().id.as_str())
            .is_err());
        assert_eq!(registry.len(), 1);
    }
}
