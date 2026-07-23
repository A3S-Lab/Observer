use a3s_observer::{
    AgentEvent, EnrichedEvent, Freshness, Identity, IdentityResolver, ObservationMetadata,
    WorkloadIdentity, WorkloadIdentityValue, MAX_WORKLOAD_IDENTITY_VALUE_LEN,
};
use serde_json::json;
use std::num::NonZeroU64;

fn identity_value(value: &str) -> WorkloadIdentityValue {
    WorkloadIdentityValue::new(value).expect("fixture identity must be valid")
}

fn workload_identity() -> WorkloadIdentity {
    WorkloadIdentity::new(
        identity_value("workload-01HV7F5N"),
        identity_value("deployment-01HV7F6A"),
        identity_value("revision-sha256:8f3a"),
        identity_value("replica-0007"),
        identity_value("containerd:4f6c2d8a"),
        identity_value("node-us-east-1a-03"),
    )
}

#[test]
fn workload_identity_serializes_as_complete_stable_ids() {
    assert_eq!(
        serde_json::to_value(workload_identity()).unwrap(),
        json!({
            "workload_id": "workload-01HV7F5N",
            "deployment_id": "deployment-01HV7F6A",
            "revision_id": "revision-sha256:8f3a",
            "replica_id": "replica-0007",
            "provider_unit_id": "containerd:4f6c2d8a",
            "node_id": "node-us-east-1a-03"
        })
    );
}

#[test]
fn workload_identity_values_are_bounded_and_safe_for_labels() {
    let max = "a".repeat(MAX_WORKLOAD_IDENTITY_VALUE_LEN);
    assert!(WorkloadIdentityValue::new(max).is_ok());

    for rejected in [
        "",
        "raw tenant label",
        "line\nbreak",
        "control\u{0007}byte",
        "非规范标识",
        "-leading-separator",
        "trailing-separator-",
    ] {
        let error = WorkloadIdentityValue::new(rejected).unwrap_err();
        assert!(
            rejected.is_empty() || !error.to_string().contains(rejected),
            "validation errors must not echo rejected identity values"
        );
    }

    let overlong = "s".repeat(MAX_WORKLOAD_IDENTITY_VALUE_LEN + 1);
    let error = WorkloadIdentityValue::new(&overlong).unwrap_err();
    assert!(!error.to_string().contains(&overlong));

    let decoded = serde_json::from_str::<WorkloadIdentityValue>("\"raw tenant label\"");
    assert!(decoded.is_err(), "deserialization must preserve validation");
}

#[test]
fn observation_metadata_distinguishes_samples_from_missing_data() {
    let interval = NonZeroU64::new(15_000_000_000);
    let fresh = ObservationMetadata::fresh(
        1_720_000_015_000_000_000,
        1_720_000_014_000_000_000,
        interval,
    )
    .unwrap();
    let stale = ObservationMetadata::stale(
        1_720_000_030_000_000_000,
        1_720_000_014_000_000_000,
        interval,
    )
    .unwrap();
    let unavailable = ObservationMetadata::unavailable(1_720_000_030_000_000_000, interval);
    let unknown = ObservationMetadata::unknown(1_720_000_030_000_000_000, None);

    assert_eq!(fresh.freshness(), Freshness::Fresh);
    assert_eq!(stale.freshness(), Freshness::Stale);
    assert_eq!(unavailable.freshness(), Freshness::Unavailable);
    assert_eq!(unknown.freshness(), Freshness::Unknown);
    assert!(unavailable.sampled_at_unix_nanos().is_none());
    assert!(unknown.sampled_at_unix_nanos().is_none());

    assert_eq!(
        serde_json::to_value(unavailable).unwrap(),
        json!({
            "observed_at_unix_nanos": 1_720_000_030_000_000_000u64,
            "collection_interval_nanos": 15_000_000_000u64,
            "freshness": "unavailable"
        })
    );
}

#[test]
fn sample_timestamp_cannot_be_after_observation_timestamp() {
    let error = ObservationMetadata::fresh(10, 11, None).unwrap_err();
    assert_eq!(
        error.to_string(),
        "sample timestamp cannot be later than observation timestamp"
    );
}

struct WorkloadResolver;

impl IdentityResolver for WorkloadResolver {
    fn resolve(&self, _pid: u32, _cgroup_id: u64, _netns: u64) -> Identity {
        Identity {
            agent: Some("agent-7".into()),
            task: Some("task-3".into()),
            session: None,
        }
    }

    fn resolve_workload(
        &self,
        _pid: u32,
        _cgroup_id: u64,
        _netns: u64,
    ) -> Option<WorkloadIdentity> {
        Some(workload_identity())
    }
}

struct LegacyResolver;

impl IdentityResolver for LegacyResolver {
    fn resolve(&self, _pid: u32, _cgroup_id: u64, _netns: u64) -> Identity {
        Identity::default()
    }
}

#[test]
fn resolver_workload_identity_and_observation_reach_ndjson() {
    let resolver = WorkloadResolver;
    let event = EnrichedEvent {
        identity: resolver.resolve(7, 11, 13),
        workload: resolver.resolve_workload(7, 11, 13),
        observation: Some(ObservationMetadata::fresh(1_720_000_015, 1_720_000_014, None).unwrap()),
        process: None,
        provider: None,
        event: AgentEvent::ProcessExit {
            pid: 7,
            exit_code: 0,
            signal: 0,
        },
    };

    let line = serde_json::to_string(&event).unwrap();
    assert!(!line.contains('\n'));
    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(value["workload"]["replica_id"], "replica-0007");
    assert_eq!(value["observation"]["freshness"], "fresh");
    assert_eq!(
        value["observation"]["sampled_at_unix_nanos"],
        1_720_000_014u64
    );
}

#[test]
fn existing_identity_resolvers_default_to_no_workload_identity() {
    let resolver = LegacyResolver;
    assert_eq!(resolver.resolve_workload(1, 2, 3), None);

    let event = EnrichedEvent {
        identity: resolver.resolve(1, 2, 3),
        workload: resolver.resolve_workload(1, 2, 3),
        observation: None,
        process: None,
        provider: None,
        event: AgentEvent::ProcessExit {
            pid: 1,
            exit_code: 0,
            signal: 0,
        },
    };
    let value = serde_json::to_value(event).unwrap();
    assert!(value.get("workload").is_none());
    assert!(value.get("observation").is_none());
}
