//! Provider-neutral workload attribution and sample freshness contracts.
//!
//! These types deliberately carry stable, platform-issued identifiers rather than display
//! names or arbitrary provider labels. A complete identity is required before a signal can be
//! attributed to a workload replica; partial identity must remain absent.

use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

/// Maximum encoded length of one workload identity component.
///
/// This bound keeps downstream metric-label storage predictable. Producers must use canonical,
/// opaque platform identifiers and must not put tenant secrets or raw user labels in these
/// values.
pub const MAX_WORKLOAD_IDENTITY_VALUE_LEN: usize = 128;

/// One validated component of a [`WorkloadIdentity`].
///
/// Values are ASCII, bounded, begin and end with an alphanumeric character, and may contain
/// alphanumerics plus `.`, `_`, `-`, `:`, and `/` internally. The restricted alphabet rejects
/// whitespace, control characters, and common free-form display labels; producers remain
/// responsible for supplying platform-issued IDs rather than user input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct WorkloadIdentityValue(String);

impl WorkloadIdentityValue {
    /// Validate and construct an identity value.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkloadIdentityValueError> {
        let value = value.into();
        validate_identity_value(&value)?;
        Ok(Self(value))
    }

    /// Return the canonical string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for WorkloadIdentityValue {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for WorkloadIdentityValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for WorkloadIdentityValue {
    type Err = WorkloadIdentityValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for WorkloadIdentityValue {
    type Error = WorkloadIdentityValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for WorkloadIdentityValue {
    type Error = WorkloadIdentityValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for WorkloadIdentityValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Why a workload identity component was rejected.
///
/// Error messages intentionally never contain the rejected value because it may have originated
/// in an untrusted provider label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadIdentityValueError {
    /// The value was empty.
    Empty,
    /// The value exceeded [`MAX_WORKLOAD_IDENTITY_VALUE_LEN`].
    TooLong,
    /// The value did not use the canonical identity alphabet or boundary characters.
    InvalidFormat,
}

impl fmt::Display for WorkloadIdentityValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("workload identity value cannot be empty"),
            Self::TooLong => write!(
                formatter,
                "workload identity value exceeds {MAX_WORKLOAD_IDENTITY_VALUE_LEN} bytes"
            ),
            Self::InvalidFormat => {
                formatter.write_str("workload identity value has an invalid format")
            }
        }
    }
}

impl std::error::Error for WorkloadIdentityValueError {}

fn validate_identity_value(value: &str) -> Result<(), WorkloadIdentityValueError> {
    if value.is_empty() {
        return Err(WorkloadIdentityValueError::Empty);
    }
    if value.len() > MAX_WORKLOAD_IDENTITY_VALUE_LEN {
        return Err(WorkloadIdentityValueError::TooLong);
    }

    let bytes = value.as_bytes();
    let has_canonical_boundaries = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric);
    let uses_canonical_alphabet = bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    });
    if !has_canonical_boundaries || !uses_canonical_alphabet {
        return Err(WorkloadIdentityValueError::InvalidFormat);
    }
    Ok(())
}

/// Complete, provider-neutral attribution for one observed workload replica.
///
/// All fields are required so consumers never accept a partially attributed metric. Identity
/// lifecycle semantics:
///
/// - `workload_id` identifies the long-lived workload.
/// - `deployment_id` identifies the deployment rollout.
/// - `revision_id` identifies immutable desired workload content.
/// - `replica_id` identifies the logical replica and survives process restart, adoption, and
///   rescheduling.
/// - `provider_unit_id` identifies the current runtime unit and changes when that unit is
///   replaced.
/// - `node_id` identifies the node that produced the observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentity {
    pub workload_id: WorkloadIdentityValue,
    pub deployment_id: WorkloadIdentityValue,
    pub revision_id: WorkloadIdentityValue,
    pub replica_id: WorkloadIdentityValue,
    pub provider_unit_id: WorkloadIdentityValue,
    pub node_id: WorkloadIdentityValue,
}

impl WorkloadIdentity {
    /// Construct a complete workload identity.
    pub fn new(
        workload_id: WorkloadIdentityValue,
        deployment_id: WorkloadIdentityValue,
        revision_id: WorkloadIdentityValue,
        replica_id: WorkloadIdentityValue,
        provider_unit_id: WorkloadIdentityValue,
        node_id: WorkloadIdentityValue,
    ) -> Self {
        Self {
            workload_id,
            deployment_id,
            revision_id,
            replica_id,
            provider_unit_id,
            node_id,
        }
    }
}

/// Whether an observation represents current, old, missing, or indeterminate data.
///
/// `Unavailable` and `Unknown` observations have no sample timestamp, while `Fresh` and `Stale`
/// always do. Producers must use the missing-data states rather than substituting a zero-valued
/// resource sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    /// A current sample was collected successfully.
    Fresh,
    /// A prior sample exists but is outside the producer's freshness policy.
    Stale,
    /// The producer confirmed that the target or signal source was unavailable.
    Unavailable,
    /// The producer cannot currently determine sample availability or age.
    Unknown,
}

/// Timing and freshness metadata for one observation.
///
/// Timestamps and intervals use Unix-epoch nanoseconds to map directly to OTLP without float
/// conversion. `observed_at_unix_nanos` records when the producer made the freshness
/// determination. A fresh or stale observation also carries the actual sample timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObservationMetadata {
    observed_at_unix_nanos: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sampled_at_unix_nanos: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection_interval_nanos: Option<NonZeroU64>,
    freshness: Freshness,
}

impl ObservationMetadata {
    /// Construct metadata for a current sample.
    pub fn fresh(
        observed_at_unix_nanos: u64,
        sampled_at_unix_nanos: u64,
        collection_interval_nanos: Option<NonZeroU64>,
    ) -> Result<Self, ObservationMetadataError> {
        Self::sampled(
            observed_at_unix_nanos,
            sampled_at_unix_nanos,
            collection_interval_nanos,
            Freshness::Fresh,
        )
    }

    /// Construct metadata for an old sample that must not be treated as current.
    pub fn stale(
        observed_at_unix_nanos: u64,
        sampled_at_unix_nanos: u64,
        collection_interval_nanos: Option<NonZeroU64>,
    ) -> Result<Self, ObservationMetadataError> {
        Self::sampled(
            observed_at_unix_nanos,
            sampled_at_unix_nanos,
            collection_interval_nanos,
            Freshness::Stale,
        )
    }

    /// Construct metadata for a confirmed missing sample.
    pub fn unavailable(
        observed_at_unix_nanos: u64,
        collection_interval_nanos: Option<NonZeroU64>,
    ) -> Self {
        Self {
            observed_at_unix_nanos,
            sampled_at_unix_nanos: None,
            collection_interval_nanos,
            freshness: Freshness::Unavailable,
        }
    }

    /// Construct metadata when sample availability or age cannot be determined.
    pub fn unknown(
        observed_at_unix_nanos: u64,
        collection_interval_nanos: Option<NonZeroU64>,
    ) -> Self {
        Self {
            observed_at_unix_nanos,
            sampled_at_unix_nanos: None,
            collection_interval_nanos,
            freshness: Freshness::Unknown,
        }
    }

    /// Time at which the producer made this observation.
    pub fn observed_at_unix_nanos(&self) -> u64 {
        self.observed_at_unix_nanos
    }

    /// Actual sample time for fresh or stale data.
    pub fn sampled_at_unix_nanos(&self) -> Option<u64> {
        self.sampled_at_unix_nanos
    }

    /// Intended collection interval, when known.
    pub fn collection_interval_nanos(&self) -> Option<NonZeroU64> {
        self.collection_interval_nanos
    }

    /// Explicit current state of the observation.
    pub fn freshness(&self) -> Freshness {
        self.freshness
    }

    fn sampled(
        observed_at_unix_nanos: u64,
        sampled_at_unix_nanos: u64,
        collection_interval_nanos: Option<NonZeroU64>,
        freshness: Freshness,
    ) -> Result<Self, ObservationMetadataError> {
        if sampled_at_unix_nanos > observed_at_unix_nanos {
            return Err(ObservationMetadataError::SampleAfterObservation);
        }
        Ok(Self {
            observed_at_unix_nanos,
            sampled_at_unix_nanos: Some(sampled_at_unix_nanos),
            collection_interval_nanos,
            freshness,
        })
    }
}

/// Invalid timing relationship in [`ObservationMetadata`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationMetadataError {
    /// A sample claimed to have been captured after its observation was emitted.
    SampleAfterObservation,
}

impl fmt::Display for ObservationMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SampleAfterObservation => {
                formatter.write_str("sample timestamp cannot be later than observation timestamp")
            }
        }
    }
}

impl std::error::Error for ObservationMetadataError {}
