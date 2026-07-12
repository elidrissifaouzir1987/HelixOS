use crate::canonical::to_jcs_vec;
use crate::{ContractError, Identifier, Nonce128, ResourceRefV1, Result, SafeU64, Sha256Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

pub(crate) const SCHEMA_V1: &str = "helixos.plan-envelope/1";
pub(crate) const DIGEST_ALGORITHM: &str = "sha-256";
pub(crate) const SIGNATURE_ALGORITHM: &str = "ed25519";
pub(crate) const INTENT_FILE_PATCH: &str = "host.file.patch";
const MAX_CONTENT_BYTES: usize = 512 * 1024;
const MAX_CAPABILITIES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevelV1 {
    L0,
    L1,
    L2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClassV1 {
    Compensation,
    Irreversible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AtomicityV1 {
    AtomicReplace,
    NonAtomic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestSourceKindV1 {
    HumanRequestGrant,
    RegisteredTrigger,
}

#[derive(Clone)]
pub struct FilePreconditionInputV1 {
    pub volume_id: String,
    pub file_id: String,
    pub content_sha256: Sha256Digest,
    pub byte_length: u64,
}

impl fmt::Debug for FilePreconditionInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FilePreconditionInputV1")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct BudgetInputV1 {
    pub reservation_id: String,
    pub currency_code: String,
    pub price_table_id: String,
    pub max_cost_micro_units: u64,
    pub action_limit: u64,
    pub egress_bytes_limit: u64,
}

impl fmt::Debug for BudgetInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BudgetInputV1")
            .field("action_limit", &self.action_limit)
            .field("egress_bytes_limit", &self.egress_bytes_limit)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryInputV1 {
    pub class: RecoveryClassV1,
    pub atomicity: AtomicityV1,
    pub reserved_bytes: u64,
}

#[derive(Clone)]
pub struct PlanInputV1 {
    pub operation_id: String,
    pub task_id: String,
    pub workload_id: String,
    pub boot_id: String,
    pub task_lease_digest: Sha256Digest,
    pub request_source_kind: RequestSourceKindV1,
    pub request_source_digest: Sha256Digest,
    pub catalog_version: String,
    pub policy_version: String,
    pub risk_level: RiskLevelV1,
    pub target: ResourceRefV1,
    pub precondition: FilePreconditionInputV1,
    pub replacement_bytes: Vec<u8>,
    pub replacement_media_type: String,
    pub recovery: RecoveryInputV1,
    pub capability_report_digest: Sha256Digest,
    pub capability_observed_at_unix_ms: u64,
    pub required_capabilities: Vec<String>,
    pub budget: BudgetInputV1,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: Nonce128,
    pub instance_epoch: u64,
    pub fencing_epoch: u64,
}

impl fmt::Debug for PlanInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanInputV1")
            .field("risk_level", &self.risk_level)
            .field("recovery", &self.recovery)
            .field("replacement_byte_length", &self.replacement_bytes.len())
            .field(
                "required_capability_count",
                &self.required_capabilities.len(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSourceV1 {
    kind: RequestSourceKindV1,
    digest_sha256: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetReservationV1 {
    reservation_id: Identifier,
    currency_code: String,
    price_table_id: Identifier,
    max_cost_micro_units: SafeU64,
    action_limit: SafeU64,
    egress_bytes_limit: SafeU64,
}

impl BudgetReservationV1 {
    fn try_from_input(input: BudgetInputV1) -> Result<Self> {
        if input.currency_code.len() != 3
            || !input
                .currency_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ContractError::invalid(
                "budget.currency_code",
                "must be three uppercase ASCII letters",
            ));
        }
        Ok(Self {
            reservation_id: Identifier::new(input.reservation_id, 128)?,
            currency_code: input.currency_code,
            price_table_id: Identifier::new(input.price_table_id, 128)?,
            max_cost_micro_units: SafeU64::new(input.max_cost_micro_units)?,
            action_limit: SafeU64::new(input.action_limit)?,
            egress_bytes_limit: SafeU64::new(input.egress_bytes_limit)?,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.currency_code.len() != 3
            || !self
                .currency_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ContractError::invalid(
                "budget.currency_code",
                "must be three uppercase ASCII letters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePreconditionV1 {
    volume_id: Identifier,
    file_id: Identifier,
    content_sha256: Sha256Digest,
    byte_length: SafeU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementContentV1 {
    content_base64url: String,
    byte_length: SafeU64,
    sha256: Sha256Digest,
    media_type: String,
}

impl ReplacementContentV1 {
    fn from_bytes(bytes: &[u8], media_type: String) -> Result<Self> {
        validate_media_type(&media_type)?;
        if bytes.len() > MAX_CONTENT_BYTES {
            return Err(ContractError::invalid(
                "intent.replacement",
                "content exceeds the v1 bound",
            ));
        }
        Ok(Self {
            content_base64url: URL_SAFE_NO_PAD.encode(bytes),
            byte_length: SafeU64::new(bytes.len() as u64)?,
            sha256: Sha256Digest::digest(bytes),
            media_type,
        })
    }

    fn validate(&self) -> Result<()> {
        validate_media_type(&self.media_type)?;
        if self.content_base64url.contains('=') {
            return Err(ContractError::InvalidEncoding {
                kind: "replacement content",
            });
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.content_base64url)
            .map_err(|_| ContractError::InvalidEncoding {
                kind: "replacement content",
            })?;
        if bytes.len() > MAX_CONTENT_BYTES
            || self.byte_length.get() != bytes.len() as u64
            || self.sha256 != Sha256Digest::digest(&bytes)
            || URL_SAFE_NO_PAD.encode(&bytes) != self.content_base64url
        {
            return Err(ContractError::invalid(
                "intent.replacement",
                "content, length, encoding, and digest are inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryProfileV1 {
    class: RecoveryClassV1,
    atomicity: AtomicityV1,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    preimage_sha256: Option<Sha256Digest>,
    reserved_bytes: SafeU64,
}

fn deserialize_present_value<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl RecoveryProfileV1 {
    fn validate(&self, precondition: &FilePreconditionV1) -> Result<()> {
        match (self.class, self.preimage_sha256) {
            (RecoveryClassV1::Compensation, Some(digest))
                if digest == precondition.content_sha256
                    && self.reserved_bytes >= precondition.byte_length =>
            {
                Ok(())
            }
            (RecoveryClassV1::Irreversible, None) => Ok(()),
            (RecoveryClassV1::Compensation, _) => Err(ContractError::invalid(
                "intent.recovery",
                "compensation requires the exact preimage digest and sufficient reserved bytes",
            )),
            (RecoveryClassV1::Irreversible, Some(_)) => Err(ContractError::invalid(
                "intent.recovery.preimage_sha256",
                "irreversible recovery must omit a preimage",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileVerificationV1 {
    expected_sha256: Sha256Digest,
    expected_byte_length: SafeU64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePatchIntentV1 {
    kind: String,
    target: ResourceRefV1,
    precondition: FilePreconditionV1,
    replacement: ReplacementContentV1,
    recovery: RecoveryProfileV1,
    verification: FileVerificationV1,
}

impl FilePatchIntentV1 {
    fn validate(&self) -> Result<()> {
        if self.kind != INTENT_FILE_PATCH {
            return Err(ContractError::UnsupportedIntent);
        }
        self.target.validate()?;
        self.replacement.validate()?;
        self.recovery.validate(&self.precondition)?;
        if self.verification.expected_sha256 != self.replacement.sha256
            || self.verification.expected_byte_length != self.replacement.byte_length
        {
            return Err(ContractError::invalid(
                "intent.verification",
                "verification must bind the exact replacement result",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanProtectedV1 {
    schema: String,
    digest_algorithm: String,
    signature_algorithm: String,
    key_id: Identifier,
    operation_id: Identifier,
    task_id: Identifier,
    workload_id: Identifier,
    boot_id: Identifier,
    task_lease_digest: Sha256Digest,
    request_source: RequestSourceV1,
    catalog_version: Identifier,
    policy_version: Identifier,
    risk_level: RiskLevelV1,
    intent: FilePatchIntentV1,
    capability_report_digest: Sha256Digest,
    capability_observed_at_unix_ms: SafeU64,
    required_capabilities: Vec<Identifier>,
    budget: BudgetReservationV1,
    issued_at_unix_ms: SafeU64,
    expires_at_unix_ms: SafeU64,
    nonce: Nonce128,
    instance_epoch: SafeU64,
    fencing_epoch: SafeU64,
}

impl fmt::Debug for PlanProtectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanProtectedV1")
            .field("risk_level", &self.risk_level)
            .field(
                "required_capability_count",
                &self.required_capabilities.len(),
            )
            .finish_non_exhaustive()
    }
}

impl PlanProtectedV1 {
    pub fn try_new(input: PlanInputV1, key_id: impl Into<String>) -> Result<Self> {
        let precondition = FilePreconditionV1 {
            volume_id: Identifier::new(input.precondition.volume_id, 128)?,
            file_id: Identifier::new(input.precondition.file_id, 128)?,
            content_sha256: input.precondition.content_sha256,
            byte_length: SafeU64::new(input.precondition.byte_length)?,
        };
        let replacement = ReplacementContentV1::from_bytes(
            &input.replacement_bytes,
            input.replacement_media_type,
        )?;
        let recovery = RecoveryProfileV1 {
            class: input.recovery.class,
            atomicity: input.recovery.atomicity,
            preimage_sha256: match input.recovery.class {
                RecoveryClassV1::Compensation => Some(precondition.content_sha256),
                RecoveryClassV1::Irreversible => None,
            },
            reserved_bytes: SafeU64::new(input.recovery.reserved_bytes)?,
        };
        let verification = FileVerificationV1 {
            expected_sha256: replacement.sha256,
            expected_byte_length: replacement.byte_length,
        };
        let mut required_capabilities = input
            .required_capabilities
            .into_iter()
            .map(|value| Identifier::new(value, 128))
            .collect::<Result<Vec<_>>>()?;
        required_capabilities.sort();
        required_capabilities.dedup();
        let plan = Self {
            schema: SCHEMA_V1.to_owned(),
            digest_algorithm: DIGEST_ALGORITHM.to_owned(),
            signature_algorithm: SIGNATURE_ALGORITHM.to_owned(),
            key_id: Identifier::new(key_id, 128)?,
            operation_id: Identifier::new(input.operation_id, 128)?,
            task_id: Identifier::new(input.task_id, 128)?,
            workload_id: Identifier::new(input.workload_id, 128)?,
            boot_id: Identifier::new(input.boot_id, 128)?,
            task_lease_digest: input.task_lease_digest,
            request_source: RequestSourceV1 {
                kind: input.request_source_kind,
                digest_sha256: input.request_source_digest,
            },
            catalog_version: Identifier::new(input.catalog_version, 128)?,
            policy_version: Identifier::new(input.policy_version, 128)?,
            risk_level: input.risk_level,
            intent: FilePatchIntentV1 {
                kind: INTENT_FILE_PATCH.to_owned(),
                target: input.target,
                precondition,
                replacement,
                recovery,
                verification,
            },
            capability_report_digest: input.capability_report_digest,
            capability_observed_at_unix_ms: SafeU64::new(input.capability_observed_at_unix_ms)?,
            required_capabilities,
            budget: BudgetReservationV1::try_from_input(input.budget)?,
            issued_at_unix_ms: SafeU64::new(input.issued_at_unix_ms)?,
            expires_at_unix_ms: SafeU64::new(input.expires_at_unix_ms)?,
            nonce: input.nonce,
            instance_epoch: SafeU64::new(input.instance_epoch)?,
            fencing_epoch: SafeU64::new(input.fencing_epoch)?,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.canonical_bytes_after_validation()
    }

    pub fn plan_id(&self) -> Result<Sha256Digest> {
        Ok(Sha256Digest::digest(&self.canonical_bytes()?))
    }

    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    pub fn operation_id(&self) -> &str {
        self.operation_id.as_str()
    }

    pub fn target(&self) -> &ResourceRefV1 {
        &self.intent.target
    }

    pub(crate) fn canonical_bytes_after_validation(&self) -> Result<Vec<u8>> {
        to_jcs_vec(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA_V1 {
            return Err(ContractError::UnsupportedSchema);
        }
        if self.digest_algorithm != DIGEST_ALGORITHM {
            return Err(ContractError::UnsupportedAlgorithm { kind: "digest" });
        }
        if self.signature_algorithm != SIGNATURE_ALGORITHM {
            return Err(ContractError::UnsupportedAlgorithm { kind: "signature" });
        }
        if self.risk_level == RiskLevelV1::L0 {
            return Err(ContractError::invalid(
                "risk_level",
                "host.file.patch is a write and requires at least L1",
            ));
        }
        if self.intent.recovery.class == RecoveryClassV1::Irreversible
            && self.risk_level != RiskLevelV1::L2
        {
            return Err(ContractError::invalid(
                "risk_level",
                "irreversible host effects require L2",
            ));
        }
        if self.required_capabilities.is_empty()
            || self.required_capabilities.len() > MAX_CAPABILITIES
            || !self
                .required_capabilities
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(ContractError::invalid(
                "required_capabilities",
                "must be a bounded sorted unique non-empty list",
            ));
        }
        if self.issued_at_unix_ms >= self.expires_at_unix_ms {
            return Err(ContractError::invalid(
                "expires_at_unix_ms",
                "must be after issued_at_unix_ms",
            ));
        }
        if self.capability_observed_at_unix_ms > self.issued_at_unix_ms {
            return Err(ContractError::invalid(
                "capability_observed_at_unix_ms",
                "cannot be later than plan issuance",
            ));
        }
        self.intent.validate()?;
        self.budget.validate()?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPlanEnvelopeV1 {
    protected: PlanProtectedV1,
    plan_id: Sha256Digest,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSignedPlanEnvelopeV1 {
    protected: PlanProtectedV1,
    plan_id: Sha256Digest,
    signature: String,
}

impl RawSignedPlanEnvelopeV1 {
    pub(crate) fn into_signed(self) -> SignedPlanEnvelopeV1 {
        SignedPlanEnvelopeV1 {
            protected: self.protected,
            plan_id: self.plan_id,
            signature: self.signature,
        }
    }
}

impl fmt::Debug for SignedPlanEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPlanEnvelopeV1")
            .field("plan_id", &self.plan_id)
            .field("protected", &self.protected)
            .finish_non_exhaustive()
    }
}

impl SignedPlanEnvelopeV1 {
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.protected.validate()?;
        to_jcs_vec(self)
    }

    pub fn protected(&self) -> &PlanProtectedV1 {
        &self.protected
    }

    pub const fn plan_id(&self) -> Sha256Digest {
        self.plan_id
    }

    pub fn signature_base64url(&self) -> &str {
        &self.signature
    }

    pub(crate) fn new(
        protected: PlanProtectedV1,
        plan_id: Sha256Digest,
        signature: String,
    ) -> Self {
        Self {
            protected,
            plan_id,
            signature,
        }
    }

    pub(crate) fn signature(&self) -> &str {
        &self.signature
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticPlanEnvelopeV1 {
    signed: SignedPlanEnvelopeV1,
    verified_key_fingerprint: Sha256Digest,
}

impl fmt::Debug for AuthenticPlanEnvelopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticPlanEnvelopeV1")
            .field("plan_id", &self.signed.plan_id)
            .finish_non_exhaustive()
    }
}

impl AuthenticPlanEnvelopeV1 {
    pub fn protected(&self) -> &PlanProtectedV1 {
        &self.signed.protected
    }

    pub const fn plan_id(&self) -> Sha256Digest {
        self.signed.plan_id
    }

    pub fn eligibility_claims(&self) -> PlanEligibilityClaimsV1<'_> {
        PlanEligibilityClaimsV1 { envelope: self }
    }

    pub fn preparation_claims(&self) -> PlanPreparationClaimsV1<'_> {
        PlanPreparationClaimsV1 { envelope: self }
    }

    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }

    pub fn into_signed(self) -> SignedPlanEnvelopeV1 {
        self.signed
    }

    pub(crate) fn new(
        signed: SignedPlanEnvelopeV1,
        verified_key_fingerprint: Sha256Digest,
    ) -> Self {
        Self {
            signed,
            verified_key_fingerprint,
        }
    }
}

/// Borrowed, read-only preparation bindings from an authenticated plan.
///
/// The projection is deliberately not a wire or persistence type and has no
/// independent public constructor.
///
/// ```compile_fail,E0277
/// use helix_contracts::PlanPreparationClaimsV1;
/// use serde::Serialize;
///
/// fn require_serialize<T: Serialize>() {}
/// require_serialize::<PlanPreparationClaimsV1<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use helix_contracts::PlanPreparationClaimsV1;
/// use serde::Deserialize;
///
/// fn require_deserialize<T: for<'de> Deserialize<'de>>() {}
/// require_deserialize::<PlanPreparationClaimsV1<'static>>();
/// ```
///
/// ```compile_fail,E0451
/// use helix_contracts::{AuthenticPlanEnvelopeV1, PlanPreparationClaimsV1};
///
/// fn forge<'plan>(
///     envelope: &'plan AuthenticPlanEnvelopeV1,
/// ) -> PlanPreparationClaimsV1<'plan> {
///     PlanPreparationClaimsV1 { envelope }
/// }
/// ```
#[derive(Clone, Copy)]
pub struct PlanPreparationClaimsV1<'plan> {
    envelope: &'plan AuthenticPlanEnvelopeV1,
}

impl fmt::Debug for PlanPreparationClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanPreparationClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'plan> PlanPreparationClaimsV1<'plan> {
    pub const fn plan_id(&self) -> Sha256Digest {
        self.envelope.signed.plan_id
    }

    pub fn operation_id(&self) -> &'plan str {
        self.envelope.signed.protected.operation_id.as_str()
    }

    pub fn task_id(&self) -> &'plan str {
        self.envelope.signed.protected.task_id.as_str()
    }

    pub fn workload_id(&self) -> &'plan str {
        self.envelope.signed.protected.workload_id.as_str()
    }

    pub const fn task_lease_digest(&self) -> Sha256Digest {
        self.envelope.signed.protected.task_lease_digest
    }

    pub fn target(&self) -> &'plan ResourceRefV1 {
        &self.envelope.signed.protected.intent.target
    }

    pub fn precondition_volume_id(&self) -> &'plan str {
        self.envelope
            .signed
            .protected
            .intent
            .precondition
            .volume_id
            .as_str()
    }

    pub fn precondition_file_id(&self) -> &'plan str {
        self.envelope
            .signed
            .protected
            .intent
            .precondition
            .file_id
            .as_str()
    }

    pub const fn precondition_content_sha256(&self) -> Sha256Digest {
        self.envelope
            .signed
            .protected
            .intent
            .precondition
            .content_sha256
    }

    pub const fn precondition_byte_length(&self) -> u64 {
        self.envelope
            .signed
            .protected
            .intent
            .precondition
            .byte_length
            .get()
    }

    pub const fn replacement_sha256(&self) -> Sha256Digest {
        self.envelope.signed.protected.intent.replacement.sha256
    }

    pub const fn replacement_byte_length(&self) -> u64 {
        self.envelope
            .signed
            .protected
            .intent
            .replacement
            .byte_length
            .get()
    }

    pub fn replacement_media_type(&self) -> &'plan str {
        &self.envelope.signed.protected.intent.replacement.media_type
    }

    pub const fn recovery_class(&self) -> RecoveryClassV1 {
        self.envelope.signed.protected.intent.recovery.class
    }

    pub const fn atomicity(&self) -> AtomicityV1 {
        self.envelope.signed.protected.intent.recovery.atomicity
    }

    pub const fn preimage_sha256(&self) -> Option<Sha256Digest> {
        self.envelope
            .signed
            .protected
            .intent
            .recovery
            .preimage_sha256
    }

    pub const fn recovery_reserved_bytes(&self) -> u64 {
        self.envelope
            .signed
            .protected
            .intent
            .recovery
            .reserved_bytes
            .get()
    }

    pub const fn verification_sha256(&self) -> Sha256Digest {
        self.envelope
            .signed
            .protected
            .intent
            .verification
            .expected_sha256
    }

    pub const fn verification_byte_length(&self) -> u64 {
        self.envelope
            .signed
            .protected
            .intent
            .verification
            .expected_byte_length
            .get()
    }

    pub fn budget(&self) -> PlanEligibilityBudgetClaimsV1<'plan> {
        PlanEligibilityBudgetClaimsV1 {
            budget: &self.envelope.signed.protected.budget,
        }
    }
}

/// Borrowed, read-only eligibility bindings from an authenticated plan.
///
/// The projection is deliberately not a wire or persistence type.
///
/// ```compile_fail,E0277
/// use helix_contracts::PlanEligibilityClaimsV1;
/// use serde::Serialize;
///
/// fn require_serialize<T: Serialize>() {}
/// require_serialize::<PlanEligibilityClaimsV1<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use helix_contracts::PlanEligibilityClaimsV1;
/// use serde::Deserialize;
///
/// fn require_deserialize<T: for<'de> Deserialize<'de>>() {}
/// require_deserialize::<PlanEligibilityClaimsV1<'static>>();
/// ```
#[derive(Clone, Copy)]
pub struct PlanEligibilityClaimsV1<'plan> {
    envelope: &'plan AuthenticPlanEnvelopeV1,
}

impl fmt::Debug for PlanEligibilityClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanEligibilityClaimsV1")
            .field(
                "required_capability_count",
                &self.envelope.signed.protected.required_capabilities.len(),
            )
            .finish_non_exhaustive()
    }
}

impl<'plan> PlanEligibilityClaimsV1<'plan> {
    pub const fn plan_id(&self) -> Sha256Digest {
        self.envelope.signed.plan_id
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.envelope.verified_key_fingerprint
    }

    pub fn schema(&self) -> &'plan str {
        &self.envelope.signed.protected.schema
    }

    pub fn key_id(&self) -> &'plan str {
        self.envelope.signed.protected.key_id.as_str()
    }

    pub fn operation_id(&self) -> &'plan str {
        self.envelope.signed.protected.operation_id.as_str()
    }

    pub fn task_id(&self) -> &'plan str {
        self.envelope.signed.protected.task_id.as_str()
    }

    pub fn workload_id(&self) -> &'plan str {
        self.envelope.signed.protected.workload_id.as_str()
    }

    pub fn boot_id(&self) -> &'plan str {
        self.envelope.signed.protected.boot_id.as_str()
    }

    pub const fn task_lease_digest(&self) -> Sha256Digest {
        self.envelope.signed.protected.task_lease_digest
    }

    pub const fn request_source_kind(&self) -> RequestSourceKindV1 {
        self.envelope.signed.protected.request_source.kind
    }

    pub const fn request_source_digest(&self) -> Sha256Digest {
        self.envelope.signed.protected.request_source.digest_sha256
    }

    pub fn catalog_version(&self) -> &'plan str {
        self.envelope.signed.protected.catalog_version.as_str()
    }

    pub fn policy_version(&self) -> &'plan str {
        self.envelope.signed.protected.policy_version.as_str()
    }

    pub const fn risk_level(&self) -> RiskLevelV1 {
        self.envelope.signed.protected.risk_level
    }

    pub fn intent_kind(&self) -> &'plan str {
        &self.envelope.signed.protected.intent.kind
    }

    pub fn target(&self) -> &'plan ResourceRefV1 {
        &self.envelope.signed.protected.intent.target
    }

    pub const fn capability_report_digest(&self) -> Sha256Digest {
        self.envelope.signed.protected.capability_report_digest
    }

    pub const fn capability_observed_at_unix_ms(&self) -> u64 {
        self.envelope
            .signed
            .protected
            .capability_observed_at_unix_ms
            .get()
    }

    pub fn required_capabilities(&self) -> &'plan [Identifier] {
        &self.envelope.signed.protected.required_capabilities
    }

    pub fn budget(&self) -> PlanEligibilityBudgetClaimsV1<'plan> {
        PlanEligibilityBudgetClaimsV1 {
            budget: &self.envelope.signed.protected.budget,
        }
    }

    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.envelope.signed.protected.issued_at_unix_ms.get()
    }

    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.envelope.signed.protected.expires_at_unix_ms.get()
    }

    pub const fn nonce(&self) -> Nonce128 {
        self.envelope.signed.protected.nonce
    }

    pub const fn instance_epoch(&self) -> u64 {
        self.envelope.signed.protected.instance_epoch.get()
    }

    pub const fn fencing_epoch(&self) -> u64 {
        self.envelope.signed.protected.fencing_epoch.get()
    }
}

#[derive(Clone, Copy)]
pub struct PlanEligibilityBudgetClaimsV1<'plan> {
    budget: &'plan BudgetReservationV1,
}

impl fmt::Debug for PlanEligibilityBudgetClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlanEligibilityBudgetClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'plan> PlanEligibilityBudgetClaimsV1<'plan> {
    pub fn reservation_id(&self) -> &'plan str {
        self.budget.reservation_id.as_str()
    }

    pub fn currency_code(&self) -> &'plan str {
        &self.budget.currency_code
    }

    pub fn price_table_id(&self) -> &'plan str {
        self.budget.price_table_id.as_str()
    }

    pub const fn max_cost_micro_units(&self) -> u64 {
        self.budget.max_cost_micro_units.get()
    }

    pub const fn action_limit(&self) -> u64 {
        self.budget.action_limit.get()
    }

    pub const fn egress_bytes_limit(&self) -> u64 {
        self.budget.egress_bytes_limit.get()
    }
}

fn validate_media_type(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 127
        || !value.is_ascii()
        || !value.contains('/')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(ContractError::invalid(
            "intent.replacement.media_type",
            "must be a bounded ASCII media type without whitespace",
        ));
    }
    Ok(())
}
