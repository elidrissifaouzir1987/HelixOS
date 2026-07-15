use crate::canonical::{decode_canonical_value, require_closed_object, to_jcs_vec};
use crate::crypto::{
    decode_signature, encode_signature, signature_message, verify_receipt_signature,
    ReceiptKeyResolver, ReceiptSigner, VerificationKeyStatusV1,
};
use crate::grant::{AuthenticExecutionGrantV1, RetainedExecutionGrantEvidenceV1};
use crate::validation::{Generation, Identifier, SafeU64};
use crate::{ContractError, Result, Sha256Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"HELIXOS\0EXECUTION-RECEIPT\0V1\0";
const MAX_RECEIPT_WIRE_BYTES: usize = 65_536;

const OUTER_FIELDS: &[&str] = &["protected", "receipt_digest", "signature"];
const PROTECTED_FIELDS: &[&str] = &[
    "schema",
    "digest_algorithm",
    "signature_algorithm",
    "key_purpose",
    "key_id",
    "receipt_id",
    "grant_id",
    "grant_digest",
    "operation_id",
    "destination_adapter_id",
    "protocol_version",
    "adapter_root_id",
    "inbox_generation",
    "consumption_generation",
    "refusal_generation",
    "receipt_generation",
    "observed_boot_id",
    "observed_supervisor_epoch",
    "epoch_observer_generation",
    "decision",
    "refusal_code",
    "no_consumption_tombstone_digest",
    "decided_at_utc_ms",
    "decided_at_monotonic_ms",
    "trace_id",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionReceiptDecisionV1 {
    Consumed,
    RefusedDefinite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionReceiptRefusalCodeV1 {
    AdapterPaused,
    GrantExpired,
    SupervisorEpochMismatch,
}

/// Adapter-owned, typed input for one receipt decision.
///
/// It is non-wire and conveys no effect or execution capability.
pub struct ExecutionReceiptInputV1 {
    pub receipt_id: Sha256Digest,
    pub grant_id: Sha256Digest,
    pub grant_digest: Sha256Digest,
    pub operation_id: Identifier,
    pub destination_adapter_id: Identifier,
    pub adapter_root_id: Sha256Digest,
    pub inbox_generation: Generation,
    pub consumption_generation: Option<Generation>,
    pub refusal_generation: Option<Generation>,
    pub receipt_generation: Generation,
    pub observed_boot_id: Identifier,
    pub observed_supervisor_epoch: SafeU64,
    pub epoch_observer_generation: Generation,
    pub decision: ExecutionReceiptDecisionV1,
    pub refusal_code: Option<ExecutionReceiptRefusalCodeV1>,
    pub no_consumption_tombstone_digest: Option<Sha256Digest>,
    pub decided_at_utc_ms: SafeU64,
    pub decided_at_monotonic_ms: SafeU64,
    pub trace_id: Identifier,
}

impl fmt::Debug for ExecutionReceiptInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReceiptInputV1")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceiptProtectedV1 {
    schema: String,
    digest_algorithm: String,
    signature_algorithm: String,
    key_purpose: String,
    key_id: Identifier,
    receipt_id: Sha256Digest,
    grant_id: Sha256Digest,
    grant_digest: Sha256Digest,
    operation_id: Identifier,
    destination_adapter_id: Identifier,
    protocol_version: u8,
    adapter_root_id: Sha256Digest,
    inbox_generation: Generation,
    consumption_generation: Option<Generation>,
    refusal_generation: Option<Generation>,
    receipt_generation: Generation,
    observed_boot_id: Identifier,
    observed_supervisor_epoch: SafeU64,
    epoch_observer_generation: Generation,
    decision: ExecutionReceiptDecisionV1,
    refusal_code: Option<ExecutionReceiptRefusalCodeV1>,
    no_consumption_tombstone_digest: Option<Sha256Digest>,
    decided_at_utc_ms: SafeU64,
    decided_at_monotonic_ms: SafeU64,
    trace_id: Identifier,
}

impl fmt::Debug for ExecutionReceiptProtectedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReceiptProtectedV1")
            .finish_non_exhaustive()
    }
}

impl ExecutionReceiptProtectedV1 {
    pub fn try_new(input: ExecutionReceiptInputV1, key_id: Identifier) -> Result<Self> {
        let value = Self {
            schema: "helixos.execution-receipt/1".to_owned(),
            digest_algorithm: "sha-256".to_owned(),
            signature_algorithm: "ed25519".to_owned(),
            key_purpose: "adapter-receipt-signing".to_owned(),
            key_id,
            receipt_id: input.receipt_id,
            grant_id: input.grant_id,
            grant_digest: input.grant_digest,
            operation_id: input.operation_id,
            destination_adapter_id: input.destination_adapter_id,
            protocol_version: 1,
            adapter_root_id: input.adapter_root_id,
            inbox_generation: input.inbox_generation,
            consumption_generation: input.consumption_generation,
            refusal_generation: input.refusal_generation,
            receipt_generation: input.receipt_generation,
            observed_boot_id: input.observed_boot_id,
            observed_supervisor_epoch: input.observed_supervisor_epoch,
            epoch_observer_generation: input.epoch_observer_generation,
            decision: input.decision,
            refusal_code: input.refusal_code,
            no_consumption_tombstone_digest: input.no_consumption_tombstone_digest,
            decided_at_utc_ms: input.decided_at_utc_ms,
            decided_at_monotonic_ms: input.decided_at_monotonic_ms,
            trace_id: input.trace_id,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "helixos.execution-receipt/1" {
            return Err(ContractError::UnsupportedSchema);
        }
        if self.digest_algorithm != "sha-256" {
            return Err(ContractError::UnsupportedDigestAlgorithm);
        }
        if self.signature_algorithm != "ed25519" {
            return Err(ContractError::UnsupportedSignatureAlgorithm);
        }
        if self.key_purpose != "adapter-receipt-signing" {
            return Err(ContractError::WrongKeyPurpose);
        }
        if self.protocol_version != 1 {
            return Err(ContractError::UnsupportedProtocol);
        }
        let valid_shape = match self.decision {
            ExecutionReceiptDecisionV1::Consumed => {
                self.consumption_generation.is_some()
                    && self.refusal_generation.is_none()
                    && self.refusal_code.is_none()
                    && self.no_consumption_tombstone_digest.is_none()
            }
            ExecutionReceiptDecisionV1::RefusedDefinite => {
                self.consumption_generation.is_none()
                    && self.refusal_generation.is_some()
                    && self.refusal_code.is_some()
                    && self.no_consumption_tombstone_digest.is_some()
            }
        };
        if !valid_shape {
            return Err(ContractError::InvalidDecisionShape);
        }
        let decision_generation = match self.decision {
            ExecutionReceiptDecisionV1::Consumed => self.consumption_generation,
            ExecutionReceiptDecisionV1::RefusedDefinite => self.refusal_generation,
        }
        .ok_or(ContractError::InvalidDecisionShape)?;
        if self.inbox_generation.get() >= decision_generation.get()
            || decision_generation.get() >= self.receipt_generation.get()
        {
            return Err(ContractError::InvalidField);
        }
        Ok(())
    }

    pub fn key_id(&self) -> &str {
        self.key_id.as_str()
    }

    pub const fn decision(&self) -> ExecutionReceiptDecisionV1 {
        self.decision
    }

    pub const fn refusal_code(&self) -> Option<ExecutionReceiptRefusalCodeV1> {
        self.refusal_code
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionReceiptV1 {
    protected: ExecutionReceiptProtectedV1,
    receipt_digest: Sha256Digest,
    signature: String,
}

impl fmt::Debug for SignedExecutionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedExecutionReceiptV1")
            .finish_non_exhaustive()
    }
}

impl SignedExecutionReceiptV1 {
    pub fn protected(&self) -> &ExecutionReceiptProtectedV1 {
        &self.protected
    }

    pub const fn receipt_digest(&self) -> Sha256Digest {
        self.receipt_digest
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        self.protected.validate()?;
        to_jcs_vec(self)
    }
}

/// Verification result for retained receipt evidence.
///
/// This type intentionally has no execution, renewal, or handoff capability.
pub struct AuthenticExecutionReceiptV1 {
    signed: SignedExecutionReceiptV1,
    verified_key_fingerprint: Sha256Digest,
    verification_key_status: VerificationKeyStatusV1,
}

impl fmt::Debug for AuthenticExecutionReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticExecutionReceiptV1")
            .finish_non_exhaustive()
    }
}

impl AuthenticExecutionReceiptV1 {
    pub fn protected(&self) -> &ExecutionReceiptProtectedV1 {
        &self.signed.protected
    }

    pub fn claims(&self) -> ExecutionReceiptClaimsV1<'_> {
        ExecutionReceiptClaimsV1 { receipt: self }
    }

    pub const fn receipt_digest(&self) -> Sha256Digest {
        self.signed.receipt_digest
    }

    pub const fn verified_key_fingerprint(&self) -> Sha256Digest {
        self.verified_key_fingerprint
    }

    pub const fn verification_key_status(&self) -> VerificationKeyStatusV1 {
        self.verification_key_status
    }

    pub fn canonical_signed_envelope_bytes(&self) -> Result<Vec<u8>> {
        self.signed.to_canonical_json()
    }
}

/// Read-only decision and durable bindings from a verified receipt evidence value.
#[derive(Clone, Copy)]
pub struct ExecutionReceiptClaimsV1<'receipt> {
    receipt: &'receipt AuthenticExecutionReceiptV1,
}

impl fmt::Debug for ExecutionReceiptClaimsV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReceiptClaimsV1")
            .finish_non_exhaustive()
    }
}

impl<'receipt> ExecutionReceiptClaimsV1<'receipt> {
    fn protected(&self) -> &'receipt ExecutionReceiptProtectedV1 {
        &self.receipt.signed.protected
    }

    pub const fn schema(&self) -> &'static str {
        "helixos.execution-receipt/1"
    }

    pub const fn digest_algorithm(&self) -> &'static str {
        "sha-256"
    }

    pub const fn signature_algorithm(&self) -> &'static str {
        "ed25519"
    }

    pub const fn key_purpose(&self) -> &'static str {
        "adapter-receipt-signing"
    }

    pub fn key_id(&self) -> &'receipt str {
        self.protected().key_id.as_str()
    }

    pub const fn receipt_id(&self) -> Sha256Digest {
        self.receipt.signed.protected.receipt_id
    }

    pub const fn receipt_digest(&self) -> Sha256Digest {
        self.receipt.signed.receipt_digest
    }

    pub const fn grant_id(&self) -> Sha256Digest {
        self.receipt.signed.protected.grant_id
    }

    pub const fn grant_digest(&self) -> Sha256Digest {
        self.receipt.signed.protected.grant_digest
    }

    pub fn operation_id(&self) -> &'receipt str {
        self.protected().operation_id.as_str()
    }

    pub fn destination_adapter_id(&self) -> &'receipt str {
        self.protected().destination_adapter_id.as_str()
    }

    pub const fn protocol_version(&self) -> u8 {
        self.receipt.signed.protected.protocol_version
    }

    pub const fn adapter_root_id(&self) -> Sha256Digest {
        self.receipt.signed.protected.adapter_root_id
    }

    pub const fn inbox_generation(&self) -> u64 {
        self.receipt.signed.protected.inbox_generation.get()
    }

    pub const fn consumption_generation(&self) -> Option<u64> {
        match self.receipt.signed.protected.consumption_generation {
            Some(value) => Some(value.get()),
            None => None,
        }
    }

    pub const fn refusal_generation(&self) -> Option<u64> {
        match self.receipt.signed.protected.refusal_generation {
            Some(value) => Some(value.get()),
            None => None,
        }
    }

    pub const fn receipt_generation(&self) -> u64 {
        self.receipt.signed.protected.receipt_generation.get()
    }

    pub fn observed_boot_id(&self) -> &'receipt str {
        self.protected().observed_boot_id.as_str()
    }

    pub const fn observed_supervisor_epoch(&self) -> u64 {
        self.receipt
            .signed
            .protected
            .observed_supervisor_epoch
            .get()
    }

    pub const fn epoch_observer_generation(&self) -> u64 {
        self.receipt
            .signed
            .protected
            .epoch_observer_generation
            .get()
    }

    pub const fn decision(&self) -> ExecutionReceiptDecisionV1 {
        self.receipt.signed.protected.decision
    }

    pub const fn refusal_code(&self) -> Option<ExecutionReceiptRefusalCodeV1> {
        self.receipt.signed.protected.refusal_code
    }

    pub const fn no_consumption_tombstone_digest(&self) -> Option<Sha256Digest> {
        self.receipt
            .signed
            .protected
            .no_consumption_tombstone_digest
    }

    pub const fn decided_at_utc_ms(&self) -> u64 {
        self.receipt.signed.protected.decided_at_utc_ms.get()
    }

    pub const fn decided_at_monotonic_ms(&self) -> u64 {
        self.receipt.signed.protected.decided_at_monotonic_ms.get()
    }

    pub fn trace_id(&self) -> &'receipt str {
        self.protected().trace_id.as_str()
    }
}

/// Exact retained grant bindings against which a receipt is evidence-verified.
///
/// The receipt validates its internal `inbox < decision < receipt` generation order
/// here. Attestation that those generations equal independently retained adapter-store
/// rows remains the inbox store's trust-domain responsibility; this wire crate never
/// treats self-asserted receipt generations as store authority.
pub struct ReceiptVerificationBindingsV1 {
    grant_id: Sha256Digest,
    grant_digest: Sha256Digest,
    operation_id: Box<str>,
    destination_adapter_id: Box<str>,
    protocol_version: u8,
    boot_id: Box<str>,
    supervisor_epoch: u64,
    issued_at_monotonic_ms: u64,
    deadline_monotonic_ms: u64,
    adapter_root_id: Sha256Digest,
}

impl fmt::Debug for ReceiptVerificationBindingsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiptVerificationBindingsV1")
            .finish_non_exhaustive()
    }
}

impl ReceiptVerificationBindingsV1 {
    pub fn new(grant: &AuthenticExecutionGrantV1, adapter_root_id: Sha256Digest) -> Self {
        Self::from_current_grant(grant, adapter_root_id)
    }

    pub fn from_current_grant(
        grant: &AuthenticExecutionGrantV1,
        adapter_root_id: Sha256Digest,
    ) -> Self {
        let claims = grant.claims();
        Self {
            grant_id: claims.grant_id(),
            grant_digest: claims.grant_digest(),
            operation_id: Box::from(claims.operation_id()),
            destination_adapter_id: Box::from(claims.destination_adapter_id()),
            protocol_version: claims.protocol_version(),
            boot_id: Box::from(claims.boot_id()),
            supervisor_epoch: claims.supervisor_epoch(),
            issued_at_monotonic_ms: claims.issued_at_monotonic_ms(),
            deadline_monotonic_ms: claims.deadline_monotonic_ms(),
            adapter_root_id,
        }
    }

    pub fn from_retained_grant_evidence(
        grant: &RetainedExecutionGrantEvidenceV1,
        adapter_root_id: Sha256Digest,
    ) -> Self {
        let claims = grant.claims();
        Self {
            grant_id: claims.grant_id(),
            grant_digest: claims.grant_digest(),
            operation_id: Box::from(claims.operation_id()),
            destination_adapter_id: Box::from(claims.destination_adapter_id()),
            protocol_version: claims.protocol_version(),
            boot_id: Box::from(claims.boot_id()),
            supervisor_epoch: claims.supervisor_epoch(),
            issued_at_monotonic_ms: claims.issued_at_monotonic_ms(),
            deadline_monotonic_ms: claims.deadline_monotonic_ms(),
            adapter_root_id,
        }
    }
}

pub fn sign_execution_receipt_v1<S: ReceiptSigner>(
    protected: ExecutionReceiptProtectedV1,
    signer: &S,
) -> Result<SignedExecutionReceiptV1> {
    protected.validate()?;
    if protected.key_id() != signer.key_id() {
        return Err(ContractError::WrongKeyPurpose);
    }
    let protected_bytes = to_jcs_vec(&protected)?;
    let receipt_digest = Sha256Digest::digest(&protected_bytes);
    let signature = signer
        .sign_execution_receipt(&signature_message(
            RECEIPT_SIGNATURE_DOMAIN,
            &protected_bytes,
        ))
        .map_err(|_| ContractError::SigningFailed)?;
    Ok(SignedExecutionReceiptV1 {
        protected,
        receipt_digest,
        signature: encode_signature(signature),
    })
}

pub fn decode_and_verify_execution_receipt_v1<R: ReceiptKeyResolver>(
    wire: &[u8],
    resolver: &R,
    bindings: &ReceiptVerificationBindingsV1,
) -> Result<AuthenticExecutionReceiptV1> {
    let value = decode_canonical_value(wire, MAX_RECEIPT_WIRE_BYTES)?;
    preflight_receipt(&value, bindings)?;
    let signed: SignedExecutionReceiptV1 =
        serde_json::from_value(value).map_err(|_| ContractError::InvalidField)?;
    signed.protected.validate()?;
    validate_bindings(&signed.protected, bindings)?;
    let protected_bytes = to_jcs_vec(&signed.protected)?;
    if Sha256Digest::digest(&protected_bytes) != signed.receipt_digest {
        return Err(ContractError::DigestMismatch);
    }
    decode_signature(&signed.signature)?;
    let key = resolver.resolve_receipt_key(signed.protected.key_id())?;
    let (verified_key_fingerprint, verification_key_status) = verify_receipt_signature(
        &signed.signature,
        &signature_message(RECEIPT_SIGNATURE_DOMAIN, &protected_bytes),
        key,
    )?;
    Ok(AuthenticExecutionReceiptV1 {
        signed,
        verified_key_fingerprint,
        verification_key_status,
    })
}

fn preflight_receipt(value: &Value, bindings: &ReceiptVerificationBindingsV1) -> Result<()> {
    require_closed_object(value, OUTER_FIELDS, true)?;
    let protected = value
        .get("protected")
        .ok_or(ContractError::MissingOuterField)?;
    require_closed_object(protected, PROTECTED_FIELDS, false)?;
    match protected.get("schema").and_then(Value::as_str) {
        Some("helixos.execution-receipt/1") => {}
        Some(_) => return Err(ContractError::UnsupportedSchema),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("digest_algorithm").and_then(Value::as_str) {
        Some("sha-256") => {}
        Some(_) => return Err(ContractError::UnsupportedDigestAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("signature_algorithm").and_then(Value::as_str) {
        Some("ed25519") => {}
        Some(_) => return Err(ContractError::UnsupportedSignatureAlgorithm),
        None => return Err(ContractError::InvalidField),
    }
    match protected.get("key_purpose").and_then(Value::as_str) {
        Some("adapter-receipt-signing") => {}
        Some(_) => return Err(ContractError::WrongKeyPurpose),
        None => return Err(ContractError::InvalidField),
    }
    if protected.get("protocol_version").and_then(Value::as_u64) != Some(1) {
        return Err(ContractError::UnsupportedProtocol);
    }
    match protected.get("decision").and_then(Value::as_str) {
        Some("CONSUMED" | "REFUSED_DEFINITE") => {}
        Some(_) => return Err(ContractError::UnknownDecision),
        None => return Err(ContractError::InvalidField),
    }
    if let Some(code) = protected.get("refusal_code").and_then(Value::as_str) {
        match code {
            "GRANT_EXPIRED" | "SUPERVISOR_EPOCH_MISMATCH" | "ADAPTER_PAUSED" => {}
            "DESTINATION_MISMATCH"
            | "PROTOCOL_UNSUPPORTED"
            | "CAPABILITY_MISMATCH"
            | "INBOX_CAPACITY_EXHAUSTED" => return Err(ContractError::PreReceivedCodeNotReceipt),
            _ => return Err(ContractError::InvalidDecisionShape),
        }
    }
    let decision = protected
        .get("decision")
        .and_then(Value::as_str)
        .ok_or(ContractError::InvalidDecisionShape)?;
    let has_consumption = protected
        .get("consumption_generation")
        .is_some_and(Value::is_number);
    let has_refusal = protected
        .get("refusal_generation")
        .is_some_and(Value::is_number);
    let has_refusal_code = protected.get("refusal_code").is_some_and(Value::is_string);
    let has_tombstone = protected
        .get("no_consumption_tombstone_digest")
        .is_some_and(Value::is_string);
    let shape_is_valid = match decision {
        "CONSUMED" => has_consumption && !has_refusal && !has_refusal_code && !has_tombstone,
        "REFUSED_DEFINITE" => !has_consumption && has_refusal && has_refusal_code && has_tombstone,
        _ => false,
    };
    if !shape_is_valid {
        return Err(ContractError::InvalidDecisionShape);
    }
    validate_binding_values(protected, bindings)
}

fn validate_binding_values(
    protected: &Value,
    bindings: &ReceiptVerificationBindingsV1,
) -> Result<()> {
    if protected.get("grant_id").and_then(Value::as_str) != Some(&bindings.grant_id.to_hex())
        || protected.get("grant_digest").and_then(Value::as_str)
            != Some(&bindings.grant_digest.to_hex())
    {
        return Err(ContractError::GrantBindingMismatch);
    }
    if protected.get("operation_id").and_then(Value::as_str) != Some(&bindings.operation_id) {
        return Err(ContractError::OperationBindingMismatch);
    }
    if protected
        .get("destination_adapter_id")
        .and_then(Value::as_str)
        != Some(&bindings.destination_adapter_id)
    {
        return Err(ContractError::DestinationBindingMismatch);
    }
    if protected.get("adapter_root_id").and_then(Value::as_str)
        != Some(&bindings.adapter_root_id.to_hex())
    {
        return Err(ContractError::AdapterRootBindingMismatch);
    }
    let observed_supervisor_epoch = protected
        .get("observed_supervisor_epoch")
        .and_then(Value::as_u64)
        .ok_or(ContractError::InvalidField)?;
    let is_supervisor_mismatch_refusal = protected.get("decision").and_then(Value::as_str)
        == Some("REFUSED_DEFINITE")
        && protected.get("refusal_code").and_then(Value::as_str)
            == Some("SUPERVISOR_EPOCH_MISMATCH");
    let supervisor_binding_is_valid = if is_supervisor_mismatch_refusal {
        observed_supervisor_epoch != bindings.supervisor_epoch
    } else {
        observed_supervisor_epoch == bindings.supervisor_epoch
    };
    if !supervisor_binding_is_valid {
        return Err(ContractError::SupervisorEpochBindingMismatch);
    }
    Ok(())
}

fn validate_bindings(
    protected: &ExecutionReceiptProtectedV1,
    bindings: &ReceiptVerificationBindingsV1,
) -> Result<()> {
    if protected.grant_id != bindings.grant_id || protected.grant_digest != bindings.grant_digest {
        return Err(ContractError::GrantBindingMismatch);
    }
    if protected.operation_id.as_str() != &*bindings.operation_id {
        return Err(ContractError::OperationBindingMismatch);
    }
    if protected.destination_adapter_id.as_str() != &*bindings.destination_adapter_id {
        return Err(ContractError::DestinationBindingMismatch);
    }
    if protected.protocol_version != bindings.protocol_version {
        return Err(ContractError::UnsupportedProtocol);
    }
    if protected.adapter_root_id != bindings.adapter_root_id {
        return Err(ContractError::AdapterRootBindingMismatch);
    }
    if protected.observed_boot_id.as_str() != &*bindings.boot_id {
        return Err(ContractError::SupervisorEpochBindingMismatch);
    }
    if protected.decided_at_monotonic_ms.get() < bindings.issued_at_monotonic_ms {
        return Err(ContractError::GrantBindingMismatch);
    }
    let observed_epoch = protected.observed_supervisor_epoch.get();
    let grant_epoch = bindings.supervisor_epoch;
    match (protected.decision, protected.refusal_code) {
        (ExecutionReceiptDecisionV1::Consumed, None) => {
            if observed_epoch != grant_epoch
                || protected.decided_at_monotonic_ms.get() >= bindings.deadline_monotonic_ms
            {
                return Err(ContractError::GrantBindingMismatch);
            }
        }
        (
            ExecutionReceiptDecisionV1::RefusedDefinite,
            Some(ExecutionReceiptRefusalCodeV1::GrantExpired),
        ) => {
            if observed_epoch != grant_epoch
                || protected.decided_at_monotonic_ms.get() < bindings.deadline_monotonic_ms
            {
                return Err(ContractError::GrantBindingMismatch);
            }
        }
        (
            ExecutionReceiptDecisionV1::RefusedDefinite,
            Some(ExecutionReceiptRefusalCodeV1::SupervisorEpochMismatch),
        ) => {
            if observed_epoch == grant_epoch {
                return Err(ContractError::SupervisorEpochBindingMismatch);
            }
        }
        (
            ExecutionReceiptDecisionV1::RefusedDefinite,
            Some(ExecutionReceiptRefusalCodeV1::AdapterPaused),
        ) => {
            if observed_epoch != grant_epoch {
                return Err(ContractError::SupervisorEpochBindingMismatch);
            }
        }
        _ => return Err(ContractError::InvalidDecisionShape),
    }
    Ok(())
}
