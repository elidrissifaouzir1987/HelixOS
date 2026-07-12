//! Host-independent validation of the frozen Feature 004 conformance corpus.

use helix_contracts::{Sha256Digest, MAX_SAFE_U64};
use helix_plan_preparation::{AmbiguousPreparationV1, PreparationDenialV1, PreparationFailureV1};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const CASES_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/cases.json");
const EXPECTED_BYTES: &[u8] =
    include_bytes!("../../../contracts/fixtures/durable-preparation-v1/expected-outcomes.json");

const CASES_SCHEMA: &str = "helixos.durable-preparation-cases/1";
const SUMMARY_SCHEMA: &str = "helixos.durable-preparation-summary/1";
const CASES_SHA256: &str = "086ec8c5b7395d494b6140a7f24411e788beb6978598a28fc81588b75f29411d";
const EXPECTED_SHA256: &str = "87bd23eeed048fe47ca4f785d17cdca80364454bae30c81dc4b3e9e7ecf3ac2b";
const PACKAGE_BINDING_DOMAIN: &[u8] = b"HELIXOS\0RECOVERY-BACKUP-PACKAGE-BINDING\0V1\0";
const RESTORE_ATTEMPT_BINDING_DOMAIN: &[u8] = b"HELIXOS\0PREPARATION-RESTORE-ATTEMPT-BINDING\0V1\0";
const RESTORE_IDENTITY_DOMAIN: &[u8] = b"HELIXOS\0RESTORE-IDENTITY\0V1\0";
const EXPECTED_ROW_LEAVES: [u64; 45] = [
    5, 1, 2, 2, 7, 1, 2, 2, 1, 2, 1, 1, 3, 3, 2, 2, 3, 2, 4, 4, 7, 1, 5, 1, 3, 1, 6, 1, 1, 1, 7, 4,
    4, 6, 5, 9, 10, 3, 5, 1, 7, 1, 1, 1, 9,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusError {
    Invalid,
    NonCanonical,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseManifest {
    cases: Vec<Case>,
    counts: Counts,
    domain_encodings: DomainEncodings,
    fault_boundaries: Vec<FaultBoundary>,
    package_binding_kats: Vec<PackageBindingKat>,
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    case_id: String,
    case_kind: String,
    expected_code: String,
    expected_outcome: String,
    fault_phase: String,
    normative_row: u64,
    primary_fault: String,
    profile: String,
    secondary_fault: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    both_capture_leaf_count: u64,
    case_count: u64,
    fault_boundary_count: u64,
    fault_boundary_count_by_phase: BoundaryPhaseCounts,
    leaf_count: u64,
    leaf_count_by_normative_row: Vec<u64>,
    normative_row_count: u64,
    ordering_case_count: u64,
    package_binding_kat_count: u64,
    positive_control_case_count: u64,
    single_fault_case_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryPhaseCounts {
    #[serde(rename = "acknowledgement-and-readback")]
    acknowledgement_and_readback: u64,
    backup: u64,
    #[serde(rename = "final-comparison")]
    final_comparison: u64,
    #[serde(rename = "known-failure")]
    known_failure: u64,
    #[serde(rename = "positive-coordinator-commit")]
    positive_coordinator_commit: u64,
    preliminary: u64,
    #[serde(rename = "quarantine-and-retirement")]
    quarantine_and_retirement: u64,
    recovery: u64,
    restore: u64,
}

impl BoundaryPhaseCounts {
    fn as_map(&self) -> BTreeMap<&'static str, u64> {
        BTreeMap::from([
            (
                "acknowledgement-and-readback",
                self.acknowledgement_and_readback,
            ),
            ("backup", self.backup),
            ("final-comparison", self.final_comparison),
            ("known-failure", self.known_failure),
            (
                "positive-coordinator-commit",
                self.positive_coordinator_commit,
            ),
            ("preliminary", self.preliminary),
            ("quarantine-and-retirement", self.quarantine_and_retirement),
            ("recovery", self.recovery),
            ("restore", self.restore),
        ])
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainEncodings {
    detached_attestation: DetachedAttestationEncoding,
    jcs_sha256: JcsSha256Encoding,
    package_binding: PackageBindingEncoding,
    restore_attempt_binding: RestoreAttemptBindingEncoding,
    restore_identity: RestoreIdentityEncoding,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreAttemptBindingEncoding {
    at_rest_profile_id: String,
    digest_encoding: String,
    expected_preimage_length: u64,
    expected_sha256: String,
    field_order: Vec<String>,
    kat_input_digests_hex: Vec<String>,
    preimage_domain_utf8_hex: String,
    profile_length_encoding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreIdentityEncoding {
    attestation_sha256: String,
    expected_preimage_length: u64,
    expected_sha256: String,
    field_order: Vec<String>,
    preimage_domain_utf8_hex: String,
    restricted_attempt_nonce_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetachedAttestationEncoding {
    protected_encoding: String,
    signature_domain_utf8_hex: String,
    signature_input_order: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JcsSha256Encoding {
    digest_output: String,
    inventory_input: String,
    inventory_self_member: bool,
    top_level_input: String,
    top_level_self_member: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageBindingEncoding {
    digest_encoding: String,
    field_order: Vec<String>,
    optional_digest_none_hex: String,
    optional_digest_some_prefix_hex: String,
    package_binding_self_included: bool,
    preimage_domain_utf8_hex: String,
    safe_integer_max: u64,
    string_encoding: String,
    u64_encoding: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaultBoundary {
    boundary_id: String,
    expected_registry_occurrences: u64,
    multiplicity: String,
    order: u64,
    owner: String,
    phase: String,
    prepared_success_occurrences: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageBindingKat {
    at_rest_profile_id: String,
    custody: String,
    evidence_class: String,
    expected_package_binding_sha256: String,
    expected_preimage_hex: String,
    expected_preimage_length: u64,
    kat_id: String,
    manifest_sha256: String,
    material_length: u64,
    material_sha256: String,
    optional_retirement_encoding_hex: String,
    provider_generation: u64,
    provider_id: String,
    provider_profile_id: String,
    provider_profile_version: u64,
    reserved_capacity: u64,
    #[serde(default)]
    retirement_manifest_sha256: Option<String>,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedManifest {
    cases: Vec<ExpectedCase>,
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedCase {
    case_id: String,
    code: String,
    event_generation_delta: String,
    operation_generation_delta: String,
    outcome: String,
    recovery_may_remain_quarantined: bool,
    recovery_provider_calls: ProviderCalls,
    replay_claim_released: bool,
    reservation_generation_delta: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderCalls {
    acquire: u64,
    prepare: u64,
    total: u64,
    verify: u64,
}

fn parse_cases(bytes: &[u8]) -> Result<CaseManifest, CorpusError> {
    let manifest: CaseManifest = serde_json::from_slice(bytes).map_err(|_| CorpusError::Invalid)?;
    validate_case_manifest(&manifest)?;
    require_jcs(bytes)?;
    Ok(manifest)
}

fn parse_expected(bytes: &[u8]) -> Result<ExpectedManifest, CorpusError> {
    let manifest: ExpectedManifest =
        serde_json::from_slice(bytes).map_err(|_| CorpusError::Invalid)?;
    validate_expected_manifest(&manifest)?;
    require_jcs(bytes)?;
    Ok(manifest)
}

fn require_jcs(bytes: &[u8]) -> Result<(), CorpusError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| CorpusError::Invalid)?;
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(|_| CorpusError::Invalid)?;
    if canonical != bytes {
        return Err(CorpusError::NonCanonical);
    }
    Ok(())
}

fn validate_case_manifest(manifest: &CaseManifest) -> Result<(), CorpusError> {
    if manifest.schema != CASES_SCHEMA || manifest.cases.len() != 335 {
        return Err(CorpusError::Invalid);
    }
    let allowed_kinds = BTreeSet::from(["ordering", "positive-control", "single-fault"]);
    let allowed_outcomes = BTreeSet::from(["ambiguous", "denied", "failed", "prepared"]);
    let allowed_phases = BTreeSet::from([
        "final",
        "positive",
        "preliminary",
        "readback",
        "recovery",
        "store",
    ]);
    let allowed_profiles =
        BTreeSet::from(["synthetic-compensable-v1", "synthetic-irreversible-v1"]);
    let allowed_codes = closed_public_codes();
    let mut prior = None;
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        if !valid_kebab(&case.case_id)
            || !valid_kebab(&case.primary_fault)
            || !valid_kebab(&case.secondary_fault)
            || !allowed_kinds.contains(case.case_kind.as_str())
            || !allowed_outcomes.contains(case.expected_outcome.as_str())
            || !allowed_phases.contains(case.fault_phase.as_str())
            || !allowed_profiles.contains(case.profile.as_str())
            || !allowed_codes.contains(case.expected_code.as_str())
            || !ids.insert(case.case_id.as_str())
            || prior.is_some_and(|value| value >= case.case_id.as_str())
        {
            return Err(CorpusError::Invalid);
        }
        match case.case_kind.as_str() {
            "positive-control"
                if case.normative_row == 0
                    && case.fault_phase == "positive"
                    && case.expected_code == "NONE"
                    && case.expected_outcome == "prepared"
                    && case.secondary_fault == "none" => {}
            "single-fault"
                if (1..=45).contains(&case.normative_row)
                    && case.primary_fault != "none"
                    && case.secondary_fault == "none" => {}
            "ordering"
                if (1..=45).contains(&case.normative_row)
                    && case.primary_fault != "none"
                    && case.secondary_fault != "none" => {}
            _ => return Err(CorpusError::Invalid),
        }
        prior = Some(case.case_id.as_str());
    }
    validate_counts(manifest)?;
    validate_domains(&manifest.domain_encodings)?;
    validate_boundaries(manifest)?;
    for kat in &manifest.package_binding_kats {
        validate_kat(kat)?;
    }
    Ok(())
}

fn closed_public_codes() -> BTreeSet<&'static str> {
    let mut codes = PreparationDenialV1::ALL
        .iter()
        .map(|value| value.code())
        .chain(PreparationFailureV1::ALL.iter().map(|value| value.code()))
        .collect::<BTreeSet<_>>();
    codes.insert(AmbiguousPreparationV1::ALL[0].code());
    codes.insert("NONE");
    codes
}

fn validate_counts(manifest: &CaseManifest) -> Result<(), CorpusError> {
    let counts = &manifest.counts;
    if counts.case_count != 335
        || counts.leaf_count != 150
        || counts.both_capture_leaf_count != 91
        || counts.normative_row_count != 45
        || counts.positive_control_case_count != 3
        || counts.single_fault_case_count != 241
        || counts.ordering_case_count != 91
        || counts.package_binding_kat_count != 2
        || counts.fault_boundary_count != 123
        || counts.leaf_count_by_normative_row != EXPECTED_ROW_LEAVES
    {
        return Err(CorpusError::Invalid);
    }

    let mut kinds = BTreeMap::<&str, u64>::new();
    let mut leaves_by_row = vec![BTreeSet::<&str>::new(); 45];
    let mut phases_by_leaf = BTreeMap::<(u64, &str), BTreeSet<&str>>::new();
    let mut ordering_leaves = BTreeSet::new();
    for case in &manifest.cases {
        *kinds.entry(case.case_kind.as_str()).or_default() += 1;
        if case.normative_row != 0 {
            leaves_by_row
                [usize::try_from(case.normative_row - 1).map_err(|_| CorpusError::Invalid)?]
            .insert(case.primary_fault.as_str());
        }
        if case.case_kind == "single-fault" {
            phases_by_leaf
                .entry((case.normative_row, case.primary_fault.as_str()))
                .or_default()
                .insert(case.fault_phase.as_str());
        } else if case.case_kind == "ordering" {
            ordering_leaves.insert((case.normative_row, case.primary_fault.as_str()));
        }
    }
    if kinds
        != BTreeMap::from([
            ("ordering", 91),
            ("positive-control", 3),
            ("single-fault", 241),
        ])
    {
        return Err(CorpusError::Invalid);
    }
    let actual_row_leaves = leaves_by_row
        .iter()
        .map(|row| u64::try_from(row.len()).map_err(|_| CorpusError::Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    if actual_row_leaves != EXPECTED_ROW_LEAVES {
        return Err(CorpusError::Invalid);
    }
    let double_capture = phases_by_leaf
        .iter()
        .filter_map(|(leaf, phases)| {
            (phases.contains("preliminary") && phases.contains("final")).then_some(*leaf)
        })
        .collect::<BTreeSet<_>>();
    if double_capture.len() != 91 || ordering_leaves != double_capture {
        return Err(CorpusError::Invalid);
    }
    Ok(())
}

fn validate_domains(domains: &DomainEncodings) -> Result<(), CorpusError> {
    let detached = &domains.detached_attestation;
    if detached.protected_encoding != "RFC8785_UTF8"
        || detached.signature_domain_utf8_hex
            != "48454c49584f53005052455041524154494f4e2d4241434b55502d4154544553544154494f4e00563100"
        || detached.signature_input_order != ["signature_domain_utf8", "protected_rfc8785_utf8"]
    {
        return Err(CorpusError::Invalid);
    }
    let jcs = &domains.jcs_sha256;
    if jcs.digest_output != "lowercase-sha256-hex"
        || jcs.inventory_input != "exact-rfc8785-utf8-complete-recovery-snapshot"
        || jcs.inventory_self_member
        || jcs.top_level_input != "exact-rfc8785-utf8-complete-preparation-backup"
        || jcs.top_level_self_member
    {
        return Err(CorpusError::Invalid);
    }
    let binding = &domains.package_binding;
    let expected_order = [
        "provider_profile_id",
        "provider_profile_version",
        "provider_id",
        "provider_generation",
        "evidence_class",
        "at_rest_profile_id",
        "custody",
        "state",
        "manifest_sha256",
        "material_sha256",
        "material_length",
        "reserved_capacity",
        "retirement_manifest_sha256",
    ];
    if binding.digest_encoding != "32-raw-octets-decoded-from-lowercase-sha256-hex"
        || binding
            .field_order
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_order
        || binding.optional_digest_none_hex != "00"
        || binding.optional_digest_some_prefix_hex != "01"
        || binding.package_binding_self_included
        || binding.preimage_domain_utf8_hex != hex_encode(PACKAGE_BINDING_DOMAIN)
        || binding.safe_integer_max != MAX_SAFE_U64
        || binding.string_encoding != "u16be-utf8-byte-length-then-utf8"
        || binding.u64_encoding != "exactly-eight-octet-unsigned-big-endian"
    {
        return Err(CorpusError::Invalid);
    }
    let attempt = &domains.restore_attempt_binding;
    let expected_attempt_order = [
        "attestation_sha256",
        "top_level_manifest_sha256",
        "inventory_sha256",
        "source_coordinator_root_identity_sha256",
        "source_recovery_root_identity_sha256",
        "source_instance_identity_sha256",
        "coordinator_schema_sha256",
        "coordinator_database_sha256",
        "coordinator_destination_reservation_sha256",
        "recovery_destination_reservation_sha256",
        "at_rest_profile_id",
    ];
    let mut attempt_preimage = RESTORE_ATTEMPT_BINDING_DOMAIN.to_vec();
    for digest in &attempt.kat_input_digests_hex {
        let bytes = hex_decode(digest)?;
        if bytes.len() != 32 {
            return Err(CorpusError::Invalid);
        }
        attempt_preimage.extend_from_slice(&bytes);
    }
    attempt_preimage.extend_from_slice(
        &u64::try_from(attempt.at_rest_profile_id.len())
            .map_err(|_| CorpusError::Invalid)?
            .to_be_bytes(),
    );
    attempt_preimage.extend_from_slice(attempt.at_rest_profile_id.as_bytes());
    if attempt.digest_encoding != "32-raw-octets-in-listed-order"
        || attempt
            .field_order
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_attempt_order
        || attempt.kat_input_digests_hex.len() != 10
        || attempt.preimage_domain_utf8_hex != hex_encode(RESTORE_ATTEMPT_BINDING_DOMAIN)
        || attempt.profile_length_encoding != "exactly-eight-octet-unsigned-big-endian"
        || u64::try_from(attempt_preimage.len()).ok() != Some(attempt.expected_preimage_length)
        || Sha256Digest::digest(&attempt_preimage).to_hex() != attempt.expected_sha256
    {
        return Err(CorpusError::Invalid);
    }
    let identity = &domains.restore_identity;
    let mut identity_preimage = RESTORE_IDENTITY_DOMAIN.to_vec();
    identity_preimage.extend_from_slice(&hex_decode(&identity.attestation_sha256)?);
    identity_preimage.extend_from_slice(&hex_decode(&identity.restricted_attempt_nonce_hex)?);
    if identity.field_order != ["attestation_sha256", "restricted_attempt_nonce"]
        || identity.preimage_domain_utf8_hex != hex_encode(RESTORE_IDENTITY_DOMAIN)
        || u64::try_from(identity_preimage.len()).ok() != Some(identity.expected_preimage_length)
        || Sha256Digest::digest(&identity_preimage).to_hex() != identity.expected_sha256
    {
        return Err(CorpusError::Invalid);
    }
    Ok(())
}

fn validate_boundaries(manifest: &CaseManifest) -> Result<(), CorpusError> {
    let allowed_multiplicities = BTreeSet::from([
        "commit-members",
        "final-groups",
        "final-guards",
        "material-packages",
        "preliminary-groups",
        "restore-packages",
        "retirement-tombstones",
        "unit",
    ]);
    let allowed_owners = BTreeSet::from(["coordinator", "portable"]);
    let expected_phases = BTreeMap::from([
        ("acknowledgement-and-readback", 12),
        ("backup", 23),
        ("final-comparison", 14),
        ("known-failure", 12),
        ("positive-coordinator-commit", 15),
        ("preliminary", 10),
        ("quarantine-and-retirement", 10),
        ("recovery", 13),
        ("restore", 14),
    ]);
    let mut phases = BTreeMap::<&str, u64>::new();
    let mut ids = BTreeSet::new();
    let mut success_count = 0_u64;
    for (index, boundary) in manifest.fault_boundaries.iter().enumerate() {
        if boundary.order != u64::try_from(index + 1).map_err(|_| CorpusError::Invalid)?
            || boundary.expected_registry_occurrences != 1
            || !valid_snake(&boundary.boundary_id)
            || !ids.insert(boundary.boundary_id.as_str())
            || !allowed_multiplicities.contains(boundary.multiplicity.as_str())
            || !allowed_owners.contains(boundary.owner.as_str())
            || !expected_phases.contains_key(boundary.phase.as_str())
        {
            return Err(CorpusError::Invalid);
        }
        *phases.entry(boundary.phase.as_str()).or_default() += 1;
        success_count = success_count
            .checked_add(boundary.prepared_success_occurrences)
            .ok_or(CorpusError::Invalid)?;
    }
    if phases != expected_phases
        || manifest.counts.fault_boundary_count_by_phase.as_map() != expected_phases
        || success_count != 93
    {
        return Err(CorpusError::Invalid);
    }
    Ok(())
}

fn validate_kat(kat: &PackageBindingKat) -> Result<(), CorpusError> {
    if kat.provider_profile_version > MAX_SAFE_U64
        || kat.provider_generation > MAX_SAFE_U64
        || kat.material_length > MAX_SAFE_U64
        || kat.reserved_capacity > MAX_SAFE_U64
        || kat.material_length > kat.reserved_capacity
    {
        return Err(CorpusError::Invalid);
    }
    let mut preimage = PACKAGE_BINDING_DOMAIN.to_vec();
    push_string(&mut preimage, &kat.provider_profile_id)?;
    preimage.extend_from_slice(&kat.provider_profile_version.to_be_bytes());
    push_string(&mut preimage, &kat.provider_id)?;
    preimage.extend_from_slice(&kat.provider_generation.to_be_bytes());
    push_string(&mut preimage, &kat.evidence_class)?;
    push_string(&mut preimage, &kat.at_rest_profile_id)?;
    push_string(&mut preimage, &kat.custody)?;
    push_string(&mut preimage, &kat.state)?;
    preimage.extend_from_slice(&decode_digest(&kat.manifest_sha256)?);
    preimage.extend_from_slice(&decode_digest(&kat.material_sha256)?);
    preimage.extend_from_slice(&kat.material_length.to_be_bytes());
    preimage.extend_from_slice(&kat.reserved_capacity.to_be_bytes());
    match &kat.retirement_manifest_sha256 {
        None => preimage.push(0),
        Some(digest) => {
            preimage.push(1);
            preimage.extend_from_slice(&decode_digest(digest)?);
        }
    }
    let expected_preimage = hex_decode(&kat.expected_preimage_hex)?;
    let optional_length = if kat.retirement_manifest_sha256.is_some() {
        33
    } else {
        1
    };
    if preimage != expected_preimage
        || preimage.len()
            != usize::try_from(kat.expected_preimage_length).map_err(|_| CorpusError::Invalid)?
        || kat.optional_retirement_encoding_hex
            != hex_encode(&preimage[preimage.len() - optional_length..])
        || Sha256Digest::digest(&preimage).to_hex() != kat.expected_package_binding_sha256
        || !valid_kebab(&kat.kat_id)
    {
        return Err(CorpusError::Invalid);
    }
    Ok(())
}

fn validate_expected_manifest(manifest: &ExpectedManifest) -> Result<(), CorpusError> {
    if manifest.schema != SUMMARY_SCHEMA || manifest.cases.len() != 335 {
        return Err(CorpusError::Invalid);
    }
    let allowed_outcomes = BTreeSet::from(["ambiguous", "denied", "failed", "prepared"]);
    let allowed_deltas = BTreeSet::from(["one", "zero", "zero-or-one"]);
    let allowed_codes = closed_public_codes();
    let mut prior = None;
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        if !valid_kebab(&case.case_id)
            || !ids.insert(case.case_id.as_str())
            || prior.is_some_and(|value| value >= case.case_id.as_str())
            || !allowed_codes.contains(case.code.as_str())
            || !allowed_outcomes.contains(case.outcome.as_str())
            || !allowed_deltas.contains(case.event_generation_delta.as_str())
            || !allowed_deltas.contains(case.operation_generation_delta.as_str())
            || !allowed_deltas.contains(case.reservation_generation_delta.as_str())
            || case.replay_claim_released
            || (case.recovery_provider_calls.total == 0 && case.recovery_may_remain_quarantined)
            || (case.outcome == "prepared" && case.recovery_may_remain_quarantined)
            || case.recovery_provider_calls.total
                != case
                    .recovery_provider_calls
                    .acquire
                    .checked_add(case.recovery_provider_calls.prepare)
                    .and_then(|sum| sum.checked_add(case.recovery_provider_calls.verify))
                    .ok_or(CorpusError::Invalid)?
        {
            return Err(CorpusError::Invalid);
        }
        prior = Some(case.case_id.as_str());
    }
    Ok(())
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), CorpusError> {
    let length = u16::try_from(value.len()).map_err(|_| CorpusError::Invalid)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32], CorpusError> {
    let digest = Sha256Digest::parse_hex(value).map_err(|_| CorpusError::Invalid)?;
    Ok(*digest.as_bytes())
}

fn hex_decode(value: &str) -> Result<Vec<u8>, CorpusError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CorpusError::Invalid);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(CorpusError::Invalid)?;
            let low = hex_nibble(pair[1]).ok_or(CorpusError::Invalid)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn valid_kebab(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && !value.ends_with('-')
        && !value.contains("--")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_snake(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('_')
        && !value.ends_with('_')
        && !value.contains("__")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[test]
fn frozen_bytes_are_strict_jcs_with_pinned_sha256() {
    let cases = parse_cases(CASES_BYTES).expect("the frozen cases corpus must be valid");
    let expected = parse_expected(EXPECTED_BYTES).expect("the frozen summary must be valid");
    assert_eq!(cases.schema, CASES_SCHEMA);
    assert_eq!(expected.schema, SUMMARY_SCHEMA);
    assert_eq!(Sha256Digest::digest(CASES_BYTES).to_hex(), CASES_SHA256);
    assert_eq!(
        Sha256Digest::digest(EXPECTED_BYTES).to_hex(),
        EXPECTED_SHA256
    );
}

#[test]
fn all_335_stable_case_projections_match_exactly() {
    let cases = parse_cases(CASES_BYTES).expect("the frozen cases corpus must be valid");
    let expected = parse_expected(EXPECTED_BYTES).expect("the frozen summary must be valid");
    assert_eq!(cases.cases.len(), 335);
    assert_eq!(expected.cases.len(), 335);
    for (case, projection) in cases.cases.iter().zip(&expected.cases) {
        assert_eq!(case.case_id, projection.case_id);
        assert_eq!(case.expected_code, projection.code);
        assert_eq!(case.expected_outcome, projection.outcome);
    }
}

#[test]
fn package_binding_known_answer_vectors_match_preimage_and_digest() {
    let cases = parse_cases(CASES_BYTES).expect("the frozen cases corpus must be valid");
    assert_eq!(cases.package_binding_kats.len(), 2);
    assert_eq!(
        cases
            .package_binding_kats
            .iter()
            .map(|kat| kat.kat_id.as_str())
            .collect::<Vec<_>>(),
        [
            "package-binding-material-present",
            "package-binding-retired-tombstone"
        ]
    );
}

#[test]
fn strict_decoder_rejects_duplicate_unknown_noncanonical_and_unsafe_input() {
    let cases = String::from_utf8(CASES_BYTES.to_vec()).expect("fixture must be UTF-8");
    let duplicate = cases.replacen("{\"cases\":", "{\"cases\":[],\"cases\":", 1);
    assert!(matches!(
        parse_cases(duplicate.as_bytes()),
        Err(CorpusError::Invalid)
    ));

    let unknown = cases.replacen("{\"cases\":", "{\"future\":0,\"cases\":", 1);
    assert!(matches!(
        parse_cases(unknown.as_bytes()),
        Err(CorpusError::Invalid)
    ));

    let nested_unknown = cases.replacen("{\"case_id\":", "{\"future\":0,\"case_id\":", 1);
    assert!(matches!(
        parse_cases(nested_unknown.as_bytes()),
        Err(CorpusError::Invalid)
    ));

    let unknown_token = cases.replacen("positive-control", "future-control", 1);
    assert!(matches!(
        parse_cases(unknown_token.as_bytes()),
        Err(CorpusError::Invalid)
    ));

    let unsafe_integer = cases.replacen(
        "\"provider_generation\":1",
        "\"provider_generation\":9007199254740992",
        1,
    );
    assert!(matches!(
        parse_cases(unsafe_integer.as_bytes()),
        Err(CorpusError::Invalid)
    ));

    let mut noncanonical = Vec::from(b" \n".as_slice());
    noncanonical.extend_from_slice(CASES_BYTES);
    assert!(matches!(
        parse_cases(&noncanonical),
        Err(CorpusError::NonCanonical)
    ));

    let expected = String::from_utf8(EXPECTED_BYTES.to_vec()).expect("fixture must be UTF-8");
    let duplicate_summary = expected.replacen("{\"cases\":", "{\"cases\":[],\"cases\":", 1);
    assert!(matches!(
        parse_expected(duplicate_summary.as_bytes()),
        Err(CorpusError::Invalid)
    ));
    let unknown_summary = expected.replacen("{\"cases\":", "{\"future\":0,\"cases\":", 1);
    assert!(matches!(
        parse_expected(unknown_summary.as_bytes()),
        Err(CorpusError::Invalid)
    ));
}
