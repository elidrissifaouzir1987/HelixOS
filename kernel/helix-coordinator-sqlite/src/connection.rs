//! Coordinator SQLite connection and durability-profile boundary.

use crate::clock::{remaining_monotonic_ms, CoordinatorMonotonicClockV1};
use crate::config::CoordinatorStoreConfigV1;
use crate::error::InternalCoordinatorError;
use crate::root_safety::{
    acquire_existing_root_lease, acquire_initialization_root_lease, CoordinatorRootIdentityV1,
    CoordinatorRootRoleV1, COORDINATOR_DATABASE_FILENAME, COORDINATOR_SHM_FILENAME,
    COORDINATOR_WAL_FILENAME, ROOT_LOCK_FILENAME,
};
use crate::schema::{self, InitializationCandidateV1, StoreSummary};
use helix_contracts::Ed25519KeyResolver;
use rusqlite::{Connection, Error as SqliteError, ErrorCode, OpenFlags};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

const MAX_SQLITE_BUSY_TIMEOUT_MS: u64 = i32::MAX as u64;

/// Closed, payload-free coordinator admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorStoreOpenErrorV1 {
    ClockUnavailable,
    DeadlineReached,
    RootInvalid,
    RootNotDedicated,
    RootRoleMismatch,
    RootIdentityMismatch,
    RootBusy,
    RootUnavailable,
    UnknownRootMember,
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
    RestorePending,
}

impl CoordinatorStoreOpenErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ClockUnavailable => "CLOCK_UNAVAILABLE",
            Self::DeadlineReached => "DEADLINE_REACHED",
            Self::RootInvalid => "ROOT_INVALID",
            Self::RootNotDedicated => "ROOT_NOT_DEDICATED",
            Self::RootRoleMismatch => "ROOT_ROLE_MISMATCH",
            Self::RootIdentityMismatch => "ROOT_IDENTITY_MISMATCH",
            Self::RootBusy => "ROOT_BUSY",
            Self::RootUnavailable => "ROOT_UNAVAILABLE",
            Self::UnknownRootMember => "UNKNOWN_ROOT_MEMBER",
            Self::ApplicationIdMismatch => "APPLICATION_ID_MISMATCH",
            Self::SchemaUnsupported => "SCHEMA_UNSUPPORTED",
            Self::SchemaInvalid => "SCHEMA_INVALID",
            Self::DurabilityProfileUnavailable => "DURABILITY_PROFILE_UNAVAILABLE",
            Self::IntegrityFailed => "INTEGRITY_FAILED",
            Self::InvariantFailed => "INVARIANT_FAILED",
            Self::RestorePending => "RESTORE_PENDING",
        }
    }

    pub(crate) const fn from_internal(error: InternalCoordinatorError) -> Self {
        match error {
            InternalCoordinatorError::ClockUnavailable => Self::ClockUnavailable,
            InternalCoordinatorError::DeadlineReached => Self::DeadlineReached,
            InternalCoordinatorError::RootInvalid => Self::RootInvalid,
            InternalCoordinatorError::RootNotDedicated => Self::RootNotDedicated,
            InternalCoordinatorError::RootRoleMismatch => Self::RootRoleMismatch,
            InternalCoordinatorError::RootIdentityMismatch => Self::RootIdentityMismatch,
            InternalCoordinatorError::RootBusy => Self::RootBusy,
            InternalCoordinatorError::RootUnavailable => Self::RootUnavailable,
            InternalCoordinatorError::UnknownRootMember => Self::UnknownRootMember,
            InternalCoordinatorError::ApplicationIdMismatch => Self::ApplicationIdMismatch,
            InternalCoordinatorError::SchemaUnsupported => Self::SchemaUnsupported,
            InternalCoordinatorError::SchemaInvalid => Self::SchemaInvalid,
            InternalCoordinatorError::DurabilityProfileUnavailable => {
                Self::DurabilityProfileUnavailable
            }
            InternalCoordinatorError::IntegrityFailed => Self::IntegrityFailed,
            InternalCoordinatorError::InvariantFailed
            | InternalCoordinatorError::JsonContractInvalid
            | InternalCoordinatorError::ProvenanceInvalid => Self::InvariantFailed,
            InternalCoordinatorError::RestorePending => Self::RestorePending,
        }
    }
}

impl fmt::Debug for CoordinatorStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Display for CoordinatorStoreOpenErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for CoordinatorStoreOpenErrorV1 {}

pub(crate) fn initialize_or_verify_store<C, R>(
    config: CoordinatorStoreConfigV1,
    clock: &C,
    historical_plan_keys: &R,
    deadline_monotonic_ms: u64,
) -> Result<
    (
        CoordinatorStoreConfigV1,
        StoreSummary,
        VerifiedStoreObserverV1,
    ),
    InternalCoordinatorError,
>
where
    C: CoordinatorMonotonicClockV1,
    R: Ed25519KeyResolver,
{
    if let Some(empty_root) = config.empty_root() {
        let mut root_lease = acquire_initialization_root_lease(
            empty_root,
            config.maximum_busy_wait_ms(),
            clock,
            deadline_monotonic_ms,
        )?;
        let root_identity = match root_lease.recovery_identity() {
            Some(identity) => identity,
            None => {
                let identity = generate_root_identity()?;
                // The identity-bearing marker is synchronized before the database path can exist.
                root_lease.begin_initialization(identity)?;
                identity
            }
        };
        let recovery_role = root_lease.recovery_role();
        let database_present = root_lease.database_present()?;
        let busy_timeout_ms = bounded_busy_timeout_ms(&config, clock, deadline_monotonic_ms)?;

        let (connection, summary) = if database_present {
            preflight_initialization_database_file(&config)?;
            let mut binding = bind_existing_database_file(&config)?;
            let mut connection = open_database(&config)?;
            configure_busy_timeout(&connection, busy_timeout_ms)?;
            match schema::classify_initialization_candidate(&connection)? {
                InitializationCandidateV1::ExactEmpty => {
                    if recovery_role == CoordinatorRootRoleV1::Existing {
                        // EXISTING is recoverable only as a fully committed publication. An empty
                        // database would otherwise turn the marker into content-based authority.
                        return Err(InternalCoordinatorError::SchemaInvalid);
                    }
                    configure_connection(&connection, busy_timeout_ms, true)?;
                    verify_existing_database_binding(&config, &mut binding)?;
                    schema::initialize_empty_to_v1(
                        &mut connection,
                        root_identity,
                        clock,
                        deadline_monotonic_ms,
                    )?;
                }
                InitializationCandidateV1::CommittedV1 => {
                    // A committed candidate is never adopted from its contents alone: full
                    // verification below must bind metadata to the durable marker identity.
                    configure_connection(&connection, busy_timeout_ms, false)?;
                }
            }
            verify_existing_database_binding(&config, &mut binding)?;
            verify_profile(&connection)?;
            let summary = schema::verify_full(&connection, root_identity, historical_plan_keys)?;
            verify_existing_database_binding(&config, &mut binding)?;
            (connection, summary)
        } else {
            if recovery_role == CoordinatorRootRoleV1::Existing {
                return Err(InternalCoordinatorError::RootRoleMismatch);
            }
            preflight_database_file(&config, true)?;
            let mut reservation = reserve_database_file_create_new(&config)?;
            prepare_reserved_database_for_sqlite(&config, &mut reservation)?;
            let mut connection = open_database(&config)?;
            configure_connection(&connection, busy_timeout_ms, true)?;
            verify_reserved_database_fingerprint(&config, &mut reservation)?;
            schema::initialize_empty_to_v1(
                &mut connection,
                root_identity,
                clock,
                deadline_monotonic_ms,
            )?;
            verify_reserved_database_fingerprint(&config, &mut reservation)?;
            verify_profile(&connection)?;
            let summary = schema::verify_full(&connection, root_identity, historical_plan_keys)?;
            verify_reserved_database_fingerprint(&config, &mut reservation)?;
            (connection, summary)
        };

        // The database entry must be durable before the marker can publish EXISTING. A crash
        // before this point leaves INITIALIZING and is therefore safely resumable.
        sync_root_directory_entry(config.root_path())?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        if root_lease
            .finalize_committed_initialization(root_identity)
            .is_err()
        {
            root_lease.finalize_committed_initialization(root_identity)?;
        }
        let existing_config = config.into_existing(root_identity)?;
        let observer = VerifiedStoreObserverV1::from_fully_verified(connection)?;
        return Ok((existing_config, summary, observer));
    }

    let existing_root = config
        .existing_root()
        .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
    let mut root_lease = acquire_existing_root_lease(
        existing_root,
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    let busy_timeout_ms = bounded_busy_timeout_ms(&config, clock, deadline_monotonic_ms)?;
    preflight_database_file(&config, false)?;
    let mut binding = bind_existing_database_file(&config)?;
    let connection = open_database(&config)?;
    configure_connection(&connection, busy_timeout_ms, false)?;
    verify_existing_database_binding(&config, &mut binding)?;
    let expected_identity = existing_root.expected_identity();
    let summary = schema::verify_full(&connection, expected_identity, historical_plan_keys)?;
    verify_existing_database_binding(&config, &mut binding)?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    let observer = VerifiedStoreObserverV1::from_fully_verified(connection)?;
    Ok((config, summary, observer))
}

/// Persistent observer for commits made outside one opened store instance.
///
/// SQLite's `data_version` changes on this connection only when another connection
/// commits. Ordinary coordinator mutations use short-lived bound connections, so the
/// store refreshes this baseline after its own acknowledged commit. Any other change
/// forces a new full historical verification before the fast operation proof can be
/// reused.
pub(crate) struct VerifiedStoreObserverV1 {
    connection: Connection,
    accepted_data_version: i64,
}

impl VerifiedStoreObserverV1 {
    fn from_fully_verified(connection: Connection) -> Result<Self, InternalCoordinatorError> {
        connection
            .pragma_update(None, "query_only", "ON")
            .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;
        let query_only: i64 = connection
            .pragma_query_value(None, "query_only", |row| row.get(0))
            .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;
        if query_only != 1 {
            return Err(InternalCoordinatorError::DurabilityProfileUnavailable);
        }
        let accepted_data_version = observed_data_version_v1(&connection)?;
        Ok(Self {
            connection,
            accepted_data_version,
        })
    }

    pub(crate) fn external_commit_observed_v1(&self) -> Result<bool, InternalCoordinatorError> {
        Ok(observed_data_version_v1(&self.connection)? != self.accepted_data_version)
    }

    pub(crate) fn accept_current_data_version_v1(
        &mut self,
    ) -> Result<(), InternalCoordinatorError> {
        self.accepted_data_version = observed_data_version_v1(&self.connection)?;
        Ok(())
    }
}

fn observed_data_version_v1(connection: &Connection) -> Result<i64, InternalCoordinatorError> {
    let version: i64 = connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))?;
    if version < 0 {
        return Err(InternalCoordinatorError::InvariantFailed);
    }
    Ok(version)
}

fn open_database(
    config: &CoordinatorStoreConfigV1,
) -> Result<Connection, InternalCoordinatorError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(config.database_path(), flags)
        .map_err(|error| map_sqlite_error(&error, InternalCoordinatorError::RootUnavailable))
}

/// One freshly opened coordinator connection held under the existing provisioner-
/// attested root lease and an exact database-file identity binding.
///
/// T037 keeps this custody alive through preflight, commit, or acknowledgement
/// readback. Full schema verification is deliberately left to the caller so readback
/// can run it inside the same `BEGIN IMMEDIATE` snapshot used for classification.
pub(crate) struct BoundCoordinatorConnectionV1 {
    config: CoordinatorStoreConfigV1,
    database_binding: BoundDatabaseFileV1,
    connection: Connection,
    expected_root_identity: CoordinatorRootIdentityV1,
    // Declared last so the exclusive root lock outlives SQLite and file bindings.
    root_lease: crate::root_safety::CoordinatorRootLeaseV1,
}

impl BoundCoordinatorConnectionV1 {
    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub(crate) const fn expected_root_identity(&self) -> CoordinatorRootIdentityV1 {
        self.expected_root_identity
    }

    /// Re-arms SQLite's process-local busy handler from the caller's remaining
    /// absolute deadline immediately before the next writer-acquisition attempt.
    ///
    /// Callers must invoke this after any potentially expensive verification and
    /// directly before `BEGIN IMMEDIATE`; the timeout established while opening the
    /// connection is not authority to wait against an older deadline sample.
    pub(crate) fn arm_next_writer_wait_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<u64, InternalCoordinatorError> {
        configure_deadline_bounded_busy_timeout_v1(
            &self.connection,
            self.config.maximum_busy_wait_ms(),
            clock,
            deadline_monotonic_ms,
        )
    }

    /// Rechecks directory, lock, database-file and absolute-deadline custody before
    /// the bound session is trusted after an operation.
    pub(crate) fn revalidate<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &mut self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<(), InternalCoordinatorError> {
        verify_existing_database_binding(&self.config, &mut self.database_binding)?;
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Existing)?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        Ok(())
    }
}

/// One root lease and one file-identity binding carrying the two SQLite sessions needed
/// by online backup.
///
/// The original bound source session supplies bytes to SQLite's backup API. The second
/// session exists only to retain `BEGIN IMMEDIATE` writer exclusion. Both are opened
/// from the same canonical coordinator path while the same root lease and held file
/// identity remain live, so hard links, cloned roots, and two independently leased
/// roots cannot split the byte source from the lock domain.
pub(crate) struct BoundCoordinatorBackupCustodyV1 {
    config: CoordinatorStoreConfigV1,
    database_binding: BoundDatabaseFileV1,
    expected_root_identity: CoordinatorRootIdentityV1,
    // Declared last so the exclusive root lock outlives the held file binding.
    root_lease: crate::root_safety::CoordinatorRootLeaseV1,
}

impl BoundCoordinatorBackupCustodyV1 {
    pub(crate) const fn expected_root_identity(&self) -> CoordinatorRootIdentityV1 {
        self.expected_root_identity
    }

    pub(crate) fn arm_writer_wait_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &self,
        writer_guard: &Connection,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<u64, InternalCoordinatorError> {
        configure_deadline_bounded_busy_timeout_v1(
            writer_guard,
            self.config.maximum_busy_wait_ms(),
            clock,
            deadline_monotonic_ms,
        )
    }

    pub(crate) fn revalidate<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &mut self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<(), InternalCoordinatorError> {
        verify_existing_database_binding(&self.config, &mut self.database_binding)?;
        self.root_lease
            .verify_role(CoordinatorRootRoleV1::Existing)?;
        remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
        Ok(())
    }
}

pub(crate) struct BoundCoordinatorBackupPairV1 {
    backup_source: Connection,
    writer_guard: Connection,
    // Declared last so the single root/file custody outlives both SQLite sessions.
    custody: BoundCoordinatorBackupCustodyV1,
}

impl BoundCoordinatorBackupPairV1 {
    pub(crate) fn parts_v1(
        &mut self,
    ) -> (
        &mut BoundCoordinatorBackupCustodyV1,
        &Connection,
        &mut Connection,
    ) {
        (
            &mut self.custody,
            &self.backup_source,
            &mut self.writer_guard,
        )
    }

    pub(crate) const fn expected_root_identity(&self) -> CoordinatorRootIdentityV1 {
        self.custody.expected_root_identity()
    }

    pub(crate) fn arm_writer_wait_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<u64, InternalCoordinatorError> {
        self.custody
            .arm_writer_wait_v1(&self.writer_guard, clock, deadline_monotonic_ms)
    }

    pub(crate) fn revalidate<C: CoordinatorMonotonicClockV1 + ?Sized>(
        &mut self,
        clock: &C,
        deadline_monotonic_ms: u64,
    ) -> Result<(), InternalCoordinatorError> {
        self.custody.revalidate(clock, deadline_monotonic_ms)
    }
}

impl fmt::Debug for BoundCoordinatorBackupPairV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundCoordinatorBackupPairV1")
            .finish_non_exhaustive()
    }
}

/// Opens an already initialized store without releasing its root/file custody.
///
/// This is the operation-level counterpart of `initialize_or_verify_store`: it
/// establishes the bounded busy timeout and exact WAL/FULL connection profile. The
/// store was fully verified at open; an ordinary operation revalidates the exact
/// ACTIVE header/schema-cookie proof in its own snapshot, while uncertain readback and
/// maintenance retain full historical verification.
pub(crate) fn open_bound_existing_connection<C: CoordinatorMonotonicClockV1 + ?Sized>(
    config: &CoordinatorStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<BoundCoordinatorConnectionV1, InternalCoordinatorError> {
    let existing_root = config
        .existing_root()
        .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
    let mut root_lease = acquire_existing_root_lease(
        existing_root,
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    let busy_timeout_ms = bounded_busy_timeout_ms(config, clock, deadline_monotonic_ms)?;
    preflight_database_file(config, false)?;
    let mut database_binding = bind_existing_database_file(config)?;
    let connection = open_database(config)?;
    configure_connection(&connection, busy_timeout_ms, false)?;
    verify_existing_database_binding(config, &mut database_binding)?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    let bound = BoundCoordinatorConnectionV1 {
        config: config.clone(),
        root_lease,
        database_binding,
        connection,
        expected_root_identity: existing_root.expected_identity(),
    };
    bound.arm_next_writer_wait_v1(clock, deadline_monotonic_ms)?;
    Ok(bound)
}

/// Opens the source/guard backup sessions under one indivisible root/file custody.
#[cfg_attr(not(feature = "test-fault-injection"), allow(dead_code))]
pub(crate) fn open_bound_backup_pair_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    config: &CoordinatorStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<BoundCoordinatorBackupPairV1, InternalCoordinatorError> {
    let existing_root = config
        .existing_root()
        .ok_or(InternalCoordinatorError::RootRoleMismatch)?;
    let mut root_lease = acquire_existing_root_lease(
        existing_root,
        config.maximum_busy_wait_ms(),
        clock,
        deadline_monotonic_ms,
    )?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    let busy_timeout_ms = bounded_busy_timeout_ms(config, clock, deadline_monotonic_ms)?;
    preflight_database_file(config, false)?;
    let mut database_binding = bind_existing_database_file(config)?;

    let backup_source = open_database(config)?;
    configure_connection(&backup_source, busy_timeout_ms, false)?;
    verify_existing_database_binding(config, &mut database_binding)?;

    let writer_guard = open_database(config)?;
    configure_connection(&writer_guard, busy_timeout_ms, false)?;
    verify_existing_database_binding(config, &mut database_binding)?;
    root_lease.verify_role(CoordinatorRootRoleV1::Existing)?;
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;

    let pair = BoundCoordinatorBackupPairV1 {
        backup_source,
        writer_guard,
        custody: BoundCoordinatorBackupCustodyV1 {
            config: config.clone(),
            database_binding,
            expected_root_identity: existing_root.expected_identity(),
            root_lease,
        },
    };
    pair.arm_writer_wait_v1(clock, deadline_monotonic_ms)?;
    Ok(pair)
}

struct ReservedDatabaseFileV1 {
    file: File,
    marker: [u8; 32],
    identity: FileIdentityV1,
}

struct BoundDatabaseFileV1 {
    file: File,
    identity: FileIdentityV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentityV1 {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: u128,
}

fn bind_existing_database_file(
    config: &CoordinatorStoreConfigV1,
) -> Result<BoundDatabaseFileV1, InternalCoordinatorError> {
    verify_reserved_root_members(config, true)?;
    let path = config.database_path();
    let before =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let identity = file_identity(
        &path,
        &file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    let after =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if after.file_type().is_symlink()
        || !after.is_file()
        || file_identity(&path, &before)? != identity
        || file_identity(&path, &after)? != identity
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(BoundDatabaseFileV1 { file, identity })
}

fn verify_existing_database_binding(
    config: &CoordinatorStoreConfigV1,
    binding: &mut BoundDatabaseFileV1,
) -> Result<(), InternalCoordinatorError> {
    verify_reserved_root_members(config, true)?;
    let path = config.database_path();
    let held_identity = file_identity(
        &path,
        &binding
            .file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || held_identity != binding.identity
        || file_identity(&path, &metadata)? != binding.identity
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn reserve_database_file_create_new(
    config: &CoordinatorStoreConfigV1,
) -> Result<ReservedDatabaseFileV1, InternalCoordinatorError> {
    let mut marker = [0_u8; 32];
    getrandom::fill(&mut marker).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let path = config.database_path();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                InternalCoordinatorError::RootRoleMismatch
            } else {
                InternalCoordinatorError::RootUnavailable
            }
        })?;
    file.write_all(&marker)
        .and_then(|()| file.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let identity = file_identity(
        &path,
        &file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    // Pair file-data durability with directory-entry durability before SQLite can commit state.
    // If this fails, the durable INITIALIZING marker remains the sole recovery authority.
    sync_root_directory_entry(config.root_path())?;
    Ok(ReservedDatabaseFileV1 {
        file,
        marker,
        identity,
    })
}

fn prepare_reserved_database_for_sqlite(
    config: &CoordinatorStoreConfigV1,
    reservation: &mut ReservedDatabaseFileV1,
) -> Result<(), InternalCoordinatorError> {
    verify_reserved_root_members(config, false)?;
    let (path_bytes, path_identity) = read_reserved_path(config)?;
    let path = config.database_path();
    if file_identity(
        &path,
        &reservation
            .file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )? != reservation.identity
        || path_identity != reservation.identity
        || read_exact_file(&mut reservation.file)? != reservation.marker
        || path_bytes != reservation.marker
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    reservation
        .file
        .set_len(0)
        .and_then(|()| reservation.file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|()| reservation.file.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let (path_bytes, path_identity) = read_reserved_path(config)?;
    if path_identity != reservation.identity
        || !read_exact_file(&mut reservation.file)?.is_empty()
        || !path_bytes.is_empty()
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    verify_reserved_root_members(config, false)
}

fn verify_reserved_database_fingerprint(
    config: &CoordinatorStoreConfigV1,
    reservation: &mut ReservedDatabaseFileV1,
) -> Result<(), InternalCoordinatorError> {
    verify_reserved_root_members(config, true)?;
    let held = read_exact_file(&mut reservation.file)?;
    let path = config.database_path();
    let held_identity = file_identity(
        &path,
        &reservation
            .file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    let (path, path_identity) = read_reserved_path(config)?;
    if held_identity != reservation.identity
        || path_identity != reservation.identity
        || held.is_empty()
        || held != path
    {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn read_exact_file(file: &mut File) -> Result<Vec<u8>, InternalCoordinatorError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    Ok(bytes)
}

fn read_reserved_path(
    config: &CoordinatorStoreConfigV1,
) -> Result<(Vec<u8>, FileIdentityV1), InternalCoordinatorError> {
    let path = config.database_path();
    let before =
        fs::symlink_metadata(&path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let identity = file_identity(
        &path,
        &file
            .metadata()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?,
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    let after =
        fs::symlink_metadata(path).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if after.file_type().is_symlink() || !after.is_file() || before.len() != after.len() {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok((bytes, identity))
}

#[cfg(unix)]
fn file_identity(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<FileIdentityV1, InternalCoordinatorError> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(FileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_identity(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<FileIdentityV1, InternalCoordinatorError> {
    match file_id::get_high_res_file_id(path)
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?
    {
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => Ok(FileIdentityV1 {
            volume_serial_number,
            file_id,
        }),
        file_id::FileId::Inode { .. } | file_id::FileId::LowRes { .. } => {
            Err(InternalCoordinatorError::RootUnavailable)
        }
    }
}

fn verify_reserved_root_members(
    config: &CoordinatorStoreConfigV1,
    sqlite_opened: bool,
) -> Result<(), InternalCoordinatorError> {
    let mut database_present = false;
    let mut lock_present = false;
    for entry in
        fs::read_dir(config.root_path()).map_err(|_| InternalCoordinatorError::RootUnavailable)?
    {
        let entry = entry.map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        let name = entry.file_name();
        let file_type = entry
            .file_type()
            .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
        if !file_type.is_file() {
            return Err(InternalCoordinatorError::RootNotDedicated);
        }
        if name == OsStr::new(COORDINATOR_DATABASE_FILENAME) {
            database_present = true;
        } else if name == OsStr::new(ROOT_LOCK_FILENAME) {
            lock_present = true;
        } else if !sqlite_opened
            || (name != OsStr::new(COORDINATOR_WAL_FILENAME)
                && name != OsStr::new(COORDINATOR_SHM_FILENAME))
        {
            return Err(InternalCoordinatorError::UnknownRootMember);
        }
    }
    if !database_present || !lock_present {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    Ok(())
}

fn preflight_database_file(
    config: &CoordinatorStoreConfigV1,
    must_be_absent: bool,
) -> Result<(), InternalCoordinatorError> {
    let metadata = match fs::symlink_metadata(config.database_path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && must_be_absent => {
            return Ok(())
        }
        Err(_) => return Err(InternalCoordinatorError::RootUnavailable),
    };
    if must_be_absent {
        return Err(InternalCoordinatorError::RootRoleMismatch);
    }
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(InternalCoordinatorError::SchemaInvalid);
    }
    Ok(())
}

fn preflight_initialization_database_file(
    config: &CoordinatorStoreConfigV1,
) -> Result<(), InternalCoordinatorError> {
    let metadata = fs::symlink_metadata(config.database_path())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InternalCoordinatorError::RootNotDedicated);
    }
    // A zero-length SQLite file is one exact-empty candidate. Classification after SQLite opens
    // still requires application_id=0, user_version=0, and zero non-internal schema objects.
    Ok(())
}

fn generate_root_identity() -> Result<CoordinatorRootIdentityV1, InternalCoordinatorError> {
    let mut identity = [0_u8; 32];
    getrandom::fill(&mut identity).map_err(|_| InternalCoordinatorError::RootUnavailable)?;
    Ok(CoordinatorRootIdentityV1::from_bytes(identity))
}

#[cfg(unix)]
fn sync_root_directory_entry(root: &std::path::Path) -> Result<(), InternalCoordinatorError> {
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| InternalCoordinatorError::RootUnavailable)
}

#[cfg(windows)]
fn sync_root_directory_entry(_root: &std::path::Path) -> Result<(), InternalCoordinatorError> {
    // Stable std cannot open a directory with FILE_FLAG_BACKUP_SEMANTICS without unsafe
    // platform bindings. The database file is still fully flushed and every path revalidation
    // uses the high-resolution Windows volume serial + 128-bit file ID. V1 does not promote this
    // to a directory-fsync or power-loss claim; Unix additionally synchronizes the directory.
    Ok(())
}

fn configure_connection(
    connection: &Connection,
    busy_timeout_ms: u64,
    establish_persistent_profile: bool,
) -> Result<(), InternalCoordinatorError> {
    configure_busy_timeout(connection, busy_timeout_ms)?;

    let journal_mode: String = if establish_persistent_profile {
        connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(|error| {
                map_sqlite_error(
                    &error,
                    InternalCoordinatorError::DurabilityProfileUnavailable,
                )
            })?
    } else {
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| {
                map_sqlite_error(
                    &error,
                    InternalCoordinatorError::DurabilityProfileUnavailable,
                )
            })?
    };
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(InternalCoordinatorError::DurabilityProfileUnavailable);
    }

    connection
        .pragma_update(None, "synchronous", "FULL")
        .and_then(|()| connection.pragma_update(None, "foreign_keys", "ON"))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .and_then(|()| connection.pragma_update(None, "cell_size_check", "ON"))
        .and_then(|()| connection.pragma_update(None, "recursive_triggers", "ON"))
        .and_then(|()| connection.pragma_update(None, "wal_autocheckpoint", 0_i64))
        .map_err(|error| {
            map_sqlite_error(
                &error,
                InternalCoordinatorError::DurabilityProfileUnavailable,
            )
        })?;
    verify_profile(connection)
}

fn configure_busy_timeout(
    connection: &Connection,
    busy_timeout_ms: u64,
) -> Result<(), InternalCoordinatorError> {
    connection
        .busy_timeout(Duration::from_millis(busy_timeout_ms))
        .map_err(|error| {
            map_sqlite_error(
                &error,
                InternalCoordinatorError::DurabilityProfileUnavailable,
            )
        })
}

fn verify_profile(connection: &Connection) -> Result<(), InternalCoordinatorError> {
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|error| {
            map_sqlite_error(
                &error,
                InternalCoordinatorError::DurabilityProfileUnavailable,
            )
        })?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || profile_pragma_i64(connection, "synchronous")? != 2
        || profile_pragma_i64(connection, "foreign_keys")? != 1
        || profile_pragma_i64(connection, "trusted_schema")? != 0
        || profile_pragma_i64(connection, "cell_size_check")? != 1
        || profile_pragma_i64(connection, "recursive_triggers")? != 1
        || profile_pragma_i64(connection, "wal_autocheckpoint")? != 0
    {
        return Err(InternalCoordinatorError::DurabilityProfileUnavailable);
    }
    Ok(())
}

fn profile_pragma_i64(
    connection: &Connection,
    pragma: &str,
) -> Result<i64, InternalCoordinatorError> {
    connection
        .pragma_query_value(None, pragma, |row| row.get(0))
        .map_err(|error| {
            map_sqlite_error(
                &error,
                InternalCoordinatorError::DurabilityProfileUnavailable,
            )
        })
}

fn bounded_busy_timeout_ms<C: CoordinatorMonotonicClockV1 + ?Sized>(
    config: &CoordinatorStoreConfigV1,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, InternalCoordinatorError> {
    bounded_busy_timeout_from_limit_v1(config.maximum_busy_wait_ms(), clock, deadline_monotonic_ms)
}

fn bounded_busy_timeout_from_limit_v1<C: CoordinatorMonotonicClockV1 + ?Sized>(
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, InternalCoordinatorError> {
    Ok(remaining_monotonic_ms(clock, deadline_monotonic_ms)?
        .min(maximum_busy_wait_ms)
        .clamp(1, MAX_SQLITE_BUSY_TIMEOUT_MS))
}

pub(crate) fn configure_deadline_bounded_busy_timeout_v1<
    C: CoordinatorMonotonicClockV1 + ?Sized,
>(
    connection: &Connection,
    maximum_busy_wait_ms: u64,
    clock: &C,
    deadline_monotonic_ms: u64,
) -> Result<u64, InternalCoordinatorError> {
    let busy_timeout_ms =
        bounded_busy_timeout_from_limit_v1(maximum_busy_wait_ms, clock, deadline_monotonic_ms)?;
    configure_busy_timeout(connection, busy_timeout_ms)?;
    // Setting the handler is not a successful admission result. Fail closed if the
    // exclusive deadline elapsed (or the clock disappeared) while it was armed.
    remaining_monotonic_ms(clock, deadline_monotonic_ms)?;
    Ok(busy_timeout_ms)
}

pub(crate) fn map_sqlite_error(
    error: &SqliteError,
    fallback: InternalCoordinatorError,
) -> InternalCoordinatorError {
    match error {
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase
            ) =>
        {
            InternalCoordinatorError::IntegrityFailed
        }
        SqliteError::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                ErrorCode::DatabaseBusy
                    | ErrorCode::DatabaseLocked
                    | ErrorCode::SchemaChanged
                    | ErrorCode::FileLockingProtocolFailed
            ) =>
        {
            InternalCoordinatorError::RootBusy
        }
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        bounded_busy_timeout_from_limit_v1, configure_connection,
        configure_deadline_bounded_busy_timeout_v1, generate_root_identity,
        initialize_or_verify_store, open_bound_backup_pair_v1, open_database,
        prepare_reserved_database_for_sqlite, profile_pragma_i64, read_exact_file,
        reserve_database_file_create_new, verify_reserved_database_fingerprint,
        MAX_SQLITE_BUSY_TIMEOUT_MS,
    };
    use crate::clock::CoordinatorMonotonicClockV1;
    use crate::config::CoordinatorStoreConfigV1;
    use crate::error::{CoordinatorClockUnavailableV1, InternalCoordinatorError};
    use crate::root_safety::{
        acquire_initialization_root_lease, reserve_empty_root, COORDINATOR_WAL_FILENAME,
    };
    use helix_contracts::{ContractError, Ed25519KeyResolver};
    use rusqlite::config::DbConfig;
    use std::fs::{self, File};
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    struct FixedClock;

    struct ValueClock {
        now: Option<u64>,
    }

    struct AdvancingClock {
        first: u64,
        later: u64,
        samples: AtomicUsize,
    }

    struct NoHistoricalKeys;

    impl CoordinatorMonotonicClockV1 for FixedClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            Ok(1)
        }
    }

    impl CoordinatorMonotonicClockV1 for ValueClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            self.now.ok_or_else(CoordinatorClockUnavailableV1::new)
        }
    }

    impl CoordinatorMonotonicClockV1 for AdvancingClock {
        fn now_monotonic_ms(&self) -> Result<u64, CoordinatorClockUnavailableV1> {
            let sample = self.samples.fetch_add(1, Ordering::Relaxed);
            Ok(if sample == 0 { self.first } else { self.later })
        }
    }

    impl Ed25519KeyResolver for NoHistoricalKeys {
        fn resolve_ed25519(&self, _: &str) -> helix_contracts::Result<[u8; 32]> {
            Err(ContractError::UnknownKey)
        }
    }

    #[test]
    fn busy_timeout_uses_live_remaining_deadline_configured_cap_and_sqlite_limit() {
        assert_eq!(
            bounded_busy_timeout_from_limit_v1(20, &ValueClock { now: Some(10) }, 50,),
            Ok(20)
        );
        assert_eq!(
            bounded_busy_timeout_from_limit_v1(100, &ValueClock { now: Some(10) }, 50,),
            Ok(40)
        );
        assert_eq!(
            bounded_busy_timeout_from_limit_v1(
                u64::MAX,
                &ValueClock { now: Some(1) },
                MAX_SQLITE_BUSY_TIMEOUT_MS + 2,
            ),
            Ok(MAX_SQLITE_BUSY_TIMEOUT_MS)
        );
        assert_eq!(
            bounded_busy_timeout_from_limit_v1(100, &ValueClock { now: Some(50) }, 50,),
            Err(InternalCoordinatorError::DeadlineReached)
        );
        assert_eq!(
            bounded_busy_timeout_from_limit_v1(100, &ValueClock { now: None }, 50),
            Err(InternalCoordinatorError::ClockUnavailable)
        );

        let connection = rusqlite::Connection::open_in_memory().expect("SQLite opens");
        let configured = configure_deadline_bounded_busy_timeout_v1(
            &connection,
            100,
            &ValueClock { now: Some(10) },
            50,
        )
        .expect("live deadline arms busy wait");
        let readback: i64 = connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("busy timeout reads back");
        assert_eq!(configured, 40);
        assert_eq!(readback, 40);
    }

    #[test]
    fn busy_timeout_arming_rechecks_deadline_after_installing_handler() {
        let connection = rusqlite::Connection::open_in_memory().expect("SQLite opens");
        let clock = AdvancingClock {
            first: 10,
            later: 50,
            samples: AtomicUsize::new(0),
        };

        assert_eq!(
            configure_deadline_bounded_busy_timeout_v1(&connection, 100, &clock, 50),
            Err(InternalCoordinatorError::DeadlineReached)
        );
        let readback: i64 = connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("the first live sample still installed its bounded handler");
        assert_eq!(readback, 40);
        assert_eq!(clock.samples.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn committed_v1_recovers_after_restart_before_marker_publication() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-commit-restart-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("empty config validates");
        let identity = generate_root_identity().expect("root identity generates");

        {
            let mut lease = acquire_initialization_root_lease(
                config.empty_root().expect("empty role retained"),
                config.maximum_busy_wait_ms(),
                &FixedClock,
                100,
            )
            .expect("initialization lease acquires");
            lease
                .begin_initialization(identity)
                .expect("identity marker publishes before database creation");
            let mut reservation =
                reserve_database_file_create_new(&config).expect("database file reserves");
            prepare_reserved_database_for_sqlite(&config, &mut reservation)
                .expect("reservation prepares");
            let mut connection = open_database(&config).expect("SQLite opens reservation");
            configure_connection(&connection, 10, true).expect("profile establishes");
            connection
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .expect("test preserves committed WAL across connection close");
            verify_reserved_database_fingerprint(&config, &mut reservation)
                .expect("opened file remains bound");
            crate::schema::initialize_empty_to_v1(&mut connection, identity, &FixedClock, 100)
                .expect("v1 transaction commits");
            verify_reserved_database_fingerprint(&config, &mut reservation)
                .expect("committed file remains bound");
            assert_eq!(
                crate::schema::classify_initialization_candidate(&connection).unwrap(),
                crate::schema::InitializationCandidateV1::CommittedV1
            );
            // Simulated process exit: connection and lease drop without publishing EXISTING.
        }
        assert!(
            fs::metadata(root.join(COORDINATOR_WAL_FILENAME))
                .is_ok_and(|metadata| metadata.len() > 0),
            "committed state must remain in WAL for the restart proof"
        );

        let restarted = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("initializing root remains an admissible restart input");
        let (existing, summary, _) =
            initialize_or_verify_store(restarted, &FixedClock, &NoHistoricalKeys, 100)
                .expect("restart verifies marker-bound v1 and finalizes publication");
        assert_eq!(summary.root_identity, identity);
        assert!(existing.existing_root().is_some());

        drop(existing);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_existing_publication_recovers_when_returned_evidence_was_lost() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-existing-return-restart-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let initial = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("empty config validates");

        let (returned_config, initial_summary, _) =
            initialize_or_verify_store(initial, &FixedClock, &NoHistoricalKeys, 100)
                .expect("initialization commits and publishes exact existing marker");
        let identity = initial_summary.root_identity;
        // Persistently this is the exact crash window after marker publication and before the
        // provisioner can retain the returned identity evidence. Discard that return authority.
        drop(returned_config);

        let recovery = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("provisioner re-attests the interrupted publication layout");
        let (recovered_config, recovered_summary, _) =
            initialize_or_verify_store(recovery, &FixedClock, &NoHistoricalKeys, 100)
                .expect("full marker-bound v1 verification returns the reserved identity");
        assert_eq!(recovered_summary.root_identity, identity);
        assert_eq!(
            recovered_config
                .existing_root()
                .expect("recovery returns existing authority")
                .expected_identity(),
            identity
        );

        drop(recovered_config);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn one_backup_custody_opens_two_same_file_sessions_without_second_root_lease() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-backup-pair-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let initial = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("empty config validates");
        let (existing, summary, _) =
            initialize_or_verify_store(initial, &FixedClock, &NoHistoricalKeys, 100)
                .expect("source store initializes");

        let mut pair = open_bound_backup_pair_v1(&existing, &FixedClock, 100)
            .expect("one lease opens the bound source/guard pair");
        assert_eq!(pair.expected_root_identity(), summary.root_identity);
        let (_, source, guard) = pair.parts_v1();
        let guard_transaction = guard
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("paired writer guard acquires");
        let mut destination = rusqlite::Connection::open_in_memory().expect("destination opens");
        let backup = rusqlite::backup::Backup::new(source, &mut destination)
            .expect("online backup initializes from paired trusted source");
        assert_eq!(
            backup.step(-1).expect("online backup steps"),
            rusqlite::backup::StepResult::Done
        );
        drop(backup);
        guard_transaction.rollback().expect("writer guard releases");
        pair.revalidate(&FixedClock, 100)
            .expect("pair retains one root/file custody after backup");

        drop(pair);
        drop(existing);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn regular_file_swap_after_create_new_reservation_is_detected() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-reservation-swap-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("empty config validates");
        let _lease = reserve_empty_root(
            config.empty_root().expect("empty role retained"),
            &FixedClock,
            100,
        )
        .expect("empty lease reserves");
        let mut reservation =
            reserve_database_file_create_new(&config).expect("database file reserves");

        fs::remove_file(config.database_path()).expect("reserved path unlinks");
        let mut replacement = File::create(config.database_path()).expect("replacement creates");
        replacement
            .write_all(&[0_u8; 32])
            .expect("replacement marker writes");
        replacement.sync_all().expect("replacement syncs");
        assert!(prepare_reserved_database_for_sqlite(&config, &mut reservation).is_err());
        drop(replacement);
        drop(reservation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn byte_identical_regular_file_swap_after_sqlite_open_is_detected_by_file_identity() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-open-swap-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let config = CoordinatorStoreConfigV1::try_new_empty_attested(root.clone(), 10)
            .expect("empty config validates");
        let lease = reserve_empty_root(
            config.empty_root().expect("empty role retained"),
            &FixedClock,
            100,
        )
        .expect("empty lease reserves");
        let mut reservation =
            reserve_database_file_create_new(&config).expect("database file reserves");
        prepare_reserved_database_for_sqlite(&config, &mut reservation)
            .expect("reservation prepares");
        let connection = open_database(&config).expect("SQLite opens reservation");
        configure_connection(&connection, 10, true).expect("SQLite profile establishes");
        verify_reserved_database_fingerprint(&config, &mut reservation)
            .expect("opened file identity initially matches");

        // Windows SQLite handles do not permit unlinking the open database path. Closing only
        // that handle keeps the reservation handle and its original file identity in custody,
        // so the byte-identical replacement still exercises the fail-closed identity check.
        #[cfg(windows)]
        drop(connection);
        let identical_bytes = read_exact_file(&mut reservation.file).expect("database bytes read");

        fs::remove_file(config.database_path()).expect("opened path unlinks");
        let mut replacement = File::create(config.database_path()).expect("replacement creates");
        replacement
            .write_all(&identical_bytes)
            .expect("identical replacement writes");
        replacement.sync_all().expect("replacement syncs");
        assert!(verify_reserved_database_fingerprint(&config, &mut reservation).is_err());
        // The exclusive marker lease has already protected the full swap and identity check.
        // Release it only before the path-based marker read, which Windows otherwise refuses.
        drop(lease);
        let role_marker =
            fs::read(root.join(".helix-coordinator-root-v1.lock")).expect("role marker reads");
        assert!(role_marker.ends_with(b"STATE=EMPTY\n"));

        drop(replacement);
        #[cfg(not(windows))]
        drop(connection);
        drop(reservation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn all_seven_required_pragmas_are_established_and_read_on_every_connection() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "helixos-coordinator-profile-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("test root creates");
        let database = root.join("profile.sqlite3");
        let assert_exact = |connection: &rusqlite::Connection| {
            let journal: String = connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .expect("journal reads");
            assert_eq!(journal.to_ascii_lowercase(), "wal");
            for (pragma, expected) in [
                ("synchronous", 2),
                ("foreign_keys", 1),
                ("trusted_schema", 0),
                ("cell_size_check", 1),
                ("recursive_triggers", 1),
                ("wal_autocheckpoint", 0),
            ] {
                assert_eq!(profile_pragma_i64(connection, pragma).unwrap(), expected);
            }
        };

        let first = rusqlite::Connection::open(&database).expect("first connection opens");
        configure_connection(&first, 10, true).expect("first profile establishes");
        assert_exact(&first);
        drop(first);
        let second = rusqlite::Connection::open(&database).expect("second connection opens");
        configure_connection(&second, 10, false).expect("second profile establishes");
        assert_exact(&second);
        drop(second);
        let _ = fs::remove_dir_all(root);
    }
}
