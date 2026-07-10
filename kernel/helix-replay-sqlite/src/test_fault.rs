//! Non-default process-crash barriers used only by repository fault tests.

use std::io::{Read as _, Write as _};

const REQUESTED_POINT_ENV: &str = "HELIX_REPLAY_TEST_FAULT_POINT";
const REQUESTED_RETURN_ERROR_ENV: &str = "HELIX_REPLAY_TEST_RETURN_ERROR";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayFaultPointV1 {
    InitializationSchemaStaged,
    InitializationCommitted,
    Opened,
    BeginAcquired,
    GenerationUpdated,
    RowInserted,
    BeforeCommit,
    CommitReturned,
    BeforeResultAck,
    BackupDatabaseComplete,
    BackupManifestStaged,
    BackupPublished,
    CheckpointBeforeMutation,
    CheckpointReturned,
    RestoreReserved,
    RestoreDatabaseStaged,
    RestorePublished,
    RestoreProfileVerified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplayReturnErrorPointV1 {
    RestoreBeforeCopy,
}

impl ReplayReturnErrorPointV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::RestoreBeforeCopy => "restore_before_copy",
        }
    }
}

impl ReplayFaultPointV1 {
    const fn code(self) -> &'static str {
        match self {
            Self::InitializationSchemaStaged => "initialization_schema_staged",
            Self::InitializationCommitted => "initialization_committed",
            Self::Opened => "opened",
            Self::BeginAcquired => "begin_acquired",
            Self::GenerationUpdated => "generation_updated",
            Self::RowInserted => "row_inserted",
            Self::BeforeCommit => "before_commit",
            Self::CommitReturned => "commit_returned",
            Self::BeforeResultAck => "before_result_ack",
            Self::BackupDatabaseComplete => "backup_database_complete",
            Self::BackupManifestStaged => "backup_manifest_staged",
            Self::BackupPublished => "backup_published",
            Self::CheckpointBeforeMutation => "checkpoint_before_mutation",
            Self::CheckpointReturned => "checkpoint_returned",
            Self::RestoreReserved => "restore_reserved",
            Self::RestoreDatabaseStaged => "restore_database_staged",
            Self::RestorePublished => "restore_published",
            Self::RestoreProfileVerified => "restore_profile_verified",
        }
    }
}

pub(crate) fn reach(point: ReplayFaultPointV1) {
    let requested = match std::env::var(REQUESTED_POINT_ENV) {
        Ok(value) => value,
        Err(_) => return,
    };
    if requested != point.code() {
        return;
    }

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "AT:{}", point.code()).expect("test fault stdout must be writable");
    stdout.flush().expect("test fault stdout must flush");
    drop(stdout);

    let mut release = [0_u8; 1];
    let _ = std::io::stdin().lock().read_exact(&mut release);
}

pub(crate) fn return_error_requested(point: ReplayReturnErrorPointV1) -> bool {
    std::env::var(REQUESTED_RETURN_ERROR_ENV).is_ok_and(|value| value == point.code())
}
