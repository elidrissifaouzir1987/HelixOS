use std::error::Error;
use std::fmt;

macro_rules! closed_error {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident => $code:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.code())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.code())
            }
        }

        impl Error for $name {}
    };
}

closed_error! {
    /// Closed failure returned by the injected boot-monotonic clock.
    pub enum ReplayClockUnavailableV1 {
        Unavailable => "CLOCK_UNAVAILABLE"
    }
}

impl ReplayClockUnavailableV1 {
    pub const fn new() -> Self {
        Self::Unavailable
    }
}

impl Default for ReplayClockUnavailableV1 {
    fn default() -> Self {
        Self::new()
    }
}

closed_error! {
    /// Failure to validate a host-provisioned, dedicated replay-store root.
    pub enum ReplayStoreLocationErrorV1 {
        LocationInvalid => "LOCATION_INVALID",
        LocationNotDedicated => "LOCATION_NOT_DEDICATED"
    }
}

closed_error! {
    /// Failure to construct the bounded, non-downgradable store configuration.
    pub enum ReplayStoreConfigErrorV1 {
        InvalidBusyBound => "INVALID_BUSY_BOUND",
        InvalidBackupStep => "INVALID_BACKUP_STEP",
        InvalidBackupWait => "INVALID_BACKUP_WAIT"
    }
}

closed_error! {
    /// Closed, payload-free store initialization or reopen failure.
    pub enum ReplayStoreOpenErrorV1 {
        ClockUnavailable => "CLOCK_UNAVAILABLE",
        DeadlineReached => "DEADLINE_REACHED",
        LocationInvalid => "LOCATION_INVALID",
        LocationNotDedicated => "LOCATION_NOT_DEDICATED",
        StoreUnavailable => "STORE_UNAVAILABLE",
        StoreBusy => "STORE_BUSY",
        ApplicationIdMismatch => "APPLICATION_ID_MISMATCH",
        SchemaUnsupported => "SCHEMA_UNSUPPORTED",
        SchemaInvalid => "SCHEMA_INVALID",
        DurabilityProfileUnavailable => "DURABILITY_PROFILE_UNAVAILABLE",
        IntegrityFailed => "INTEGRITY_FAILED",
        InvariantFailed => "INVARIANT_FAILED"
    }
}

closed_error! {
    /// Closed, payload-free verification, checkpoint, backup, or restore failure.
    pub enum ReplayStoreMaintenanceErrorV1 {
        ClockUnavailable => "CLOCK_UNAVAILABLE",
        DeadlineReached => "DEADLINE_REACHED",
        LocationInvalid => "LOCATION_INVALID",
        LocationNotDedicated => "LOCATION_NOT_DEDICATED",
        StoreUnavailable => "STORE_UNAVAILABLE",
        StoreBusy => "STORE_BUSY",
        ApplicationIdMismatch => "APPLICATION_ID_MISMATCH",
        SchemaUnsupported => "SCHEMA_UNSUPPORTED",
        SchemaInvalid => "SCHEMA_INVALID",
        DurabilityProfileUnavailable => "DURABILITY_PROFILE_UNAVAILABLE",
        IntegrityFailed => "INTEGRITY_FAILED",
        InvariantFailed => "INVARIANT_FAILED",
        DestinationNotEmpty => "DESTINATION_NOT_EMPTY",
        SourceDestinationConflict => "SOURCE_DESTINATION_CONFLICT",
        ManifestMissing => "MANIFEST_MISSING",
        ManifestInvalid => "MANIFEST_INVALID",
        DatabaseDigestMismatch => "DATABASE_DIGEST_MISMATCH",
        BackupIncomplete => "BACKUP_INCOMPLETE",
        RestoreIncomplete => "RESTORE_INCOMPLETE",
        MaintenanceDeadlineReached => "MAINTENANCE_DEADLINE_REACHED"
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InternalStoreError {
    ClockUnavailable,
    DeadlineReached,
    LocationInvalid,
    LocationNotDedicated,
    StoreUnavailable,
    StoreBusy,
    ApplicationIdMismatch,
    SchemaUnsupported,
    SchemaInvalid,
    DurabilityProfileUnavailable,
    IntegrityFailed,
    InvariantFailed,
    DestinationNotEmpty,
    SourceDestinationConflict,
    ManifestMissing,
    ManifestInvalid,
    DatabaseDigestMismatch,
    BackupIncomplete,
    RestoreIncomplete,
    MaintenanceDeadlineReached,
}

impl InternalStoreError {
    pub(crate) const fn is_busy(self) -> bool {
        matches!(self, Self::StoreBusy)
    }

    pub(crate) const fn is_retryable_connection(self) -> bool {
        matches!(
            self,
            Self::StoreUnavailable | Self::StoreBusy | Self::DurabilityProfileUnavailable
        )
    }

    pub(crate) const fn requires_unhealthy_latch(self) -> bool {
        matches!(
            self,
            Self::ApplicationIdMismatch
                | Self::SchemaUnsupported
                | Self::SchemaInvalid
                | Self::IntegrityFailed
                | Self::InvariantFailed
        )
    }

    pub(crate) const fn requires_durable_quarantine(self) -> bool {
        matches!(self, Self::IntegrityFailed | Self::InvariantFailed)
    }

    pub(crate) const fn to_open(self) -> ReplayStoreOpenErrorV1 {
        match self {
            Self::ClockUnavailable => ReplayStoreOpenErrorV1::ClockUnavailable,
            Self::DeadlineReached | Self::MaintenanceDeadlineReached => {
                ReplayStoreOpenErrorV1::DeadlineReached
            }
            Self::LocationInvalid => ReplayStoreOpenErrorV1::LocationInvalid,
            Self::LocationNotDedicated | Self::DestinationNotEmpty => {
                ReplayStoreOpenErrorV1::LocationNotDedicated
            }
            Self::StoreUnavailable
            | Self::SourceDestinationConflict
            | Self::ManifestMissing
            | Self::ManifestInvalid
            | Self::DatabaseDigestMismatch
            | Self::BackupIncomplete
            | Self::RestoreIncomplete => ReplayStoreOpenErrorV1::StoreUnavailable,
            Self::StoreBusy => ReplayStoreOpenErrorV1::StoreBusy,
            Self::ApplicationIdMismatch => ReplayStoreOpenErrorV1::ApplicationIdMismatch,
            Self::SchemaUnsupported => ReplayStoreOpenErrorV1::SchemaUnsupported,
            Self::SchemaInvalid => ReplayStoreOpenErrorV1::SchemaInvalid,
            Self::DurabilityProfileUnavailable => {
                ReplayStoreOpenErrorV1::DurabilityProfileUnavailable
            }
            Self::IntegrityFailed => ReplayStoreOpenErrorV1::IntegrityFailed,
            Self::InvariantFailed => ReplayStoreOpenErrorV1::InvariantFailed,
        }
    }

    pub(crate) const fn to_maintenance(self) -> ReplayStoreMaintenanceErrorV1 {
        match self {
            Self::ClockUnavailable => ReplayStoreMaintenanceErrorV1::ClockUnavailable,
            Self::DeadlineReached => ReplayStoreMaintenanceErrorV1::DeadlineReached,
            Self::LocationInvalid => ReplayStoreMaintenanceErrorV1::LocationInvalid,
            Self::LocationNotDedicated => ReplayStoreMaintenanceErrorV1::LocationNotDedicated,
            Self::StoreUnavailable => ReplayStoreMaintenanceErrorV1::StoreUnavailable,
            Self::StoreBusy => ReplayStoreMaintenanceErrorV1::StoreBusy,
            Self::ApplicationIdMismatch => ReplayStoreMaintenanceErrorV1::ApplicationIdMismatch,
            Self::SchemaUnsupported => ReplayStoreMaintenanceErrorV1::SchemaUnsupported,
            Self::SchemaInvalid => ReplayStoreMaintenanceErrorV1::SchemaInvalid,
            Self::DurabilityProfileUnavailable => {
                ReplayStoreMaintenanceErrorV1::DurabilityProfileUnavailable
            }
            Self::IntegrityFailed => ReplayStoreMaintenanceErrorV1::IntegrityFailed,
            Self::InvariantFailed => ReplayStoreMaintenanceErrorV1::InvariantFailed,
            Self::DestinationNotEmpty => ReplayStoreMaintenanceErrorV1::DestinationNotEmpty,
            Self::SourceDestinationConflict => {
                ReplayStoreMaintenanceErrorV1::SourceDestinationConflict
            }
            Self::ManifestMissing => ReplayStoreMaintenanceErrorV1::ManifestMissing,
            Self::ManifestInvalid => ReplayStoreMaintenanceErrorV1::ManifestInvalid,
            Self::DatabaseDigestMismatch => ReplayStoreMaintenanceErrorV1::DatabaseDigestMismatch,
            Self::BackupIncomplete => ReplayStoreMaintenanceErrorV1::BackupIncomplete,
            Self::RestoreIncomplete => ReplayStoreMaintenanceErrorV1::RestoreIncomplete,
            Self::MaintenanceDeadlineReached => {
                ReplayStoreMaintenanceErrorV1::MaintenanceDeadlineReached
            }
        }
    }
}
