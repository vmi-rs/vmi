use vmi_core::{Va, VmiError, VmiState, VmiVa, driver::VmiRead};

use super::{
    super::{WindowsLuid, WindowsSid, WindowsSidAndAttributes},
    FromWindowsObject, WindowsObject, WindowsObjectTypeKind,
};
use crate::{ArchAdapter, WindowsOs, offset};

/// A Windows access token.
///
/// An access token records a security principal's identity and the
/// privileges the kernel grants to it. Every process holds a primary
/// token. Threads may carry an [impersonation token] that overrides the
/// process token for the duration of an impersonation.
///
/// # Implementation Details
///
/// Corresponds to `_TOKEN`.
///
/// [impersonation token]: crate::WindowsThread::impersonation_token
pub struct WindowsToken<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// Address of the `_TOKEN` structure.
    va: Va,
}

impl<'a, Driver> From<WindowsToken<'a, Driver>> for WindowsObject<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from(value: WindowsToken<'a, Driver>) -> Self {
        Self::new(value.vmi, value.va)
    }
}

impl<'a, Driver> FromWindowsObject<'a, Driver> for WindowsToken<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn from_object(object: WindowsObject<'a, Driver>) -> Result<Option<Self>, VmiError> {
        match object.type_kind()? {
            Some(WindowsObjectTypeKind::Token) => Ok(Some(Self::new(object.vmi, object.va))),
            _ => Ok(None),
        }
    }
}

impl<Driver> VmiVa for WindowsToken<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

bitflags::bitflags! {
    /// Flags stored in `_TOKEN.TokenFlags`.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct WindowsTokenFlags: u32 {
        /// Corresponds to `TOKEN_HAS_TRAVERSE_PRIVILEGE`.
        const HAS_TRAVERSE_PRIVILEGE         = 0x0000_0001;

        /// Corresponds to `TOKEN_HAS_BACKUP_PRIVILEGE`.
        const HAS_BACKUP_PRIVILEGE           = 0x0000_0002;

        /// Corresponds to `TOKEN_HAS_RESTORE_PRIVILEGE`.
        const HAS_RESTORE_PRIVILEGE          = 0x0000_0004;

        /// Corresponds to `TOKEN_WRITE_RESTRICTED`.
        const WRITE_RESTRICTED               = 0x0000_0008;

        /// Corresponds to `TOKEN_IS_RESTRICTED`.
        const IS_RESTRICTED                  = 0x0000_0010;

        /// Corresponds to `TOKEN_SESSION_NOT_REFERENCED`.
        const SESSION_NOT_REFERENCED         = 0x0000_0020;

        /// Corresponds to `TOKEN_SANDBOX_INERT`.
        const SANDBOX_INERT                  = 0x0000_0040;

        /// Corresponds to `TOKEN_HAS_IMPERSONATE_PRIVILEGE`.
        const HAS_IMPERSONATE_PRIVILEGE      = 0x0000_0080;

        /// Corresponds to `SE_BACKUP_PRIVILEGES_CHECKED`.
        const SE_BACKUP_PRIVILEGES_CHECKED   = 0x0000_0100;

        /// Corresponds to `TOKEN_VIRTUALIZE_ALLOWED`.
        const VIRTUALIZE_ALLOWED             = 0x0000_0200;

        /// Corresponds to `TOKEN_VIRTUALIZE_ENABLED`.
        const VIRTUALIZE_ENABLED             = 0x0000_0400;

        /// Corresponds to `TOKEN_IS_FILTERED`.
        const IS_FILTERED                    = 0x0000_0800;

        /// Corresponds to `TOKEN_UIACCESS`.
        const UIACCESS                       = 0x0000_1000;

        /// Corresponds to `TOKEN_NOT_LOW`.
        const NOT_LOW                        = 0x0000_2000;

        /// Corresponds to `TOKEN_LOWBOX`.
        const LOWBOX                         = 0x0000_4000;

        /// Corresponds to `TOKEN_HAS_OWN_CLAIM_ATTRIBUTES`.
        const HAS_OWN_CLAIM_ATTRIBUTES       = 0x0000_8000;

        /// Corresponds to `TOKEN_PRIVATE_NAMESPACE`.
        const PRIVATE_NAMESPACE              = 0x0001_0000;

        /// Corresponds to `TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY`.
        const DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY = 0x0002_0000;

        /// Corresponds to `SPECIAL_ENCRYPTED_OPEN`.
        const SPECIAL_ENCRYPTED_OPEN         = 0x0004_0000;

        /// Corresponds to `TOKEN_NO_CHILD_PROCESS`.
        const NO_CHILD_PROCESS               = 0x0008_0000;

        /// Corresponds to `TOKEN_NO_CHILD_PROCESS_UNLESS_SECURE`.
        const NO_CHILD_PROCESS_UNLESS_SECURE = 0x0010_0000;

        /// Corresponds to `TOKEN_AUDIT_NO_CHILD_PROCESS`.
        const AUDIT_NO_CHILD_PROCESS         = 0x0020_0000;

        /// Corresponds to `TOKEN_ENFORCE_REDIRECTION_TRUST`.
        const ENFORCE_REDIRECTION_TRUST      = 0x0040_0000;

        /// Corresponds to `TOKEN_AUDIT_REDIRECTION_TRUST`.
        const AUDIT_REDIRECTION_TRUST        = 0x0080_0000;

        /// Corresponds to `TOKEN_LEARNING_MODE_LOGGING`.
        const LEARNING_MODE_LOGGING          = 0x0100_0000;

        /// Corresponds to `TOKEN_PERMISSIVE_LEARNING_MODE`.
        ///
        /// Implies `LEARNING_MODE_LOGGING`.
        const PERMISSIVE_LEARNING_MODE       = 0x0300_0000;

        /// Corresponds to `TOKEN_SYSTEM_MANAGED_ADMIN_FULL_TOKEN`.
        const SYSTEM_MANAGED_ADMIN_FULL_TOKEN = 0x0800_0000;
    }
}

/// Distinguishes a primary token from an impersonation token.
///
/// # Implementation Details
///
/// Corresponds to `_TOKEN_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsTokenType {
    /// `TokenPrimary`.
    Primary,

    /// `TokenImpersonation`.
    Impersonation,

    /// Token type not recognized.
    Unknown(u32),
}

impl From<u32> for WindowsTokenType {
    /// Decodes a raw `_TOKEN_TYPE` value.
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Primary,
            2 => Self::Impersonation,
            _ => Self::Unknown(value),
        }
    }
}

/// Impersonation level of a token.
///
/// # Implementation Details
///
/// Corresponds to `_SECURITY_IMPERSONATION_LEVEL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsImpersonationLevel {
    /// `SecurityAnonymous`.
    Anonymous,

    /// `SecurityIdentification`.
    Identification,

    /// `SecurityImpersonation`.
    Impersonation,

    /// `SecurityDelegation`.
    Delegation,

    /// Impersonation level not recognized.
    Unknown(u32),
}

impl From<u32> for WindowsImpersonationLevel {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Anonymous,
            1 => Self::Identification,
            2 => Self::Impersonation,
            3 => Self::Delegation,
            _ => Self::Unknown(value),
        }
    }
}

/// Identifies the subsystem that minted a token.
///
/// # Implementation Details
///
/// Corresponds to `_TOKEN_SOURCE`.
pub struct WindowsTokenSource<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// The VMI state.
    vmi: VmiState<'a, WindowsOs<Driver>>,

    /// The virtual address of the `_TOKEN_SOURCE` structure.
    va: Va,
}

impl<Driver> VmiVa for WindowsTokenSource<'_, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    fn va(&self) -> Va {
        self.va
    }
}

impl<'a, Driver> WindowsTokenSource<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows token source accessor.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the raw 8-byte source name as stored in the kernel.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN_SOURCE.SourceName`.
    pub fn name_bytes(&self) -> Result<[u8; 8], VmiError> {
        let TOKEN_SOURCE = offset!(self.vmi, _TOKEN_SOURCE);
        debug_assert_eq!(TOKEN_SOURCE.SourceName.size(), 8);

        let mut bytes = [0; 8];
        self.vmi
            .read(self.va + TOKEN_SOURCE.SourceName.offset(), &mut bytes)?;

        Ok(bytes)
    }

    /// Returns the source name.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN_SOURCE.SourceName`.
    pub fn name(&self) -> Result<String, VmiError> {
        let bytes = self.name_bytes()?;

        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());

        Ok(String::from_utf8_lossy(&bytes[..end])
            .trim_end()
            .to_string())
    }

    /// Returns the source identifier LUID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN_SOURCE.SourceIdentifier`.
    pub fn identifier(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN_SOURCE = offset!(self.vmi, _TOKEN_SOURCE);

        let raw = self
            .vmi
            .read_u64(self.va + TOKEN_SOURCE.SourceIdentifier.offset())?;

        Ok(WindowsLuid::from(raw))
    }
}

/// A Windows access token privilege.
///
/// Wraps a privilege LUID's `LowPart`. `HighPart` is always zero for
/// privilege LUIDs.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct WindowsPrivilege(u32);

impl WindowsPrivilege {
    /// Corresponds to `SE_CREATE_TOKEN_PRIVILEGE`.
    pub const CREATE_TOKEN: Self = Self(2);

    /// Corresponds to `SE_ASSIGNPRIMARYTOKEN_PRIVILEGE`.
    pub const ASSIGNPRIMARYTOKEN: Self = Self(3);

    /// Corresponds to `SE_LOCK_MEMORY_PRIVILEGE`.
    pub const LOCK_MEMORY: Self = Self(4);

    /// Corresponds to `SE_INCREASE_QUOTA_PRIVILEGE`.
    pub const INCREASE_QUOTA: Self = Self(5);

    /// Corresponds to `SE_MACHINE_ACCOUNT_PRIVILEGE`.
    pub const MACHINE_ACCOUNT: Self = Self(6);

    /// Corresponds to `SE_TCB_PRIVILEGE`.
    pub const TCB: Self = Self(7);

    /// Corresponds to `SE_SECURITY_PRIVILEGE`.
    pub const SECURITY: Self = Self(8);

    /// Corresponds to `SE_TAKE_OWNERSHIP_PRIVILEGE`.
    pub const TAKE_OWNERSHIP: Self = Self(9);

    /// Corresponds to `SE_LOAD_DRIVER_PRIVILEGE`.
    pub const LOAD_DRIVER: Self = Self(10);

    /// Corresponds to `SE_SYSTEM_PROFILE_PRIVILEGE`.
    pub const SYSTEM_PROFILE: Self = Self(11);

    /// Corresponds to `SE_SYSTEMTIME_PRIVILEGE`.
    pub const SYSTEMTIME: Self = Self(12);

    /// Corresponds to `SE_PROF_SINGLE_PROCESS_PRIVILEGE`.
    pub const PROF_SINGLE_PROCESS: Self = Self(13);

    /// Corresponds to `SE_INC_BASE_PRIORITY_PRIVILEGE`.
    pub const INC_BASE_PRIORITY: Self = Self(14);

    /// Corresponds to `SE_CREATE_PAGEFILE_PRIVILEGE`.
    pub const CREATE_PAGEFILE: Self = Self(15);

    /// Corresponds to `SE_CREATE_PERMANENT_PRIVILEGE`.
    pub const CREATE_PERMANENT: Self = Self(16);

    /// Corresponds to `SE_BACKUP_PRIVILEGE`.
    pub const BACKUP: Self = Self(17);

    /// Corresponds to `SE_RESTORE_PRIVILEGE`.
    pub const RESTORE: Self = Self(18);

    /// Corresponds to `SE_SHUTDOWN_PRIVILEGE`.
    pub const SHUTDOWN: Self = Self(19);

    /// Corresponds to `SE_DEBUG_PRIVILEGE`.
    pub const DEBUG: Self = Self(20);

    /// Corresponds to `SE_AUDIT_PRIVILEGE`.
    pub const AUDIT: Self = Self(21);

    /// Corresponds to `SE_SYSTEM_ENVIRONMENT_PRIVILEGE`.
    pub const SYSTEM_ENVIRONMENT: Self = Self(22);

    /// Corresponds to `SE_CHANGE_NOTIFY_PRIVILEGE`.
    pub const CHANGE_NOTIFY: Self = Self(23);

    /// Corresponds to `SE_REMOTE_SHUTDOWN_PRIVILEGE`.
    pub const REMOTE_SHUTDOWN: Self = Self(24);

    /// Corresponds to `SE_UNDOCK_PRIVILEGE`.
    pub const UNDOCK: Self = Self(25);

    /// Corresponds to `SE_SYNC_AGENT_PRIVILEGE`.
    pub const SYNC_AGENT: Self = Self(26);

    /// Corresponds to `SE_ENABLE_DELEGATION_PRIVILEGE`.
    pub const ENABLE_DELEGATION: Self = Self(27);

    /// Corresponds to `SE_MANAGE_VOLUME_PRIVILEGE`.
    pub const MANAGE_VOLUME: Self = Self(28);

    /// Corresponds to `SE_IMPERSONATE_PRIVILEGE`.
    pub const IMPERSONATE: Self = Self(29);

    /// Corresponds to `SE_CREATE_GLOBAL_PRIVILEGE`.
    pub const CREATE_GLOBAL: Self = Self(30);

    /// Corresponds to `SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE`.
    pub const TRUSTED_CREDMAN_ACCESS: Self = Self(31);

    /// Corresponds to `SE_RELABEL_PRIVILEGE`.
    pub const RELABEL: Self = Self(32);

    /// Corresponds to `SE_INC_WORKING_SET_PRIVILEGE`.
    pub const INC_WORKING_SET: Self = Self(33);

    /// Corresponds to `SE_TIME_ZONE_PRIVILEGE`.
    pub const TIME_ZONE: Self = Self(34);

    /// Corresponds to `SE_CREATE_SYMBOLIC_LINK_PRIVILEGE`.
    pub const CREATE_SYMBOLIC_LINK: Self = Self(35);

    /// Corresponds to `SE_DELEGATE_SESSION_USER_IMPERSONATE_PRIVILEGE`.
    pub const DELEGATE_SESSION_USER_IMPERSONATE: Self = Self(36);

    /// Creates a new token privilege from a LUID LowPart.
    pub const fn new(low_part: u32) -> Self {
        Self(low_part)
    }

    /// Returns the LUID `LowPart` that identifies this privilege.
    pub const fn low_part(self) -> u32 {
        self.0
    }

    /// Returns the `_SEP_TOKEN_PRIVILEGES` bit mask for this privilege.
    pub const fn mask(self) -> u64 {
        1 << self.0
    }

    /// Returns the canonical name.
    pub const fn name(self) -> Option<&'static str> {
        match self.0 {
            2 => Some("SeCreateTokenPrivilege"),
            3 => Some("SeAssignPrimaryTokenPrivilege"),
            4 => Some("SeLockMemoryPrivilege"),
            5 => Some("SeIncreaseQuotaPrivilege"),
            6 => Some("SeMachineAccountPrivilege"),
            7 => Some("SeTcbPrivilege"),
            8 => Some("SeSecurityPrivilege"),
            9 => Some("SeTakeOwnershipPrivilege"),
            10 => Some("SeLoadDriverPrivilege"),
            11 => Some("SeSystemProfilePrivilege"),
            12 => Some("SeSystemtimePrivilege"),
            13 => Some("SeProfileSingleProcessPrivilege"),
            14 => Some("SeIncreaseBasePriorityPrivilege"),
            15 => Some("SeCreatePagefilePrivilege"),
            16 => Some("SeCreatePermanentPrivilege"),
            17 => Some("SeBackupPrivilege"),
            18 => Some("SeRestorePrivilege"),
            19 => Some("SeShutdownPrivilege"),
            20 => Some("SeDebugPrivilege"),
            21 => Some("SeAuditPrivilege"),
            22 => Some("SeSystemEnvironmentPrivilege"),
            23 => Some("SeChangeNotifyPrivilege"),
            24 => Some("SeRemoteShutdownPrivilege"),
            25 => Some("SeUndockPrivilege"),
            26 => Some("SeSyncAgentPrivilege"),
            27 => Some("SeEnableDelegationPrivilege"),
            28 => Some("SeManageVolumePrivilege"),
            29 => Some("SeImpersonatePrivilege"),
            30 => Some("SeCreateGlobalPrivilege"),
            31 => Some("SeTrustedCredManAccessPrivilege"),
            32 => Some("SeRelabelPrivilege"),
            33 => Some("SeIncreaseWorkingSetPrivilege"),
            34 => Some("SeTimeZonePrivilege"),
            35 => Some("SeCreateSymbolicLinkPrivilege"),
            36 => Some("SeDelegateSessionUserImpersonatePrivilege"),
            _ => None,
        }
    }
}

impl std::fmt::Debug for WindowsPrivilege {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name}"),
            None => write!(f, "UnknownPrivilege({})", self.low_part()),
        }
    }
}

/// A privilege entry in a Windows token.
#[derive(Debug, Copy, Clone)]
pub struct WindowsTokenPrivilege {
    /// The privilege identity.
    pub privilege: WindowsPrivilege,

    /// Whether the privilege is currently enabled.
    pub enabled: bool,

    /// Whether the privilege is enabled by default for new sessions.
    pub enabled_by_default: bool,
}

impl<'a, Driver> WindowsToken<'a, Driver>
where
    Driver: VmiRead,
    Driver::Architecture: ArchAdapter<Driver>,
{
    /// Creates a new Windows token object.
    pub fn new(vmi: VmiState<'a, WindowsOs<Driver>>, va: Va) -> Self {
        Self { vmi, va }
    }

    /// Returns the Terminal Services session ID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.SessionId`.
    pub fn session_id(&self) -> Result<u32, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        self.vmi.read_u32(self.va + TOKEN.SessionId.offset())
    }

    /// Returns an accessor for the token source.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.TokenSource`.
    pub fn token_source(&self) -> WindowsTokenSource<'a, Driver> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        WindowsTokenSource::new(self.vmi, self.va + TOKEN.TokenSource.offset())
    }

    /// Returns the authentication LUID identifying the logon session.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.AuthenticationId`.
    pub fn authentication_id(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self
            .vmi
            .read_u64(self.va + TOKEN.AuthenticationId.offset())?;

        Ok(WindowsLuid::from(raw))
    }

    /// Returns the token's own identifier.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.TokenId`.
    pub fn token_id(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self.vmi.read_u64(self.va + TOKEN.TokenId.offset())?;

        Ok(WindowsLuid::from(raw))
    }

    /// Returns the parent token identifier, or zero for tokens minted
    /// from scratch.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.ParentTokenId`.
    pub fn parent_token_id(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self.vmi.read_u64(self.va + TOKEN.ParentTokenId.offset())?;

        Ok(WindowsLuid::from(raw))
    }

    /// Returns the modified-token identifier.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.ModifiedId`.
    pub fn modified_id(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self.vmi.read_u64(self.va + TOKEN.ModifiedId.offset())?;

        Ok(WindowsLuid::from(raw))
    }

    /// Returns the originating logon-session LUID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.OriginatingLogonSession`.
    pub fn originating_logon_session(&self) -> Result<WindowsLuid, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self
            .vmi
            .read_u64(self.va + TOKEN.OriginatingLogonSession.offset())?;

        Ok(WindowsLuid::from(raw))
    }

    /// Returns the token type discriminator.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.TokenType`.
    pub fn token_type(&self) -> Result<WindowsTokenType, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self.vmi.read_u32(self.va + TOKEN.TokenType.offset())?;

        Ok(WindowsTokenType::from(raw))
    }

    /// Returns the impersonation level.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.ImpersonationLevel`.
    pub fn impersonation_level(&self) -> Result<WindowsImpersonationLevel, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self
            .vmi
            .read_u32(self.va + TOKEN.ImpersonationLevel.offset())?;

        Ok(WindowsImpersonationLevel::from(raw))
    }

    /// Returns the token flags.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.TokenFlags`.
    pub fn token_flags(&self) -> Result<WindowsTokenFlags, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let raw = self.vmi.read_u32(self.va + TOKEN.TokenFlags.offset())?;

        Ok(WindowsTokenFlags::from_bits_retain(raw))
    }

    /// Returns whether the token is currently in use.
    ///
    /// Only meaningful for primary tokens. Impersonation tokens leave
    /// the field clear.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.TokenInUse`.
    pub fn token_in_use(&self) -> Result<bool, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        Ok(self.vmi.read_u8(self.va + TOKEN.TokenInUse.offset())? != 0)
    }

    /// Returns the number of entries in `UserAndGroups`. The first
    /// entry is the user SID, the rest are group SIDs.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.UserAndGroupCount`.
    pub fn user_and_group_count(&self) -> Result<u32, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        self.vmi
            .read_u32(self.va + TOKEN.UserAndGroupCount.offset())
    }

    /// Returns the number of entries in `RestrictedSids`.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.RestrictedSidCount`.
    pub fn restricted_sid_count(&self) -> Result<u32, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        self.vmi
            .read_u32(self.va + TOKEN.RestrictedSidCount.offset())
    }

    /// Returns the primary group SID.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.PrimaryGroup`.
    pub fn primary_group(&self) -> Result<WindowsSid<'a, Driver>, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let sid = self
            .vmi
            .read_va_native(self.va + TOKEN.PrimaryGroup.offset())?;

        Ok(WindowsSid::new(self.vmi, sid))
    }

    /// Returns an iterator over the token's user SID followed by every
    /// group SID. The first entry is always the user, the rest are
    /// groups.
    ///
    /// # Implementation Details
    ///
    /// Walks `_TOKEN.UserAndGroups`.
    pub fn user_and_groups(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsSidAndAttributes<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let count = self.user_and_group_count()?;
        let base = self
            .vmi
            .read_va_native(self.va + TOKEN.UserAndGroups.offset())?;

        Ok(self.sid_and_attributes(base, count))
    }

    /// Returns an iterator over the token's restricted SIDs. Empty
    /// when the token is not a restricted token.
    ///
    /// # Implementation Details
    ///
    /// Walks `_TOKEN.RestrictedSids`.
    pub fn restricted_sids(
        &self,
    ) -> Result<
        impl Iterator<Item = Result<WindowsSidAndAttributes<'a, Driver>, VmiError>> + use<'a, Driver>,
        VmiError,
    > {
        let TOKEN = offset!(self.vmi, _TOKEN);

        let count = self.restricted_sid_count()?;
        let base = self
            .vmi
            .read_va_native(self.va + TOKEN.RestrictedSids.offset())?;

        Ok(self.sid_and_attributes(base, count))
    }

    /// Returns the `_SEP_TOKEN_PRIVILEGES.Present` bitmap. Each set bit
    /// is a privilege whose LUID `LowPart` equals the bit position.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.Privileges.Present`.
    pub fn privileges_present(&self) -> Result<u64, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);
        let SEP_TOKEN_PRIVILEGES = offset!(self.vmi, _SEP_TOKEN_PRIVILEGES);

        self.vmi
            .read_u64(self.va + TOKEN.Privileges.offset() + SEP_TOKEN_PRIVILEGES.Present.offset())
    }

    /// Returns the `_SEP_TOKEN_PRIVILEGES.Enabled` bitmap.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.Privileges.Enabled`.
    pub fn privileges_enabled(&self) -> Result<u64, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);
        let SEP_TOKEN_PRIVILEGES = offset!(self.vmi, _SEP_TOKEN_PRIVILEGES);

        self.vmi
            .read_u64(self.va + TOKEN.Privileges.offset() + SEP_TOKEN_PRIVILEGES.Enabled.offset())
    }

    /// Returns the `_SEP_TOKEN_PRIVILEGES.EnabledByDefault` bitmap.
    ///
    /// # Implementation Details
    ///
    /// Corresponds to `_TOKEN.Privileges.EnabledByDefault`.
    pub fn privileges_enabled_by_default(&self) -> Result<u64, VmiError> {
        let TOKEN = offset!(self.vmi, _TOKEN);
        let SEP_TOKEN_PRIVILEGES = offset!(self.vmi, _SEP_TOKEN_PRIVILEGES);

        self.vmi.read_u64(
            self.va + TOKEN.Privileges.offset() + SEP_TOKEN_PRIVILEGES.EnabledByDefault.offset(),
        )
    }

    /// Returns an iterator over privileges present in this token.
    pub fn privileges(&self) -> Result<impl Iterator<Item = WindowsTokenPrivilege>, VmiError> {
        let present = self.privileges_present()?;
        let enabled = self.privileges_enabled()?;
        let enabled_by_default = self.privileges_enabled_by_default()?;

        Ok((0..64).filter_map(move |bit| {
            let mask = 1u64 << bit;
            match present & mask {
                0 => None,
                _ => Some(WindowsTokenPrivilege {
                    privilege: WindowsPrivilege::new(bit),
                    enabled: enabled & mask != 0,
                    enabled_by_default: enabled_by_default & mask != 0,
                }),
            }
        }))
    }

    /// Builds an iterator that walks an inline `_SID_AND_ATTRIBUTES` array.
    fn sid_and_attributes(
        &self,
        base: Va,
        count: u32,
    ) -> impl Iterator<Item = Result<WindowsSidAndAttributes<'a, Driver>, VmiError>> + use<'a, Driver>
    {
        let vmi = self.vmi;
        let sizeof_sid_and_attributes = offset!(vmi, _SID_AND_ATTRIBUTES).len() as u64;

        (0..u64::from(count)).map(move |index| {
            Ok(WindowsSidAndAttributes::new(
                vmi,
                base + index * sizeof_sid_and_attributes,
            ))
        })
    }
}
