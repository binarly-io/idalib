use std::fmt::Display;
use std::ops::Deref;

use crate::{IDAError, ffi, init_library};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LicenseId([u8; 6]);

impl Display for LicenseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.0;
        write!(
            f,
            "{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}",
            id[0], id[1], id[2], id[3], id[4], id[5]
        )
    }
}

impl AsRef<[u8]> for LicenseId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for LicenseId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<LicenseId> for [u8; 6] {
    fn from(value: LicenseId) -> Self {
        value.0
    }
}

pub fn is_valid_license() -> bool {
    init_library();
    ffi::ida::is_license_valid()
}

pub fn license_id() -> Result<LicenseId, IDAError> {
    init_library();
    Ok(LicenseId(ffi::ida::license_id()?))
}
