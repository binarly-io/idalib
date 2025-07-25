//! # idalib
//!
//! idalib is a Rust library providing idiomatic bindings for the IDA SDK, enabling the development
//! of standalone analysis tools using IDA v9.x’s idalib.
//!
//! ## Usage
//!
//! To use idalib, add it as a dependency in your `Cargo.toml` and include a `build.rs` file in
//! your project to properly link against IDA:
//!
//! ```toml
//! [dependencies]
//! idalib = "0.6"
//!
//! [build-dependencies]
//! idalib-build = "0.6"
//! ```
//!
//! Here is a basic example of a `build.rs` file:
//!
//! ```rust,ignore
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     idalib_build::configure_linkage()?;
//!     Ok(())
//! }
//! ```
//!
//! This script uses the `idalib-build` crate to automatically configure the linkage against IDA.
//! Ensure that the environment variables `IDASDKDIR` and optionally `IDADIR` are set to point to
//! your IDA SDK and installation directories, respectively.
//!
//! ## Setting Environment Variables
//!
//! ### On Linux/macOS
//!
//! You can set the environment variables in your terminal session or add them to your shell
//! configuration file (e.g., `.bashrc`, `.zshrc`):
//!
//! ```sh,ignore
//! export IDASDKDIR=/path/to/ida/sdk
//! export IDADIR=/path/to/ida/installation
//! ```
//!
//! ### On Windows
//!
//! Set environment variables using Command Prompt, PowerShell, or System Properties.
//!
//! **Command Prompt:**
//! ```cmd
//! set IDASDKDIR=C:\path\to\ida\sdk
//! set IDADIR=C:\path\to\ida\installation
//! ```
//!
//! **PowerShell:**
//! ```powershell,ignore
//! $env:IDASDKDIR = "C:\path\to\ida\sdk"
//! $env:IDADIR = "C:\path\to\ida\installation"
//! ```
//!
//! **System Properties:**
//! Go to "Environment Variables" in System Properties and add `IDASDKDIR` and `IDADIR`.
//!
//! ## Example
//!
//! Here's a simple example of how to use idalib:
//!
//! ```rust,ignore
//! use idalib::idb::IDB;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let idb = IDB::open("/path/to/binary")?;
//!     // Perform analysis...
//!     Ok(())
//! }
//! ```
//!
#![allow(clippy::needless_lifetimes)]

use std::ffi::c_char;
use std::marker::PhantomData;
use std::sync::{Mutex, MutexGuard, OnceLock};

pub mod bookmarks;
pub mod decompiler;
pub mod func;
pub mod idb;
pub mod insn;
pub mod license;
pub mod meta;
pub mod name;
pub mod plugin;
pub mod processor;
pub mod segment;
pub mod strings;
pub mod xref;

pub use idalib_sys as ffi;

pub use ffi::IDAError;
pub use idb::{IDB, IDBOpenOptions};
pub use license::{LicenseId, is_valid_license, license_id};

pub type Address = u64;
pub struct AddressFlags<'a> {
    flags: ffi::bytes::flags64_t,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> AddressFlags<'a> {
    pub(crate) fn new(flags: ffi::bytes::flags64_t) -> Self {
        Self {
            flags,
            _marker: PhantomData,
        }
    }

    pub fn is_code(&self) -> bool {
        unsafe { ffi::bytes::is_code(self.flags) }
    }

    pub fn is_data(&self) -> bool {
        unsafe { ffi::bytes::is_data(self.flags) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IDAVersion {
    major: i32,
    minor: i32,
    build: i32,
}

impl IDAVersion {
    pub fn major(&self) -> i32 {
        self.major
    }

    pub fn minor(&self) -> i32 {
        self.minor
    }

    pub fn build(&self) -> i32 {
        self.build
    }
}

static INIT: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(not(target_os = "windows"))]
unsafe extern "C" {
    static mut batch: c_char;
}

pub(crate) type IDARuntimeHandle = MutexGuard<'static, ()>;

pub fn force_batch_mode() {
    #[cfg(not(target_os = "windows"))]
    unsafe {
        batch = 1;
    }
}

pub fn init_library() -> &'static Mutex<()> {
    INIT.get_or_init(|| {
        force_batch_mode();
        ffi::ida::init_library().expect("IDA initialised successfully");
        Mutex::new(())
    })
}

pub(crate) fn prepare_library() -> IDARuntimeHandle {
    let mutex = init_library();
    mutex.lock().unwrap()
}

pub fn enable_console_messages(enabled: bool) {
    init_library();
    ffi::ida::enable_console_messages(enabled);
}

pub fn version() -> Result<IDAVersion, IDAError> {
    ffi::ida::library_version().map(|(major, minor, build)| IDAVersion {
        major,
        minor,
        build,
    })
}
