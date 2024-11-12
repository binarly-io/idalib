use std::ffi::c_char;
use std::sync::{Mutex, MutexGuard, OnceLock};

pub mod bookmarks;
pub mod decompiler;
pub mod func;
pub mod idb;
pub mod insn;
pub mod license;
pub mod meta;
pub mod plugin;
pub mod processor;
pub mod segment;
pub mod xref;

pub use idalib_sys as ffi;

pub use ffi::IDAError;
pub use license::{is_valid_license, license_id, LicenseId};

pub type Address = u64;

static INIT: OnceLock<Mutex<()>> = OnceLock::new();

extern "C" {
    static mut batch: c_char;
}

pub(crate) type IDARuntimeHandle = MutexGuard<'static, ()>;

pub fn force_batch_mode() {
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
    ffi::ida::enable_console_messages(enabled)
}
