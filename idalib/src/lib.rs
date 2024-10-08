use std::sync::{Mutex, MutexGuard, OnceLock};

pub mod func;
pub mod idb;
pub mod insn;
pub mod meta;
pub mod processor;
pub mod segment;
pub mod xref;

pub use idalib_sys as ffi;

pub use ffi::IDAError;

pub type Address = u64;

static INIT: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) type IDARuntimeHandle = MutexGuard<'static, ()>;

pub(crate) fn init_library() -> &'static Mutex<()> {
    INIT.get_or_init(|| {
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
