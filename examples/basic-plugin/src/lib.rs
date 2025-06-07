use idalib::ffi::ida::msg;
use idalib::ffi::plugin::{plugin_t, plugmod_t};

#[unsafe(no_mangle)]
pub static mut PLUGIN: plugin_t = plugin_t {
    comment: c"this is a basic plugin written in Rust".as_ptr(),
    flags: 0,
    init: Some(init),
    run: Some(run),
    term: Some(term),
    help: c"this plugin does nothing useful".as_ptr(),
    version: 900,
    wanted_name: c"basic plugin".as_ptr(),
    wanted_hotkey: c"Ctrl-Shift-B".as_ptr(),
};

extern "C" fn init() -> *mut plugmod_t {
    unsafe { msg("[basic-plugin] Hello, world! This is Rust speaking!\n").ok() };
    std::ptr::null_mut()
}

extern "C" fn run(_args: usize) -> bool {
    true
}

extern "C" fn term() {}
