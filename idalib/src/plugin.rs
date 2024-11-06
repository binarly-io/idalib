use std::marker::PhantomData;

use crate::ffi::loader::{plugin_t, run_plugin};
use crate::idb::IDB;

pub use crate::ffi::processor::ids as id;

pub struct Plugin<'a> {
    ptr: *const plugin_t,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Plugin<'a> {
    pub(crate) fn from_ptr(ptr: *const plugin_t) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn run(&self, arg: usize) -> bool {
        unsafe { run_plugin(&*self.ptr, arg) }
    }
}
