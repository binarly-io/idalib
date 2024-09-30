use std::marker::PhantomData;

use crate::ffi::processor::*;
use crate::idb::IDB;

pub use crate::ffi::processor::ids as id;

pub struct Processor<'a> {
    ptr: *const processor_t,
    _marker: PhantomData<&'a IDB>,
}

pub type ProcessorId = i32;

impl<'a> Processor<'a> {
    pub(crate) fn from_ptr(ptr: *const processor_t) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> ProcessorId {
        unsafe { idalib_ph_id(self.ptr) }
    }

    pub fn long_name(&self) -> String {
        unsafe { idalib_ph_long_name(self.ptr) }
    }

    pub fn short_name(&self) -> String {
        unsafe { idalib_ph_short_name(self.ptr) }
    }
}
