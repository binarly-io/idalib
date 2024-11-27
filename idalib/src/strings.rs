use std::marker::PhantomData;

use crate::ffi::strings::{
    build_strlist, clear_strlist, get_strlist_qty, idalib_get_strlist_item_addr,
    idalib_get_strlist_item_length,
};
use crate::ffi::BADADDR;

use crate::idb::IDB;
use crate::Address;

pub struct StringList<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> StringList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    // Note: Seems pretty much useless
    pub fn build(&self) {
        unsafe { build_strlist() }
    }

    // Note: Seems pretty much useless
    pub fn clear(&self) {
        unsafe { clear_strlist() }
    }

    pub fn get_item_addr(&self, index: usize) -> Option<Address> {
        let addr = unsafe { idalib_get_strlist_item_addr(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    // Note: get_item_type() was not implemented
    pub fn get_item_length(&self, index: usize) -> usize {
        unsafe { idalib_get_strlist_item_length(index) }
    }

    pub fn len(&self) -> usize {
        unsafe { get_strlist_qty() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
