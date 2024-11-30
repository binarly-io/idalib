use std::marker::PhantomData;

use crate::ffi::strings::{
    build_strlist, clear_strlist, get_strlist_qty, idalib_get_strlist_item_addr,
    idalib_get_strlist_item_length,
};
use crate::ffi::BADADDR;

use crate::idb::IDB;
use crate::Address;

pub type StringIndex = usize;

pub struct StringList<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> StringList<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    // TODO: remove?
    pub fn build(&self) {
        unsafe { build_strlist() }
    }

    // TODO: remove?
    pub fn clear(&self) {
        unsafe { clear_strlist() }
    }

    pub fn get_by_index(&self, index: usize) -> Option<String> {
        todo!()
    }

    pub fn get_address_by_index(&self, index: StringIndex) -> Option<Address> {
        let addr = unsafe { idalib_get_strlist_item_addr(index) };
        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    // TODO: remove the `pub` visibility marker and keep it internal
    pub fn get_length_by_index(&self, index: StringIndex) -> usize {
        unsafe { idalib_get_strlist_item_length(index) }
    }

    pub fn len(&self) -> StringIndex {
        unsafe { get_strlist_qty() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
