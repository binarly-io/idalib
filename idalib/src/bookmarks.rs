use std::ffi::CString;
use std::marker::PhantomData;

use crate::ffi::BADADDR;
use crate::ffi::bookmarks::{
    idalib_bookmarks_t_erase, idalib_bookmarks_t_find_index, idalib_bookmarks_t_get,
    idalib_bookmarks_t_get_desc, idalib_bookmarks_t_mark, idalib_bookmarks_t_size,
};
use crate::idb::IDB;
use crate::{Address, IDAError};

pub type BookmarkIndex = u32;

const BOOKMARKS_BAD_INDEX: BookmarkIndex = 0xffffffff; // (uint32(-1))

pub struct Bookmarks<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Bookmarks<'a> {
    pub(crate) const fn new(_: &'a IDB) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn mark(&self, ea: Address, desc: impl AsRef<str>) -> Result<BookmarkIndex, IDAError> {
        self.mark_with(ea, self.len(), desc)
    }

    // Notes:
    // * Adding a bookmark at an already marked address creates an overlaid bookmark
    // * Adding a bookmark at an already used index has no effect and no error is returned
    // * Adding a bookmark at an index > `len()` increments `len()` accordingly, while leaving
    //   the unused bookmark slots empty
    // * The `MAX_MARK_SLOT` limit (1024) doesn't seem to play an actual role ¯\_(ツ)_/¯
    pub fn mark_with(
        &self,
        ea: Address,
        idx: BookmarkIndex,
        desc: impl AsRef<str>,
    ) -> Result<BookmarkIndex, IDAError> {
        let desc = CString::new(desc.as_ref()).map_err(IDAError::ffi)?;

        let slot = unsafe { idalib_bookmarks_t_mark(ea.into(), idx.into(), desc.as_ptr()) };

        if slot != BOOKMARKS_BAD_INDEX {
            Ok(slot)
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set bookmark at address {ea:#x}, index {idx}"
            )))
        }
    }

    pub fn get_description(&self, ea: Address) -> Option<String> {
        self.get_description_by_index(self.find_index(ea)?)
    }

    // Note: The `bookmarks_t::get` function is used here only to get the address
    pub fn get_address(&self, idx: BookmarkIndex) -> Option<Address> {
        let addr = unsafe { idalib_bookmarks_t_get(idx.into()) };

        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    // Note: The address parameter has been removed because it is unused by IDA's API
    pub fn get_description_by_index(&self, idx: BookmarkIndex) -> Option<String> {
        let s = unsafe { idalib_bookmarks_t_get_desc(idx.into()) };

        if s.is_empty() { None } else { Some(s) }
    }

    pub fn erase(&self, ea: Address) -> Result<(), IDAError> {
        self.erase_by_index(self.find_index(ea).ok_or_else(|| {
            IDAError::ffi_with(format!("failed to find bookmark index for address {ea:#x}"))
        })?)
    }

    // Notes:
    // * When a bookmark is erased, all the following indexes are decremented to fill the gap
    // * The address parameter has been removed because it is unused by IDA's API
    pub fn erase_by_index(&self, idx: BookmarkIndex) -> Result<(), IDAError> {
        // Prevent IDA's internal error 1312 that triggers when an invalid index is supplied
        if idx >= self.len() {
            return Err(IDAError::ffi_with(format!(
                "failed to erase bookmark at index {idx}"
            )));
        }
        if unsafe { idalib_bookmarks_t_erase(idx.into()) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to erase bookmark at index {idx}"
            )))
        }
    }

    pub fn find_index(&self, ea: Address) -> Option<BookmarkIndex> {
        let index = unsafe { idalib_bookmarks_t_find_index(ea.into()) };

        if index != BOOKMARKS_BAD_INDEX {
            Some(index)
        } else {
            None
        }
    }

    // Note: The address parameter has been removed because it is unused by IDA's API
    pub fn len(&self) -> BookmarkIndex {
        unsafe { idalib_bookmarks_t_size() }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
