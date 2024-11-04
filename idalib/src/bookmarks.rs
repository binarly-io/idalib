use std::ffi::CString;
use std::marker::PhantomData;

use crate::ffi::bookmarks::{
    idalib_bookmarks_t_erase, idalib_bookmarks_t_find_index, idalib_bookmarks_t_get_desc,
    idalib_bookmarks_t_mark, idalib_bookmarks_t_size,
};

use crate::idb::IDB;
use crate::{Address, IDAError};

const BOOKMARKS_BAD_INDEX: u32 = 0xffffffff; // (uint32(-1))

pub type BookmarkIndex = u32;

pub struct Bookmarks<'a> {
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Bookmarks<'a> {
    pub(crate) fn new(_: &'a IDB) -> Self {
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
    // * Adding a bookmark at an index > `bookmarks_size()` increments `bookmarks_size()`
    //   accordingly, while leaving the unused bookmark slots empty
    // * The MAX_MARK_SLOT = 1024 limit doesn't seem to play an actual role ¯\_(ツ)_/¯
    pub fn mark_with(
        &self,
        ea: Address,
        idx: u32,
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
        self.get_description_by_index(self.find_index(ea)?.into())
    }

    // Note: The address parameter has been removed because it is unused by IDA Pro's API
    pub fn get_description_by_index(&self, idx: BookmarkIndex) -> Option<String> {
        let s = unsafe { idalib_bookmarks_t_get_desc(idx.into()) };

        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    pub fn erase(&self, ea: Address) -> Result<(), IDAError> {
        self.erase_by_index(self.find_index(ea).ok_or(IDAError::ffi_with(format!(
            "failed to find bookmark index for address {ea:#x}"
        )))?)
    }

    // Notes:
    // * When a bookmark is erased, all the following indexes are decremented to fill the gap
    // * The address parameter has been removed because it is unused by IDA Pro's API
    pub fn erase_by_index(&self, idx: BookmarkIndex) -> Result<(), IDAError> {
        // Prevent IDA Pro's internal error 1312 that triggers when an invalid index is supplied
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

    // Note: The address parameter has been removed because it is unused by IDA Pro's API
    // TODO: use `usize` (or `BookmarkIndex` or another aliased type) instead of `u32`
    pub fn len(&self) -> u32 {
        unsafe { idalib_bookmarks_t_size() }
    }

    pub fn find_index(&self, ea: Address) -> Option<BookmarkIndex> {
        let index = unsafe { idalib_bookmarks_t_find_index(ea.into()) };

        if index != BOOKMARKS_BAD_INDEX {
            Some(index)
        } else {
            None
        }
    }
}

/*









*/
