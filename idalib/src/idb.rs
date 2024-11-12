use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};

use crate::ffi::bytes::*;
use crate::ffi::comments::{append_cmt, idalib_get_cmt, set_cmt};
use crate::ffi::entry::{get_entry, get_entry_ordinal, get_entry_qty};
use crate::ffi::func::{get_func, get_func_qty, getn_func};
use crate::ffi::hexrays::{decompile_func, init_hexrays_plugin, term_hexrays_plugin};
use crate::ffi::ida::{
    auto_wait, close_database_with, make_signatures, open_database_quiet, set_screen_ea,
};
use crate::ffi::insn::decode;
use crate::ffi::loader::find_plugin;
use crate::ffi::processor::get_ph;
use crate::ffi::segment::{get_segm_qty, getnseg, getseg};
use crate::ffi::util::{is_align_insn, next_head, prev_head, str2reg};
use crate::ffi::xref::{xrefblk_t, xrefblk_t_first_from, xrefblk_t_first_to};
use crate::ffi::BADADDR;

use crate::bookmarks::Bookmarks;
use crate::decompiler::CFunction;
use crate::func::{Function, FunctionId};
use crate::insn::{Insn, Register};
use crate::meta::Metadata;
use crate::plugin::Plugin;
use crate::processor::Processor;
use crate::segment::{Segment, SegmentId};
use crate::xref::{XRef, XRefQuery};
use crate::{prepare_library, Address, IDAError, IDARuntimeHandle};

pub struct IDB {
    path: PathBuf,
    save: bool,
    decompiler: bool,
    _guard: IDARuntimeHandle,
    _marker: PhantomData<*const ()>,
}

impl IDB {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IDAError> {
        Self::open_with(path, true, false)
    }

    pub fn open_with(
        path: impl AsRef<Path>,
        auto_analyse: bool,
        save: bool,
    ) -> Result<Self, IDAError> {
        let _guard = prepare_library();
        let path = path.as_ref();

        open_database_quiet(path, auto_analyse)?;

        let decompiler = unsafe { init_hexrays_plugin(0.into()) };

        Ok(Self {
            path: path.to_owned(),
            save,
            decompiler,
            _guard,
            _marker: PhantomData,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn save_on_close(&mut self, status: bool) {
        self.save = status;
    }

    pub fn auto_wait(&mut self) -> bool {
        unsafe { auto_wait() }
    }

    pub fn set_screen_address(&mut self, ea: Address) {
        set_screen_ea(ea.into())
    }

    pub fn make_signatures(&mut self, only_pat: bool) -> Result<(), IDAError> {
        make_signatures(only_pat)
    }

    pub fn decompiler_available(&self) -> bool {
        self.decompiler
    }

    pub fn meta<'a>(&'a self) -> Metadata<'a> {
        Metadata::new()
    }

    pub fn processor<'a>(&'a self) -> Processor<'a> {
        let ptr = unsafe { get_ph() };
        Processor::from_ptr(ptr)
    }

    pub fn entries<'a>(&'a self) -> EntryPointIter<'a> {
        let limit = unsafe { get_entry_qty() };
        EntryPointIter {
            index: 0,
            limit,
            _marker: PhantomData,
        }
    }

    pub fn function_at<'a>(&'a self, ea: Address) -> Option<Function<'a>> {
        let ptr = unsafe { get_func(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn next_head(&self, ea: Address) -> Option<Address> {
        self.next_head_with(ea, BADADDR.into())
    }

    pub fn next_head_with(&self, ea: Address, max_ea: Address) -> Option<Address> {
        let next = unsafe { next_head(ea.into(), max_ea.into()) };
        if next == BADADDR {
            None
        } else {
            Some(next.into())
        }
    }

    pub fn prev_head(&self, ea: Address) -> Option<Address> {
        self.prev_head_with(ea, 0)
    }

    pub fn prev_head_with(&self, ea: Address, min_ea: Address) -> Option<Address> {
        let prev = unsafe { prev_head(ea.into(), min_ea.into()) };
        if prev == BADADDR {
            None
        } else {
            Some(prev.into())
        }
    }

    pub fn insn_at(&self, ea: Address) -> Option<Insn> {
        let insn = decode(ea.into())?;
        Some(Insn::from_repr(insn))
    }

    pub fn decompile<'a>(&'a self, f: &Function<'a>) -> Option<CFunction<'a>> {
        self.decompile_with(f, false)
    }

    pub fn decompile_with<'a>(
        &'a self,
        f: &Function<'a>,
        all_blocks: bool,
    ) -> Option<CFunction<'a>> {
        if !self.decompiler {
            return None;
        }

        decompile_func(f.as_ptr(), all_blocks).and_then(CFunction::new)
    }

    pub fn function_by_id<'a>(&'a self, id: FunctionId) -> Option<Function<'a>> {
        let ptr = unsafe { getn_func(id) };

        if ptr.is_null() {
            return None;
        }

        Some(Function::from_ptr(ptr))
    }

    pub fn functions<'a>(&'a self) -> impl Iterator<Item = (FunctionId, Function<'a>)> + 'a {
        (0..self.function_count()).filter_map(|id| self.function_by_id(id).map(|f| (id, f)))
    }

    pub fn function_count(&self) -> usize {
        unsafe { get_func_qty() }
    }

    pub fn segment_at<'a>(&'a self, ea: Address) -> Option<Segment<'a>> {
        let ptr = unsafe { getseg(ea.into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segment_by_id<'a>(&'a self, id: SegmentId) -> Option<Segment<'a>> {
        let ptr = unsafe { getnseg((id as i32).into()) };

        if ptr.is_null() {
            return None;
        }

        Some(Segment::from_ptr(ptr))
    }

    pub fn segments<'a>(&'a self) -> impl Iterator<Item = (SegmentId, Segment<'a>)> + 'a {
        (0..self.segment_count()).filter_map(|id| self.segment_by_id(id).map(|s| (id, s)))
    }

    pub fn segment_count(&self) -> usize {
        unsafe { get_segm_qty().0 as _ }
    }

    pub fn register_by_name(&self, name: impl AsRef<str>) -> Option<Register> {
        let s = CString::new(name.as_ref()).ok()?;
        let id = unsafe { str2reg(s.as_ptr()).0 };

        if id == -1 {
            None
        } else {
            Some(id as _)
        }
    }

    pub fn insn_alignment_at(&self, ea: Address) -> Option<usize> {
        let align = unsafe { is_align_insn(ea.into()).0 };
        if align == 0 {
            None
        } else {
            Some(align as _)
        }
    }

    pub fn first_xref_from(&self, ea: Address, flags: XRefQuery) -> Option<XRef> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_from(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn first_xref_to(&self, ea: Address, flags: XRefQuery) -> Option<XRef> {
        let mut xref = MaybeUninit::<xrefblk_t>::zeroed();
        let found =
            unsafe { xrefblk_t_first_to(xref.as_mut_ptr(), ea.into(), flags.bits().into()) };

        if found {
            Some(XRef::from_repr(unsafe { xref.assume_init() }))
        } else {
            None
        }
    }

    pub fn get_cmt(&self, ea: Address) -> Option<String> {
        self.get_cmt_with(ea, false)
    }

    pub fn get_cmt_with(&self, ea: Address, rptble: bool) -> Option<String> {
        let s = unsafe { idalib_get_cmt(ea.into(), rptble) };

        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    pub fn set_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.set_cmt_with(ea, comm, false)
    }

    pub fn set_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { set_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to set comment at {ea:#x}"
            )))
        }
    }

    pub fn append_cmt(&self, ea: Address, comm: impl AsRef<str>) -> Result<(), IDAError> {
        self.append_cmt_with(ea, comm, false)
    }

    pub fn append_cmt_with(
        &self,
        ea: Address,
        comm: impl AsRef<str>,
        rptble: bool,
    ) -> Result<(), IDAError> {
        let s = CString::new(comm.as_ref()).map_err(IDAError::ffi)?;
        if unsafe { append_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to append comment at {ea:#x}"
            )))
        }
    }

    pub fn remove_cmt(&self, ea: Address) -> Result<(), IDAError> {
        self.remove_cmt_with(ea, false)
    }

    pub fn remove_cmt_with(&self, ea: Address, rptble: bool) -> Result<(), IDAError> {
        let s = CString::new("").map_err(IDAError::ffi)?;
        if unsafe { set_cmt(ea.into(), s.as_ptr(), rptble) } {
            Ok(())
        } else {
            Err(IDAError::ffi_with(format!(
                "failed to remove comment at {ea:#x}"
            )))
        }
    }

    pub fn bookmarks<'a>(&'a self) -> Bookmarks<'a> {
        Bookmarks::new(self)
    }

    pub fn get_byte(&self, ea: Address) -> u8 {
        unsafe { idalib_get_byte(ea.into()) }
    }

    pub fn get_word(&self, ea: Address) -> u16 {
        unsafe { idalib_get_word(ea.into()) }
    }

    pub fn get_dword(&self, ea: Address) -> u32 {
        unsafe { idalib_get_dword(ea.into()) }
    }

    pub fn get_qword(&self, ea: Address) -> u64 {
        unsafe { idalib_get_qword(ea.into()) }
    }

    pub fn get_bytes(&self, ea: Address, size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size);

        let Ok(new_len) = (unsafe { idalib_get_bytes(ea.into(), &mut buf) }) else {
            return Vec::with_capacity(0);
        };

        unsafe {
            buf.set_len(new_len);
        }

        buf
    }

    pub fn find_plugin(
        &self,
        name: impl AsRef<str>,
        load_if_needed: bool,
    ) -> Result<Plugin, IDAError> {
        let plugin = CString::new(name.as_ref()).map_err(IDAError::ffi)?;
        let ptr = unsafe { find_plugin(plugin.as_ptr(), load_if_needed) };

        if ptr.is_null() {
            Err(IDAError::ffi_with(format!(
                "failed to load {} plugin",
                name.as_ref()
            )))
        } else {
            Ok(Plugin::from_ptr(ptr))
        }
    }

    pub fn load_plugin(&self, name: impl AsRef<str>) -> Result<Plugin, IDAError> {
        self.find_plugin(name, true)
    }
}

impl Drop for IDB {
    fn drop(&mut self) {
        if self.decompiler {
            unsafe {
                term_hexrays_plugin();
            }
        }
        close_database_with(self.save);
    }
}

pub struct EntryPointIter<'a> {
    index: usize,
    limit: usize,
    _marker: PhantomData<&'a IDB>,
}

impl<'a> Iterator for EntryPointIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.limit {
            return None;
        }

        let ordinal = unsafe { get_entry_ordinal(self.index) };
        let addr = unsafe { get_entry(ordinal) };

        // skip?
        if addr == BADADDR {
            self.index += 1;
            return self.next();
        }

        Some(addr.into())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let lim = self.limit - self.index;
        (0, Some(lim))
    }
}
