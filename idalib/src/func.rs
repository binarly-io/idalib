use std::marker::PhantomData;
use std::mem;
use std::pin::Pin;
use std::ptr;

use autocxx::moveit::Emplace;
use bitflags::bitflags;
use cxx::UniquePtr;

use crate::ffi::func::*;
use crate::ffi::xref::has_external_refs;
use crate::ffi::{range_t, IDAError, BADADDR};
use crate::idb::IDB;
use crate::types::FieldAttributes;
use crate::Address;

pub struct Function<'a> {
    ptr: *mut func_t,
    _lock: Pin<Box<lock_func>>,
    _marker: PhantomData<&'a IDB>,
}

pub struct FunctionCFG<'a> {
    flow_chart: UniquePtr<qflow_chart_t>,
    _marker: PhantomData<&'a Function<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionFrame {
    arguments: Vec<FunctionVar>,
    locals: Vec<FunctionVar>,
    saved_registers: Option<FunctionVar>,
    return_address: Option<FunctionVar>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionVar {
    name: Option<String>,
    alignment: u8,
    effective_alignment: i32,
    attributes: FieldAttributes,
    fp_offset: i64,
    size: usize,
}

impl From<func_var_t> for FunctionVar {
    fn from(v: func_var_t) -> Self {
        FunctionVar {
            name: if v.name.is_empty() {
                None
            } else {
                Some(v.name)
            },
            attributes: FieldAttributes::from_bits_truncate(v.attributes),
            alignment: v.alignment,
            effective_alignment: v.effective_alignment.0,
            fp_offset: v.fp_offset,
            size: v.size,
        }
    }
}

pub struct BasicBlock<'a> {
    block: *const qbasic_block_t,
    kind: fc_block_type_t,
    _marker: PhantomData<&'a FunctionCFG<'a>>,
}

impl<'a> BasicBlock<'a> {
    fn as_range_t(&self) -> *const range_t {
        self.block.cast()
    }

    pub(crate) fn from_parts(ptr: *const qbasic_block_t, kind: fc_block_type_t) -> Self {
        BasicBlock {
            block: ptr,
            kind,
            _marker: PhantomData,
        }
    }

    pub fn start_address(&self) -> Address {
        unsafe { (*self.as_range_t()).start_ea.into() }
    }

    pub fn end_address(&self) -> Address {
        unsafe { (*self.as_range_t()).end_ea.into() }
    }

    pub fn contains_address(&self, addr: Address) -> bool {
        unsafe { (*self.as_range_t()).contains(addr.into()) }
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.as_range_t()).size().0 as _ }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_normal(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_normal)
    }

    pub fn is_indjump(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_indjump)
    }

    pub fn is_ret(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_ret)
    }

    pub fn is_cndret(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_cndret)
    }

    pub fn is_noret(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_noret)
    }

    pub fn is_enoret(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_enoret)
    }

    pub fn is_extern(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_extern)
    }

    pub fn is_error(&self) -> bool {
        matches!(self.kind, fc_block_type_t::fcb_error)
    }

    pub fn succs<'b>(&'b self) -> impl ExactSizeIterator<Item = BasicBlockId> + 'b {
        unsafe { idalib_qbasic_block_succs(self.block) }
            .iter()
            .map(|v| v.0 as _)
    }

    pub fn succs_with<'b>(
        &'b self,
        cfg: &'a FunctionCFG<'_>,
    ) -> impl ExactSizeIterator<Item = BasicBlock<'a>> + 'b {
        self.succs()
            .map(|id| cfg.block_by_id(id).expect("valid block"))
    }

    pub fn preds<'b>(&'b self) -> impl ExactSizeIterator<Item = BasicBlockId> + 'b {
        unsafe { idalib_qbasic_block_preds(self.block) }
            .iter()
            .map(|v| v.0 as _)
    }

    pub fn preds_with<'b>(
        &'b self,
        cfg: &'a FunctionCFG<'_>,
    ) -> impl ExactSizeIterator<Item = BasicBlock<'a>> + 'b {
        self.preds()
            .map(|id| cfg.block_by_id(id).expect("valid block"))
    }
}

pub type FunctionId = usize;
pub type BasicBlockId = usize;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FunctionFlags: u64 {
        const NORET = flags::FUNC_NORET as u64;
        const FAR = flags::FUNC_FAR as u64;
        const LIB = flags::FUNC_LIB as u64;
        const STATICDEF = flags::FUNC_STATICDEF as u64;
        const FRAME = flags::FUNC_FRAME as u64;
        const USERFAR = flags::FUNC_USERFAR as u64;
        const HIDDEN = flags::FUNC_HIDDEN as u64;
        const THUNK = flags::FUNC_THUNK as u64;
        const BOTTOMBP = flags::FUNC_BOTTOMBP as u64;
        const NORET_PENDING = flags::FUNC_NORET_PENDING as u64;
        const SP_READY = flags::FUNC_SP_READY as u64;
        const FUZZY_SP = flags::FUNC_FUZZY_SP as u64;
        const PROLOG_OK = flags::FUNC_PROLOG_OK as u64;
        const PURGED_OK = flags::FUNC_PURGED_OK as u64;
        const TAIL = flags::FUNC_TAIL as u64;
        const LUMINA = flags::FUNC_LUMINA as u64;
        const OUTLINE = flags::FUNC_OUTLINE as u64;
        const REANALYZE = flags::FUNC_REANALYZE as u64;
        const RESERVED = flags::FUNC_RESERVED as u64;
    }
}

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FunctionCFGFlags: i32 {
        const PRINT = cfg_flags::FC_PRINT as i32;
        const NOEXT = cfg_flags::FC_NOEXT as i32;
        const RESERVED = cfg_flags::FC_RESERVED as i32;
        const APPND = cfg_flags::FC_APPND as i32;
        const CHKBREAK = cfg_flags::FC_CHKBREAK as i32;
        const CALL_ENDS = cfg_flags::FC_CALL_ENDS as i32;
        const NOPREDS = cfg_flags::FC_NOPREDS as i32;
        const OUTLINES = cfg_flags::FC_OUTLINES as i32;
    }
}

impl<'a> Function<'a> {
    pub(crate) fn from_ptr(ptr: *mut func_t) -> Self {
        let lock = unsafe { Box::emplace(lock_func::new(ptr)) };
        Self {
            ptr,
            _lock: lock,
            _marker: PhantomData,
        }
    }

    pub(crate) fn as_ptr(&self) -> *mut func_t {
        self.ptr
    }

    fn as_range_t(&self) -> *const range_t {
        self.ptr.cast()
    }

    pub fn start_address(&self) -> Address {
        unsafe { (*self.as_range_t()).start_ea.into() }
    }

    pub fn end_address(&self) -> Address {
        unsafe { (*self.as_range_t()).end_ea.into() }
    }

    pub fn contains_address(&self, addr: Address) -> bool {
        unsafe { (*self.as_range_t()).contains(addr.into()) }
    }

    pub fn len(&self) -> usize {
        unsafe { (*self.as_range_t()).size().0 as _ }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn name(&self) -> Option<String> {
        let name = unsafe { idalib_func_name(self.ptr) }.ok()?;

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    pub fn flags(&self) -> FunctionFlags {
        let bits = unsafe { idalib_func_flags(self.ptr) };
        FunctionFlags::from_bits_retain(bits)
    }

    pub fn is_far(&self) -> bool {
        unsafe { (*self.ptr).is_far() }
    }

    pub fn does_return(&self) -> bool {
        unsafe { (*self.ptr).does_return() }
    }

    pub fn analyzed_sp(&self) -> bool {
        unsafe { (*self.ptr).analyzed_sp() }
    }

    pub fn need_prolog_analysis(&self) -> bool {
        unsafe { (*self.ptr).need_prolog_analysis() }
    }

    pub fn has_external_refs(&self, ea: Address) -> bool {
        unsafe { has_external_refs(self.ptr, ea.into()) }
    }

    pub fn sp_delta_at(&self, ea: Address) -> i64 {
        unsafe { idalib_func_spd(self.ptr, ea.into()) }
    }

    pub fn effective_sp_delta_at(&self, ea: Address) -> i64 {
        unsafe { idalib_func_effective_spd(self.ptr, ea.into()) }
    }

    pub fn sp_delta_of(&self, ea: Address) -> i64 {
        unsafe { idalib_func_sp_delta(self.ptr, ea.into()) }
    }

    pub fn frame(&self) -> Option<FunctionFrame> {
        let mut frame = func_frame_t::default();
        unsafe { idalib_func_frame(self.ptr, &mut frame).ok()? };

        Some(FunctionFrame {
            arguments: frame.arguments.into_iter().map(FunctionVar::from).collect(),
            locals: frame.locals.into_iter().map(FunctionVar::from).collect(),
            saved_registers: (frame.saved_registers.size != 0)
                .then(|| FunctionVar::from(frame.saved_registers)),
            return_address: (frame.return_address.size != 0)
                .then(|| FunctionVar::from(frame.return_address)),
        })
    }

    pub fn calc_thunk_target(&self) -> Option<Address> {
        let addr = unsafe { calc_thunk_func_target(self.ptr, ptr::null_mut()) };

        if addr == BADADDR {
            None
        } else {
            Some(addr.into())
        }
    }

    pub fn cfg(&self) -> Result<FunctionCFG, IDAError> {
        self.cfg_with(FunctionCFGFlags::empty())
    }

    pub fn cfg_with(&self, flags: FunctionCFGFlags) -> Result<FunctionCFG, IDAError> {
        let ptr = unsafe { idalib_func_flow_chart(self.ptr, flags.bits().into()) };

        Ok(FunctionCFG {
            flow_chart: ptr.map_err(IDAError::ffi)?,
            _marker: PhantomData,
        })
    }
}

impl FunctionFrame {
    pub fn arguments(&self) -> &[FunctionVar] {
        &self.arguments
    }

    pub fn locals(&self) -> &[FunctionVar] {
        &self.locals
    }

    pub fn saved_registers(&self) -> Option<&FunctionVar> {
        self.saved_registers.as_ref()
    }

    pub fn return_address(&self) -> Option<&FunctionVar> {
        self.return_address.as_ref()
    }
}

impl FunctionVar {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn attributes(&self) -> FieldAttributes {
        self.attributes
    }

    pub fn alignment(&self) -> usize {
        self.alignment as _
    }

    pub fn effective_alignment(&self) -> usize {
        self.effective_alignment as _
    }

    pub fn fp_offset(&self) -> i64 {
        self.fp_offset
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl<'a> FunctionCFG<'a> {
    unsafe fn as_gdl_graph(&self) -> Option<&gdl_graph_t> {
        self.flow_chart
            .as_ref()
            .map(|r| mem::transmute::<&qflow_chart_t, &gdl_graph_t>(r))
    }

    pub fn block_by_id(&self, id: BasicBlockId) -> Option<BasicBlock> {
        let blk = unsafe {
            idalib_qflow_graph_getn_block(self.flow_chart.as_ref().expect("valid pointer"), id)
        };

        if blk.is_null() {
            return None;
        }

        let kind = unsafe {
            self.flow_chart
                .as_ref()
                .expect("valid pointer")
                .calc_block_type(id)
        };

        Some(BasicBlock::from_parts(blk, kind))
    }

    pub fn entry(&self) -> Option<BasicBlock> {
        let id = unsafe { self.as_gdl_graph().expect("valid pointer").entry() };

        if id.0 < 0 {
            return None;
        }

        self.block_by_id(id.0 as _)
    }

    pub fn exit(&self) -> Option<BasicBlock> {
        let id = unsafe { self.as_gdl_graph().expect("valid pointer").exit() };

        if id.0 < 0 {
            return None;
        }

        self.block_by_id(id.0 as _)
    }

    pub fn blocks_count(&self) -> usize {
        unsafe { self.as_gdl_graph().expect("valid pointer").node_qty().0 as _ }
    }

    pub fn blocks<'b>(&'b self) -> impl ExactSizeIterator<Item = BasicBlock<'b>> + 'b {
        (0..self.blocks_count()).map(|id| self.block_by_id(id).expect("valid block"))
    }
}
