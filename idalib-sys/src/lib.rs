use autocxx::prelude::*;
use thiserror::Error;

mod platform;

#[derive(Debug, Error)]
pub enum IDAError {
    #[error(transparent)]
    Ffi(anyhow::Error),
    #[error("could not initialise IDA: error code {:x}", _0.0)]
    Init(autocxx::c_int),
    #[error("could not open IDA database: error code {:x}", _0.0)]
    OpenDb(autocxx::c_int),
    #[error("could not close IDA database: error code {:x}", _0.0)]
    CloseDb(autocxx::c_int),
    #[error("could not generate pattern or signature files")]
    MakeSigs,
}

impl IDAError {
    pub fn ffi<E>(e: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Ffi(anyhow::Error::from(e))
    }
}

include_cpp! {
    // NOTE: this fixes autocxx's inability to detect ea_t, optype_t as POD...
    #include "types.h"

    #include "ida/bytes.hpp"
    #include "ida/entry.hpp"
    #include "ida/funcs.hpp"
    #include "ida/gdl.hpp"
    #include "ida/ida.hpp"
    #include "ida/idalib.hpp"
    #include "ida/idp.hpp"
    #include "ida/pro.h"
    #include "ida/segment.hpp"
    #include "ida/ua.hpp"
    #include "ida/xref.hpp"

    generate!("qstring")

    // generate_pod!("cm_t")
    // generate_pod!("comp_t")
    // generate_pod!("compiler_info_t")
    generate_pod!("ea_t")
    generate_pod!("filetype_t")
    generate_pod!("range_t")
    generate_pod!("uval_t")

    // entry
    generate!("get_entry")
    generate!("get_entry_ordinal")
    generate!("get_entry_qty")

    // idp
    generate!("processor_t")
    generate!("get_ph")
    generate!("is_align_insn")
    generate!("is_basic_block_end")
    generate!("is_call_insn")
    generate!("is_indirect_jump_insn")

    generate!("is_ret_insn")
    generate!("IRI_EXTENDED")
    generate!("IRI_RET_LITERALLY")
    generate!("IRI_SKIP_RETTARGET")
    generate!("IRI_STRICT") // default

    generate!("next_head")
    generate!("prev_head")

    generate!("str2reg")

    // funcs
    generate!("func_t")
    generate!("get_func")
    generate!("get_func_num")
    generate!("get_func_qty")
    generate!("getn_func")

    generate!("calc_thunk_func_target")

    generate!("FUNC_NORET")
    generate!("FUNC_FAR")
    generate!("FUNC_LIB")
    generate!("FUNC_STATICDEF")
    generate!("FUNC_FRAME")
    generate!("FUNC_USERFAR")
    generate!("FUNC_HIDDEN")
    generate!("FUNC_THUNK")
    generate!("FUNC_BOTTOMBP")
    generate!("FUNC_NORET_PENDING")
    generate!("FUNC_SP_READY")
    generate!("FUNC_FUZZY_SP")
    generate!("FUNC_PROLOG_OK")
    generate!("FUNC_PURGED_OK")
    generate!("FUNC_TAIL")
    generate!("FUNC_LUMINA")
    generate!("FUNC_OUTLINE")
    generate!("FUNC_REANALYZE")
    generate!("FUNC_RESERVED")

    // gdl
    generate!("qbasic_block_t")
    generate!("qflow_chart_t")
    generate!("gdl_graph_t")
    generate_pod!("fc_block_type_t")

    generate!("FC_PRINT")
    generate!("FC_NOEXT")
    generate!("FC_RESERVED")
    generate!("FC_APPND")
    generate!("FC_CHKBREAK")
    generate!("FC_CALL_ENDS")
    generate!("FC_NOPREDS")
    generate!("FC_OUTLINES")

    // idalib
    generate!("open_database")
    generate!("close_database")

    generate!("make_signatures")
    generate!("enable_console_messages")
    generate!("set_screen_ea")

    // segment
    generate!("segment_t")
    generate!("getseg")
    generate!("getnseg")
    generate!("get_segm_qty")
    generate!("get_segm_by_name")

    generate!("SEG_NORM")
    generate!("SEG_XTRN")
    generate!("SEG_CODE")
    generate!("SEG_DATA")
    generate!("SEG_IMP")
    generate!("SEG_GRP")
    generate!("SEG_NULL")
    generate!("SEG_UNDF")
    generate!("SEG_BSS")
    generate!("SEG_ABSSYM")
    generate!("SEG_COMM")
    generate!("SEG_IMEM")
    generate!("SEG_MAX_SEGTYPE_CODE")

    generate!("saAbs")
    generate!("saRelByte")
    generate!("saRelWord")
    generate!("saRelPara")
    generate!("saRelPage")
    generate!("saRelDble")
    generate!("saRel4K")
    generate!("saGroup")
    generate!("saRel32Bytes")
    generate!("saRel64Bytes")
    generate!("saRelQword")
    generate!("saRel128Bytes")
    generate!("saRel512Bytes")
    generate!("saRel1024Bytes")
    generate!("saRel2048Bytes")
    generate!("saRel_MAX_ALIGN_CODE")

    generate!("SEGPERM_EXEC")
    generate!("SEGPERM_WRITE")
    generate!("SEGPERM_READ")
    generate!("SEGPERM_MAXVAL")

    // ua (we use insn_t, op_t, etc. from pod)
    generate!("decode_insn")

    extern_cpp_type!("insn_t", crate::pod::insn_t)
    extern_cpp_type!("op_t", crate::pod::op_t)

    generate_pod!("optype_t")

    generate!("o_void")
    generate!("o_reg")
    generate!("o_mem")
    generate!("o_phrase")
    generate!("o_displ")
    generate!("o_imm")
    generate!("o_far")
    generate!("o_near")
    generate!("o_idpspec0")
    generate!("o_idpspec1")
    generate!("o_idpspec2")
    generate!("o_idpspec3")
    generate!("o_idpspec4")
    generate!("o_idpspec5")

    generate!("dt_byte")
    generate!("dt_word")
    generate!("dt_dword")
    generate!("dt_float")
    generate!("dt_double")
    generate!("dt_tbyte")
    generate!("dt_packreal")
    generate!("dt_qword")
    generate!("dt_byte16")
    generate!("dt_code")
    generate!("dt_void")
    generate!("dt_fword")
    generate!("dt_bitfild")
    generate!("dt_string")
    generate!("dt_unicode")
    generate!("dt_ldbl")
    generate!("dt_byte32")
    generate!("dt_byte64")
    generate!("dt_half")

    // xref
    generate_pod!("xrefblk_t")

    // NOTE: autocxx fails to generate methods on xrefblk_t...
    generate!("xrefblk_t_first_from")
    generate!("xrefblk_t_next_from")
    generate!("xrefblk_t_first_to")
    generate!("xrefblk_t_next_to")

    generate!("XREF_ALL")
    generate!("XREF_FAR")
    generate!("XREF_DATA")

    generate!("cref_t")
    generate!("dref_t")

    generate!("XREF_USER")
    generate!("XREF_TAIL")
    generate!("XREF_BASE")
    generate!("XREF_MASK")
    generate!("XREF_PASTEND")

    generate!("has_external_refs")

    // comments
    generate!("get_cmt")
    generate!("set_cmt")
}

pub mod idp {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/idp.rs"));
}

pub mod inf {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/inf.rs"));

    unsafe impl cxx::ExternType for compiler_info_t {
        type Id = cxx::type_id!("compiler_info_t");
        type Kind = cxx::kind::Trivial;
    }

    pub use super::ffi::filetype_t;
    pub use super::ffix::{
        idalib_inf_abi_set_by_user, idalib_inf_allow_non_matched_ops, idalib_inf_allow_sigmulti,
        idalib_inf_append_sigcmt, idalib_inf_big_arg_align, idalib_inf_check_manual_ops,
        idalib_inf_check_unicode_strlits, idalib_inf_coagulate_code, idalib_inf_coagulate_data,
        idalib_inf_compress_idb, idalib_inf_create_all_xrefs, idalib_inf_create_func_from_call,
        idalib_inf_create_func_from_ptr, idalib_inf_create_func_tails,
        idalib_inf_create_jump_tables, idalib_inf_create_off_on_dref,
        idalib_inf_create_off_using_fixup, idalib_inf_create_strlit_on_xref,
        idalib_inf_data_offset, idalib_inf_dbg_no_store_path, idalib_inf_decode_fpp,
        idalib_inf_final_pass, idalib_inf_full_sp_ana, idalib_inf_gen_assume, idalib_inf_gen_lzero,
        idalib_inf_gen_null, idalib_inf_gen_org, idalib_inf_gen_tryblks, idalib_inf_get_abibits,
        idalib_inf_get_af, idalib_inf_get_af2, idalib_inf_get_app_bitness,
        idalib_inf_get_appcall_options, idalib_inf_get_apptype, idalib_inf_get_asmtype,
        idalib_inf_get_baseaddr, idalib_inf_get_bin_prefix_size, idalib_inf_get_cc,
        idalib_inf_get_cc_cm, idalib_inf_get_cc_defalign, idalib_inf_get_cc_id,
        idalib_inf_get_cc_size_b, idalib_inf_get_cc_size_e, idalib_inf_get_cc_size_i,
        idalib_inf_get_cc_size_l, idalib_inf_get_cc_size_ldbl, idalib_inf_get_cc_size_ll,
        idalib_inf_get_cc_size_s, idalib_inf_get_cmt_indent, idalib_inf_get_cmtflg,
        idalib_inf_get_database_change_count, idalib_inf_get_datatypes, idalib_inf_get_demnames,
        idalib_inf_get_filetype, idalib_inf_get_genflags, idalib_inf_get_highoff,
        idalib_inf_get_indent, idalib_inf_get_lenxref, idalib_inf_get_lflags,
        idalib_inf_get_limiter, idalib_inf_get_listnames, idalib_inf_get_long_demnames,
        idalib_inf_get_lowoff, idalib_inf_get_main, idalib_inf_get_margin,
        idalib_inf_get_max_autoname_len, idalib_inf_get_max_ea, idalib_inf_get_maxref,
        idalib_inf_get_min_ea, idalib_inf_get_nametype, idalib_inf_get_netdelta,
        idalib_inf_get_omax_ea, idalib_inf_get_omin_ea, idalib_inf_get_ostype,
        idalib_inf_get_outflags, idalib_inf_get_prefflag, idalib_inf_get_privrange,
        idalib_inf_get_privrange_end_ea, idalib_inf_get_privrange_start_ea,
        idalib_inf_get_procname, idalib_inf_get_refcmtnum, idalib_inf_get_short_demnames,
        idalib_inf_get_specsegs, idalib_inf_get_start_cs, idalib_inf_get_start_ea,
        idalib_inf_get_start_ip, idalib_inf_get_start_sp, idalib_inf_get_start_ss,
        idalib_inf_get_strlit_break, idalib_inf_get_strlit_flags, idalib_inf_get_strlit_pref,
        idalib_inf_get_strlit_sernum, idalib_inf_get_strlit_zeroes, idalib_inf_get_strtype,
        idalib_inf_get_type_xrefnum, idalib_inf_get_version, idalib_inf_get_xrefflag,
        idalib_inf_get_xrefnum, idalib_inf_guess_func_type, idalib_inf_handle_eh,
        idalib_inf_handle_rtti, idalib_inf_hide_comments, idalib_inf_hide_libfuncs,
        idalib_inf_huge_arg_align, idalib_inf_is_16bit, idalib_inf_is_32bit_exactly,
        idalib_inf_is_32bit_or_higher, idalib_inf_is_64bit, idalib_inf_is_auto_enabled,
        idalib_inf_is_be, idalib_inf_is_dll, idalib_inf_is_flat_off32, idalib_inf_is_graph_view,
        idalib_inf_is_hard_float, idalib_inf_is_kernel_mode, idalib_inf_is_limiter_empty,
        idalib_inf_is_limiter_thick, idalib_inf_is_limiter_thin, idalib_inf_is_mem_aligned4,
        idalib_inf_is_snapshot, idalib_inf_is_wide_high_byte_first, idalib_inf_line_pref_with_seg,
        idalib_inf_loading_idc, idalib_inf_macros_enabled, idalib_inf_map_stkargs,
        idalib_inf_mark_code, idalib_inf_merge_strlits, idalib_inf_no_store_user_info,
        idalib_inf_noflow_to_data, idalib_inf_noret_ana, idalib_inf_op_offset, idalib_inf_pack_idb,
        idalib_inf_pack_stkargs, idalib_inf_prefix_show_funcoff, idalib_inf_prefix_show_segaddr,
        idalib_inf_prefix_show_stack, idalib_inf_prefix_truncate_opcode_bytes,
        idalib_inf_propagate_regargs, idalib_inf_propagate_stkargs, idalib_inf_readonly_idb,
        idalib_inf_rename_jumpfunc, idalib_inf_rename_nullsub, idalib_inf_should_create_stkvars,
        idalib_inf_should_trace_sp, idalib_inf_show_all_comments, idalib_inf_show_auto,
        idalib_inf_show_hidden_funcs, idalib_inf_show_hidden_insns, idalib_inf_show_hidden_segms,
        idalib_inf_show_line_pref, idalib_inf_show_repeatables, idalib_inf_show_src_linnum,
        idalib_inf_show_void, idalib_inf_show_xref_fncoff, idalib_inf_show_xref_seg,
        idalib_inf_show_xref_tmarks, idalib_inf_show_xref_val, idalib_inf_stack_ldbl,
        idalib_inf_stack_varargs, idalib_inf_strlit_autocmt, idalib_inf_strlit_name_bit,
        idalib_inf_strlit_names, idalib_inf_strlit_savecase, idalib_inf_strlit_serial_names,
        idalib_inf_test_mode, idalib_inf_trace_flow, idalib_inf_truncate_on_del,
        idalib_inf_unicode_strlits, idalib_inf_use_allasm, idalib_inf_use_flirt,
        idalib_inf_use_gcc_layout,
    };
}

pub mod pod {
    #![allow(non_camel_case_types)]
    #![allow(non_upper_case_globals)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/pod.rs"));

    unsafe impl cxx::ExternType for op_t {
        type Id = cxx::type_id!("op_t");
        type Kind = cxx::kind::Trivial;
    }

    unsafe impl cxx::ExternType for insn_t {
        type Id = cxx::type_id!("insn_t");
        type Kind = cxx::kind::Trivial;
    }
}

#[cxx::bridge]
mod ffix {
    unsafe extern "C++" {
        include!("autocxxgen_ffi.h");
        include!("ida/idalib.hpp");

        include!("types.h");
        include!("bytes_extras.h");
        include!("comments_extras.h");
        include!("entry_extras.h");
        include!("func_extras.h");
        include!("inf_extras.h");
        include!("ph_extras.h");
        include!("segm_extras.h");

        type c_short = autocxx::c_short;
        type c_int = autocxx::c_int;
        type c_uint = autocxx::c_uint;
        type c_longlong = autocxx::c_longlong;
        type c_ulonglong = autocxx::c_ulonglong;

        // type comp_t = super::ffi::comp_t;
        type compiler_info_t = super::inf::compiler_info_t;
        // type cm_t = super::ffi::cm_t;
        type filetype_t = super::ffi::filetype_t;
        type range_t = super::ffi::range_t;
        // type uval_t = autocxx::c_ulonglong;

        type func_t = super::ffi::func_t;
        type processor_t = super::ffi::processor_t;
        type qflow_chart_t = super::ffi::qflow_chart_t;
        type qbasic_block_t = super::ffi::qbasic_block_t;
        type segment_t = super::ffi::segment_t;

        unsafe fn init_library(argc: c_int, argv: *mut *mut c_char) -> c_int;

        // NOTE: we can't use uval_t here due to it resolving to c_ulonglong,
        // which causes `verify_extern_type` to fail...
        unsafe fn idalib_entry_name(e: c_ulonglong) -> Result<String>;

        unsafe fn idalib_func_flags(f: *const func_t) -> u64;
        unsafe fn idalib_func_name(f: *const func_t) -> Result<String>;

        unsafe fn idalib_func_flow_chart(
            f: *mut func_t,
            flags: c_int,
        ) -> Result<UniquePtr<qflow_chart_t>>;

        unsafe fn idalib_inf_get_version() -> u16;
        unsafe fn idalib_inf_get_genflags() -> u16;
        unsafe fn idalib_inf_is_auto_enabled() -> bool;
        unsafe fn idalib_inf_use_allasm() -> bool;
        unsafe fn idalib_inf_loading_idc() -> bool;
        unsafe fn idalib_inf_no_store_user_info() -> bool;
        unsafe fn idalib_inf_readonly_idb() -> bool;
        unsafe fn idalib_inf_check_manual_ops() -> bool;
        unsafe fn idalib_inf_allow_non_matched_ops() -> bool;
        unsafe fn idalib_inf_is_graph_view() -> bool;
        unsafe fn idalib_inf_get_lflags() -> u32;
        unsafe fn idalib_inf_decode_fpp() -> bool;
        unsafe fn idalib_inf_is_32bit_or_higher() -> bool;
        unsafe fn idalib_inf_is_32bit_exactly() -> bool;
        unsafe fn idalib_inf_is_16bit() -> bool;
        unsafe fn idalib_inf_is_64bit() -> bool;
        unsafe fn idalib_inf_is_dll() -> bool;
        unsafe fn idalib_inf_is_flat_off32() -> bool;
        unsafe fn idalib_inf_is_be() -> bool;
        unsafe fn idalib_inf_is_wide_high_byte_first() -> bool;
        unsafe fn idalib_inf_dbg_no_store_path() -> bool;
        unsafe fn idalib_inf_is_snapshot() -> bool;
        unsafe fn idalib_inf_pack_idb() -> bool;
        unsafe fn idalib_inf_compress_idb() -> bool;
        unsafe fn idalib_inf_is_kernel_mode() -> bool;
        unsafe fn idalib_inf_get_app_bitness() -> c_uint;
        unsafe fn idalib_inf_get_database_change_count() -> u32;
        unsafe fn idalib_inf_get_filetype() -> filetype_t;
        unsafe fn idalib_inf_get_ostype() -> u16;
        unsafe fn idalib_inf_get_apptype() -> u16;
        unsafe fn idalib_inf_get_asmtype() -> u8;
        unsafe fn idalib_inf_get_specsegs() -> u8;
        unsafe fn idalib_inf_get_af() -> u32;
        unsafe fn idalib_inf_trace_flow() -> bool;
        unsafe fn idalib_inf_mark_code() -> bool;
        unsafe fn idalib_inf_create_jump_tables() -> bool;
        unsafe fn idalib_inf_noflow_to_data() -> bool;
        unsafe fn idalib_inf_create_all_xrefs() -> bool;
        unsafe fn idalib_inf_create_func_from_ptr() -> bool;
        unsafe fn idalib_inf_create_func_from_call() -> bool;
        unsafe fn idalib_inf_create_func_tails() -> bool;
        unsafe fn idalib_inf_should_create_stkvars() -> bool;
        unsafe fn idalib_inf_propagate_stkargs() -> bool;
        unsafe fn idalib_inf_propagate_regargs() -> bool;
        unsafe fn idalib_inf_should_trace_sp() -> bool;
        unsafe fn idalib_inf_full_sp_ana() -> bool;
        unsafe fn idalib_inf_noret_ana() -> bool;
        unsafe fn idalib_inf_guess_func_type() -> bool;
        unsafe fn idalib_inf_truncate_on_del() -> bool;
        unsafe fn idalib_inf_create_strlit_on_xref() -> bool;
        unsafe fn idalib_inf_check_unicode_strlits() -> bool;
        unsafe fn idalib_inf_create_off_using_fixup() -> bool;
        unsafe fn idalib_inf_create_off_on_dref() -> bool;
        unsafe fn idalib_inf_op_offset() -> bool;
        unsafe fn idalib_inf_data_offset() -> bool;
        unsafe fn idalib_inf_use_flirt() -> bool;
        unsafe fn idalib_inf_append_sigcmt() -> bool;
        unsafe fn idalib_inf_allow_sigmulti() -> bool;
        unsafe fn idalib_inf_hide_libfuncs() -> bool;
        unsafe fn idalib_inf_rename_jumpfunc() -> bool;
        unsafe fn idalib_inf_rename_nullsub() -> bool;
        unsafe fn idalib_inf_coagulate_data() -> bool;
        unsafe fn idalib_inf_coagulate_code() -> bool;
        unsafe fn idalib_inf_final_pass() -> bool;
        unsafe fn idalib_inf_get_af2() -> u32;
        unsafe fn idalib_inf_handle_eh() -> bool;
        unsafe fn idalib_inf_handle_rtti() -> bool;
        unsafe fn idalib_inf_macros_enabled() -> bool;
        unsafe fn idalib_inf_merge_strlits() -> bool;
        unsafe fn idalib_inf_get_baseaddr() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ss() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_cs() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ip() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_start_sp() -> c_ulonglong;
        unsafe fn idalib_inf_get_main() -> c_ulonglong;
        unsafe fn idalib_inf_get_min_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_max_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omin_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_omax_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_lowoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_highoff() -> c_ulonglong;
        unsafe fn idalib_inf_get_maxref() -> c_ulonglong;
        unsafe fn idalib_inf_get_netdelta() -> c_longlong;
        unsafe fn idalib_inf_get_xrefnum() -> u8;
        unsafe fn idalib_inf_get_type_xrefnum() -> u8;
        unsafe fn idalib_inf_get_refcmtnum() -> u8;
        unsafe fn idalib_inf_get_xrefflag() -> u8;
        unsafe fn idalib_inf_show_xref_seg() -> bool;
        unsafe fn idalib_inf_show_xref_tmarks() -> bool;
        unsafe fn idalib_inf_show_xref_fncoff() -> bool;
        unsafe fn idalib_inf_show_xref_val() -> bool;
        unsafe fn idalib_inf_get_max_autoname_len() -> u16;
        unsafe fn idalib_inf_get_nametype() -> c_char;
        unsafe fn idalib_inf_get_short_demnames() -> u32;
        unsafe fn idalib_inf_get_long_demnames() -> u32;
        unsafe fn idalib_inf_get_demnames() -> u8;
        unsafe fn idalib_inf_get_listnames() -> u8;
        unsafe fn idalib_inf_get_indent() -> u8;
        unsafe fn idalib_inf_get_cmt_indent() -> u8;
        unsafe fn idalib_inf_get_margin() -> u16;
        unsafe fn idalib_inf_get_lenxref() -> u16;
        unsafe fn idalib_inf_get_outflags() -> u32;
        unsafe fn idalib_inf_show_void() -> bool;
        unsafe fn idalib_inf_show_auto() -> bool;
        unsafe fn idalib_inf_gen_null() -> bool;
        unsafe fn idalib_inf_show_line_pref() -> bool;
        unsafe fn idalib_inf_line_pref_with_seg() -> bool;
        unsafe fn idalib_inf_gen_lzero() -> bool;
        unsafe fn idalib_inf_gen_org() -> bool;
        unsafe fn idalib_inf_gen_assume() -> bool;
        unsafe fn idalib_inf_gen_tryblks() -> bool;
        unsafe fn idalib_inf_get_cmtflg() -> u8;
        unsafe fn idalib_inf_show_repeatables() -> bool;
        unsafe fn idalib_inf_show_all_comments() -> bool;
        unsafe fn idalib_inf_hide_comments() -> bool;
        unsafe fn idalib_inf_show_src_linnum() -> bool;
        unsafe fn idalib_inf_test_mode() -> bool;
        unsafe fn idalib_inf_show_hidden_insns() -> bool;
        unsafe fn idalib_inf_show_hidden_funcs() -> bool;
        unsafe fn idalib_inf_show_hidden_segms() -> bool;
        unsafe fn idalib_inf_get_limiter() -> u8;
        unsafe fn idalib_inf_is_limiter_thin() -> bool;
        unsafe fn idalib_inf_is_limiter_thick() -> bool;
        unsafe fn idalib_inf_is_limiter_empty() -> bool;
        unsafe fn idalib_inf_get_bin_prefix_size() -> c_short;
        unsafe fn idalib_inf_get_prefflag() -> u8;
        unsafe fn idalib_inf_prefix_show_segaddr() -> bool;
        unsafe fn idalib_inf_prefix_show_funcoff() -> bool;
        unsafe fn idalib_inf_prefix_show_stack() -> bool;
        unsafe fn idalib_inf_prefix_truncate_opcode_bytes() -> bool;
        unsafe fn idalib_inf_get_strlit_flags() -> u8;
        unsafe fn idalib_inf_strlit_names() -> bool;
        unsafe fn idalib_inf_strlit_name_bit() -> bool;
        unsafe fn idalib_inf_strlit_serial_names() -> bool;
        unsafe fn idalib_inf_unicode_strlits() -> bool;
        unsafe fn idalib_inf_strlit_autocmt() -> bool;
        unsafe fn idalib_inf_strlit_savecase() -> bool;
        unsafe fn idalib_inf_get_strlit_break() -> u8;
        unsafe fn idalib_inf_get_strlit_zeroes() -> c_char;
        unsafe fn idalib_inf_get_strtype() -> i32;
        unsafe fn idalib_inf_get_strlit_sernum() -> c_ulonglong;
        unsafe fn idalib_inf_get_datatypes() -> c_ulonglong;
        unsafe fn idalib_inf_get_abibits() -> u32;
        unsafe fn idalib_inf_is_mem_aligned4() -> bool;
        unsafe fn idalib_inf_pack_stkargs() -> bool;
        unsafe fn idalib_inf_big_arg_align() -> bool;
        unsafe fn idalib_inf_stack_ldbl() -> bool;
        unsafe fn idalib_inf_stack_varargs() -> bool;
        unsafe fn idalib_inf_is_hard_float() -> bool;
        unsafe fn idalib_inf_abi_set_by_user() -> bool;
        unsafe fn idalib_inf_use_gcc_layout() -> bool;
        unsafe fn idalib_inf_map_stkargs() -> bool;
        unsafe fn idalib_inf_huge_arg_align() -> bool;
        unsafe fn idalib_inf_get_appcall_options() -> u32;
        unsafe fn idalib_inf_get_privrange_start_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_privrange_end_ea() -> c_ulonglong;
        unsafe fn idalib_inf_get_cc_id() -> u8;
        unsafe fn idalib_inf_get_cc_cm() -> u8;
        unsafe fn idalib_inf_get_cc_size_i() -> u8;
        unsafe fn idalib_inf_get_cc_size_b() -> u8;
        unsafe fn idalib_inf_get_cc_size_e() -> u8;
        unsafe fn idalib_inf_get_cc_defalign() -> u8;
        unsafe fn idalib_inf_get_cc_size_s() -> u8;
        unsafe fn idalib_inf_get_cc_size_l() -> u8;
        unsafe fn idalib_inf_get_cc_size_ll() -> u8;
        unsafe fn idalib_inf_get_cc_size_ldbl() -> u8;
        unsafe fn idalib_inf_get_procname() -> String;
        unsafe fn idalib_inf_get_strlit_pref() -> String;
        unsafe fn idalib_inf_get_cc(out: *mut compiler_info_t) -> bool;
        unsafe fn idalib_inf_get_privrange(out: *mut range_t) -> bool;

        unsafe fn idalib_ph_id(ph: *const processor_t) -> i32;
        unsafe fn idalib_ph_short_name(ph: *const processor_t) -> String;
        unsafe fn idalib_ph_long_name(ph: *const processor_t) -> String;

        unsafe fn idalib_qflow_graph_getn_block(
            f: *const qflow_chart_t,
            n: usize,
        ) -> *const qbasic_block_t;

        unsafe fn idalib_qbasic_block_succs<'a>(b: *const qbasic_block_t) -> &'a [c_int];
        unsafe fn idalib_qbasic_block_preds<'a>(b: *const qbasic_block_t) -> &'a [c_int];

        unsafe fn idalib_segm_name(s: *const segment_t) -> Result<String>;
        unsafe fn idalib_segm_bytes(s: *const segment_t, buf: &mut Vec<u8>) -> Result<usize>;
        unsafe fn idalib_segm_align(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_perm(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_bitness(s: *const segment_t) -> u8;
        unsafe fn idalib_segm_type(s: *const segment_t) -> u8;

        unsafe fn idalib_get_cmt(ea: c_ulonglong, rptble: bool) -> String;

        unsafe fn idalib_get_byte(ea: c_ulonglong) -> u8;
        unsafe fn idalib_get_word(ea: c_ulonglong) -> u16;
        unsafe fn idalib_get_dword(ea: c_ulonglong) -> u32;
        unsafe fn idalib_get_qword(ea: c_ulonglong) -> u64;
        unsafe fn idalib_get_bytes(ea: c_ulonglong, buf: &mut Vec<u8>) -> Result<usize>;
    }
}

pub use ffi::{ea_t, range_t};
pub const BADADDR: ea_t = into_ea(0xffffffff_ffffffffu64);

#[inline(always)]
pub const fn into_ea(v: u64) -> ea_t {
    c_ulonglong(v)
}

#[inline(always)]
pub const fn from_ea(v: ea_t) -> u64 {
    v.0
}

pub mod entry {
    pub use super::ffi::{get_entry, get_entry_ordinal, get_entry_qty, uval_t};
    pub use super::ffix::idalib_entry_name;
}

pub mod insn {
    use std::mem::MaybeUninit;

    use super::ea_t;
    use super::ffi::decode_insn;

    pub use super::pod::insn_t;

    pub fn decode(ea: ea_t) -> Option<insn_t> {
        let mut insn = MaybeUninit::<insn_t>::zeroed();
        unsafe { (decode_insn(insn.as_mut_ptr(), ea).0 > 0).then(|| insn.assume_init()) }
    }

    pub mod op {
        pub use super::super::ffi::{
            dt_bitfild, dt_byte, dt_byte16, dt_byte32, dt_byte64, dt_code, dt_double, dt_dword,
            dt_float, dt_fword, dt_half, dt_ldbl, dt_packreal, dt_qword, dt_string, dt_tbyte,
            dt_unicode, dt_void, dt_word, o_displ, o_far, o_idpspec0, o_idpspec1, o_idpspec2,
            o_idpspec3, o_idpspec4, o_idpspec5, o_imm, o_mem, o_near, o_phrase, o_reg, o_void,
            IRI_EXTENDED, IRI_RET_LITERALLY, IRI_SKIP_RETTARGET, IRI_STRICT,
        };
        pub use super::super::pod::{
            op_dtype_t, op_t, optype_t, OF_NO_BASE_DISP, OF_NUMBER, OF_OUTER_DISP, OF_SHOW,
        };
    }

    pub mod arm {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_arm.rs"));
    }

    pub mod mips {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_mips.rs"));
    }

    pub mod x86 {
        #![allow(non_camel_case_types)]
        #![allow(non_upper_case_globals)]
        #![allow(unused)]

        include!(concat!(env!("OUT_DIR"), "/insn_x86.rs"));
    }
}

pub mod func {
    pub use super::ffi::{
        calc_thunk_func_target, fc_block_type_t, func_t, gdl_graph_t, get_func, get_func_num,
        get_func_qty, getn_func, qbasic_block_t, qflow_chart_t,
    };
    pub use super::ffix::{
        idalib_func_flags, idalib_func_flow_chart, idalib_func_name, idalib_qbasic_block_preds,
        idalib_qbasic_block_succs, idalib_qflow_graph_getn_block,
    };

    pub mod flags {
        pub use super::super::ffi::{
            FUNC_BOTTOMBP, FUNC_FAR, FUNC_FRAME, FUNC_FUZZY_SP, FUNC_HIDDEN, FUNC_LIB, FUNC_LUMINA,
            FUNC_NORET, FUNC_NORET_PENDING, FUNC_OUTLINE, FUNC_PROLOG_OK, FUNC_PURGED_OK,
            FUNC_REANALYZE, FUNC_RESERVED, FUNC_SP_READY, FUNC_STATICDEF, FUNC_TAIL, FUNC_THUNK,
            FUNC_USERFAR,
        };
    }

    pub mod cfg_flags {
        pub use super::super::ffi::{
            FC_APPND, FC_CALL_ENDS, FC_CHKBREAK, FC_NOEXT, FC_NOPREDS, FC_OUTLINES, FC_PRINT,
            FC_RESERVED,
        };
    }
}

pub mod processor {
    pub use super::ffi::{get_ph, processor_t};
    pub use super::ffix::{idalib_ph_id, idalib_ph_long_name, idalib_ph_short_name};

    pub use super::idp as ids;
}

pub mod segment {
    pub use super::ffi::{
        get_segm_by_name, get_segm_qty, getnseg, getseg, saAbs, saGroup, saRel1024Bytes,
        saRel128Bytes, saRel2048Bytes, saRel32Bytes, saRel4K, saRel512Bytes, saRel64Bytes,
        saRelByte, saRelDble, saRelPage, saRelPara, saRelQword, saRelWord, saRel_MAX_ALIGN_CODE,
        segment_t, SEGPERM_EXEC, SEGPERM_MAXVAL, SEGPERM_READ, SEGPERM_WRITE, SEG_ABSSYM, SEG_BSS,
        SEG_CODE, SEG_COMM, SEG_DATA, SEG_GRP, SEG_IMEM, SEG_IMP, SEG_MAX_SEGTYPE_CODE, SEG_NORM,
        SEG_NULL, SEG_UNDF, SEG_XTRN,
    };

    pub use super::ffix::{
        idalib_segm_align, idalib_segm_bitness, idalib_segm_bytes, idalib_segm_name,
        idalib_segm_perm, idalib_segm_type,
    };
}

pub mod bytes {
    pub use super::ffix::{
        idalib_get_byte, idalib_get_bytes, idalib_get_dword, idalib_get_qword, idalib_get_word,
    };
}

pub mod util {
    pub use super::ffi::{
        is_align_insn, is_basic_block_end, is_call_insn, is_indirect_jump_insn, is_ret_insn,
        next_head, prev_head, str2reg,
    };
}

pub mod xref {
    pub use super::ffi::{
        cref_t, dref_t, has_external_refs, xrefblk_t, xrefblk_t_first_from, xrefblk_t_first_to,
        xrefblk_t_next_from, xrefblk_t_next_to, XREF_ALL, XREF_BASE, XREF_DATA, XREF_FAR,
        XREF_MASK, XREF_PASTEND, XREF_TAIL, XREF_USER,
    };
}

pub mod comments {
    pub use super::ffi::set_cmt;
    pub use super::ffix::idalib_get_cmt;
}

pub mod ida {
    use std::env;
    use std::ffi::CString;
    use std::path::Path;
    use std::ptr;

    use autocxx::prelude::*;

    use super::platform::is_main_thread;
    use super::{ea_t, ffi, ffix, IDAError};

    // NOTE: once; main thread
    pub fn init_library() -> Result<(), IDAError> {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }

        env::set_var("TVHEADLESS", "1");

        let res = unsafe { self::ffix::init_library(c_int(0), ptr::null_mut()) };

        if res != c_int(0) {
            Err(IDAError::Init(res))
        } else {
            Ok(())
        }
    }

    pub fn make_signatures(only_pat: bool) -> Result<(), IDAError> {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }

        if unsafe { self::ffi::make_signatures(only_pat) } {
            Ok(())
        } else {
            Err(IDAError::MakeSigs)
        }
    }

    pub fn enable_console_messages(enable: bool) {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }

        unsafe { self::ffi::enable_console_messages(enable) }
    }

    pub fn set_screen_ea(ea: ea_t) {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }
        unsafe { self::ffi::set_screen_ea(ea) }
    }

    pub fn open_database(path: impl AsRef<Path>) -> Result<(), IDAError> {
        open_database_with(path, true)
    }

    // NOTE: main thread
    pub fn open_database_with(path: impl AsRef<Path>, auto_analysis: bool) -> Result<(), IDAError> {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }

        let path = CString::new(path.as_ref().to_string_lossy().as_ref()).map_err(IDAError::ffi)?;

        let res = unsafe { self::ffi::open_database(path.as_ptr(), auto_analysis) };

        if res != c_int(0) {
            Err(IDAError::OpenDb(res))
        } else {
            Ok(())
        }
    }

    pub fn close_database() {
        close_database_with(true)
    }

    pub fn close_database_with(save: bool) {
        if !is_main_thread() {
            panic!("IDA cannot function correctly when not running on the main thread");
        }

        unsafe { self::ffi::close_database(save) }
    }
}
