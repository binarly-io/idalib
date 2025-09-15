use std::marker::PhantomData;

use crate::Address;
pub use crate::ffi::processor::ids as id;
use crate::ffi::processor::*;
use crate::idb::IDB;

pub struct Processor<'a> {
    ptr: *const processor_t,
    _marker: PhantomData<&'a IDB>,
}

pub type ProcessorId = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessorFamily(ProcessorId);

impl ProcessorFamily {
    pub const fn is_386(&self) -> bool {
        self.0 == id::PLFM_386 as _
    }

    pub const fn is_z80(&self) -> bool {
        self.0 == id::PLFM_Z80 as _
    }

    pub const fn is_i860(&self) -> bool {
        self.0 == id::PLFM_I860 as _
    }

    pub const fn is_8051(&self) -> bool {
        self.0 == id::PLFM_8051 as _
    }

    pub const fn is_tms(&self) -> bool {
        self.0 == id::PLFM_TMS as _
    }

    pub const fn is_6502(&self) -> bool {
        self.0 == id::PLFM_6502 as _
    }

    pub const fn is_pdp(&self) -> bool {
        self.0 == id::PLFM_PDP as _
    }

    pub const fn is_68k(&self) -> bool {
        self.0 == id::PLFM_68K as _
    }

    pub const fn is_java(&self) -> bool {
        self.0 == id::PLFM_JAVA as _
    }

    pub const fn is_6800(&self) -> bool {
        self.0 == id::PLFM_6800 as _
    }

    pub const fn is_st7(&self) -> bool {
        self.0 == id::PLFM_ST7 as _
    }

    pub const fn is_mc6812(&self) -> bool {
        self.0 == id::PLFM_MC6812 as _
    }

    pub const fn is_mips(&self) -> bool {
        self.0 == id::PLFM_MIPS as _
    }

    pub const fn is_arm(&self) -> bool {
        self.0 == id::PLFM_ARM as _
    }

    pub const fn is_tmsc6(&self) -> bool {
        self.0 == id::PLFM_TMSC6 as _
    }

    pub const fn is_ppc(&self) -> bool {
        self.0 == id::PLFM_PPC as _
    }

    pub const fn is_80196(&self) -> bool {
        self.0 == id::PLFM_80196 as _
    }

    pub const fn is_z8(&self) -> bool {
        self.0 == id::PLFM_Z8 as _
    }

    pub const fn is_sh(&self) -> bool {
        self.0 == id::PLFM_SH as _
    }

    pub const fn is_net(&self) -> bool {
        self.0 == id::PLFM_NET as _
    }

    pub const fn is_avr(&self) -> bool {
        self.0 == id::PLFM_AVR as _
    }

    pub const fn is_h8(&self) -> bool {
        self.0 == id::PLFM_H8 as _
    }

    pub const fn is_pic(&self) -> bool {
        self.0 == id::PLFM_PIC as _
    }

    pub const fn is_sparc(&self) -> bool {
        self.0 == id::PLFM_SPARC as _
    }

    pub const fn is_alpha(&self) -> bool {
        self.0 == id::PLFM_ALPHA as _
    }

    pub const fn is_hppa(&self) -> bool {
        self.0 == id::PLFM_HPPA as _
    }

    pub const fn is_h8500(&self) -> bool {
        self.0 == id::PLFM_H8500 as _
    }

    pub const fn is_tricore(&self) -> bool {
        self.0 == id::PLFM_TRICORE as _
    }

    pub const fn is_dsp56k(&self) -> bool {
        self.0 == id::PLFM_DSP56K as _
    }

    pub const fn is_c166(&self) -> bool {
        self.0 == id::PLFM_C166 as _
    }

    pub const fn is_st20(&self) -> bool {
        self.0 == id::PLFM_ST20 as _
    }

    pub const fn is_ia64(&self) -> bool {
        self.0 == id::PLFM_IA64 as _
    }

    pub const fn is_i960(&self) -> bool {
        self.0 == id::PLFM_I960 as _
    }

    pub const fn is_f2mc(&self) -> bool {
        self.0 == id::PLFM_F2MC as _
    }

    pub const fn is_tms320c54(&self) -> bool {
        self.0 == id::PLFM_TMS320C54 as _
    }

    pub const fn is_tms320c55(&self) -> bool {
        self.0 == id::PLFM_TMS320C55 as _
    }

    pub const fn is_trimedia(&self) -> bool {
        self.0 == id::PLFM_TRIMEDIA as _
    }

    pub const fn is_m32r(&self) -> bool {
        self.0 == id::PLFM_M32R as _
    }

    pub const fn is_nec_78k0(&self) -> bool {
        self.0 == id::PLFM_NEC_78K0 as _
    }

    pub const fn is_nec_78k0s(&self) -> bool {
        self.0 == id::PLFM_NEC_78K0S as _
    }

    pub const fn is_m740(&self) -> bool {
        self.0 == id::PLFM_M740 as _
    }

    pub const fn is_m7700(&self) -> bool {
        self.0 == id::PLFM_M7700 as _
    }

    pub const fn is_st9(&self) -> bool {
        self.0 == id::PLFM_ST9 as _
    }

    pub const fn is_fr(&self) -> bool {
        self.0 == id::PLFM_FR as _
    }

    pub const fn is_mc6816(&self) -> bool {
        self.0 == id::PLFM_MC6816 as _
    }

    pub const fn is_m7900(&self) -> bool {
        self.0 == id::PLFM_M7900 as _
    }

    pub const fn is_tms320c3(&self) -> bool {
        self.0 == id::PLFM_TMS320C3 as _
    }

    pub const fn is_kr1878(&self) -> bool {
        self.0 == id::PLFM_KR1878 as _
    }

    pub const fn is_ad218x(&self) -> bool {
        self.0 == id::PLFM_AD218X as _
    }

    pub const fn is_oakdsp(&self) -> bool {
        self.0 == id::PLFM_OAKDSP as _
    }

    pub const fn is_tlcs900(&self) -> bool {
        self.0 == id::PLFM_TLCS900 as _
    }

    pub const fn is_c39(&self) -> bool {
        self.0 == id::PLFM_C39 as _
    }

    pub const fn is_cr16(&self) -> bool {
        self.0 == id::PLFM_CR16 as _
    }

    pub const fn is_mn102l00(&self) -> bool {
        self.0 == id::PLFM_MN102L00 as _
    }

    pub const fn is_tms320c1x(&self) -> bool {
        self.0 == id::PLFM_TMS320C1X as _
    }

    pub const fn is_nec_v850x(&self) -> bool {
        self.0 == id::PLFM_NEC_V850X as _
    }

    pub const fn is_scr_adpt(&self) -> bool {
        self.0 == id::PLFM_SCR_ADPT as _
    }

    pub const fn is_ebc(&self) -> bool {
        self.0 == id::PLFM_EBC as _
    }

    pub const fn is_msp430(&self) -> bool {
        self.0 == id::PLFM_MSP430 as _
    }

    pub const fn is_spu(&self) -> bool {
        self.0 == id::PLFM_SPU as _
    }

    pub const fn is_dalvik(&self) -> bool {
        self.0 == id::PLFM_DALVIK as _
    }

    pub const fn is_65c816(&self) -> bool {
        self.0 == id::PLFM_65C816 as _
    }

    pub const fn is_m16c(&self) -> bool {
        self.0 == id::PLFM_M16C as _
    }

    pub const fn is_arc(&self) -> bool {
        self.0 == id::PLFM_ARC as _
    }

    pub const fn is_unsp(&self) -> bool {
        self.0 == id::PLFM_UNSP as _
    }

    pub const fn is_tms320c28(&self) -> bool {
        self.0 == id::PLFM_TMS320C28 as _
    }

    pub const fn is_dsp96k(&self) -> bool {
        self.0 == id::PLFM_DSP96K as _
    }

    pub const fn is_spc700(&self) -> bool {
        self.0 == id::PLFM_SPC700 as _
    }

    pub const fn is_ad2106x(&self) -> bool {
        self.0 == id::PLFM_AD2106X as _
    }

    pub const fn is_pic16(&self) -> bool {
        self.0 == id::PLFM_PIC16 as _
    }

    pub const fn is_s390(&self) -> bool {
        self.0 == id::PLFM_S390 as _
    }

    pub const fn is_xtensa(&self) -> bool {
        self.0 == id::PLFM_XTENSA as _
    }

    pub const fn is_riscv(&self) -> bool {
        self.0 == id::PLFM_RISCV as _
    }

    pub const fn is_rl78(&self) -> bool {
        self.0 == id::PLFM_RL78 as _
    }

    pub const fn is_rx(&self) -> bool {
        self.0 == id::PLFM_RX as _
    }

    pub const fn is_wasm(&self) -> bool {
        self.0 == id::PLFM_WASM as _
    }
}

impl<'a> Processor<'a> {
    pub(crate) const fn from_ptr(ptr: *const processor_t) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn id(&self) -> ProcessorId {
        unsafe { idalib_ph_id(self.ptr) }
    }

    pub fn family(&self) -> ProcessorFamily {
        ProcessorFamily(self.id())
    }

    pub fn long_name(&self) -> String {
        unsafe { idalib_ph_long_name(self.ptr) }
    }

    pub fn short_name(&self) -> String {
        unsafe { idalib_ph_short_name(self.ptr) }
    }

    pub fn is_thumb_at(&self, ea: Address) -> bool {
        unsafe { idalib_is_thumb_at(self.ptr, ea.into()) }
    }
}
