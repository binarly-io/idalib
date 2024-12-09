use bitflags::bitflags;

use crate::ffi::typeinf::*;

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FieldAttributes: u32 {
        const BASECLASS = TAFLD_BASECLASS as _;
        const UNALIGNED = TAFLD_UNALIGNED as _;
        const VIRTBASE = TAFLD_VIRTBASE as _;
        const VFTABLE = TAFLD_VFTABLE as _;
        const METHOD = TAFLD_METHOD as _;
        const GAP = TAFLD_GAP as _;
        const REGCMT = TAFLD_REGCMT as _;
        const FRAME_R = TAFLD_FRAME_R as _;
        const FRAME_S = TAFLD_FRAME_S as _;
        const BYTIL = TAFLD_BYTIL as _;
    }
}
