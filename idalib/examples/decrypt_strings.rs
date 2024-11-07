// tested samples:
// e8cdc0697748e702cf2916a2c5670325a891402ee38c98d91873a0f03e3f9025

use idalib::idb::*;
use idalib::insn::x86::{NN_lea, NN_mov};
use idalib::insn::OperandType;
use idalib::xref::{XRef, XRefQuery};
use idalib::is_valid_license;

const RCX: u16 = 1;
const RDX: u16 = 2;

#[derive(Default, Debug, Copy, Clone)]
struct EncString {
    address: Option<u64>,
    size: Option<usize>,
}

impl EncString {
    fn set_address(&mut self, address: u64) {
        self.address = Some(address)
    }

    fn set_size(&mut self, size: usize) {
        self.size = Some(size)
    }

    fn ready(self) -> bool {
        self.address.is_some() && self.size.is_some()
    }

    #[inline]
    fn shrink_byte(b: u8) -> u8 {
        if b > 0x7F {
            b - 0x60
        } else {
            b
        }
    }

    fn decrypt(&self, idb: &IDB) -> Option<String> {
        let addr = self.address?;
        let size = self.size?;

        if size < 3 {
            return None;
        }

        let enc = idb.get_bytes(addr, size * 2);
        let mut dec = vec![0u8; size + 1];

        dec[size - 1] = Self::shrink_byte(enc[2 * (size - 1)]);

        for i in 0..size {
            let kbyte = Self::shrink_byte(enc[2 * (size - i - 1)]);
            dec[size - i - 1] = kbyte ^ dec[size - i]
        }

        for i in (0..size - 1).step_by(2) {
            dec.swap(i, i + 1);
        }

        for i in 0..(size >> 1) {
            dec.swap(i, size - 1 - i);
        }

        dec.truncate(size - 1);

        String::from_utf8(dec).ok()
    }
}

fn handle_xref(idb: &IDB, xref: &XRef) -> Option<EncString> {
    let mut ea = xref.from();
    let segment = idb.segment_at(ea)?;
    println!("xref: {:#x} (in {})", ea, segment.name()?);

    let mut enc_string = EncString::default();

    loop {
        ea = idb.prev_head(ea)?;
        let insn = idb.insn_at(ea)?;
        if insn.is_basic_block_end(true) {
            break;
        }

        if insn.itype() == NN_lea
            && insn.operand_count() > 1
            && insn.operand(0)?.type_() == OperandType::Reg
        {
            let reg = insn.operand(0)?.reg();
            let type_ = insn.operand(1)?.type_();
            if reg == Some(RCX) && type_ == OperandType::Mem {
                enc_string.set_address(insn.operand(1)?.addr()?);
            } else if reg == Some(RDX) && type_ == OperandType::Displ {
                enc_string.set_size(insn.operand(1)?.addr()? as usize);
            }
        }

        if insn.itype() == NN_mov
            && insn.operand_count() > 1
            && insn.operand(0)?.type_() == OperandType::Reg
        {
            let reg = insn.operand(0)?.reg();
            let type_ = insn.operand(1)?.type_();

            if reg == Some(RDX) && type_ == OperandType::Imm {
                enc_string.set_size(insn.operand(1)?.value()? as usize);
            }
        }

        if enc_string.ready() {
            return Some(enc_string);
        }
    }

    None
}

fn main() -> anyhow::Result<()> {
    let idb =
        IDB::open("./tests/e8cdc0697748e702cf2916a2c5670325a891402ee38c98d91873a0f03e3f9025")?;

    let address = 0x180002A54; // address of DecryptString() function
    let mut current = idb
        .first_xref_to(address, XRefQuery::ALL)
        .ok_or_else(|| anyhow::anyhow!("no xrefs to {address:#x}"))?;

    loop {
        if let Some(enc_string) = handle_xref(&idb, &current) {
            println!(
                "found encrypted string: {enc_string:#?}, decrypted: {:#?}",
                enc_string.decrypt(&idb)
            );
        }

        match current.next_to() {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(())
}
