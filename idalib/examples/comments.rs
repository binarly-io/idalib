use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open_with("./tests/ls", true)?;

    // TODO: has_cmt(), f_has_cmt()
    // TODO: has_extra_cmts(), f_has_extra_cmts()

    // TODO: get_cmt()

    // TODO: get_predef_insn_cmt()

    // TODO: append_cmt()

    // set_cmt
    println!("Testing set_cmt()");
    for (id, f) in idb.functions() {
        let comment = format!(
            "Comment added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            f.start_address()
        );
        idb.set_cmt(f.start_address(), comment, true)?;
        // TODO: get_cmt
    }

    Ok(())
}
