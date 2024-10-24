use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open_with("./tests/ls", true)?;

    // TODO: has_cmt(), f_has_cmt()
    // TODO: has_extra_cmts(), f_has_extra_cmts()

    // TODO: get_predef_insn_cmt()

    // TODO: append_cmt()

    // set_cmt(), get_cmt()
    println!("Testing set_cmt() and get_cmt()");
    for (id, f) in idb.functions() {
        let comment = format!(
            "Comment added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            f.start_address()
        );
        idb.set_cmt(f.start_address(), comment, true)?;

        let read_comment = idb.get_cmt(f.start_address().into(), true);
        assert!(read_comment.starts_with("Comment added by idalib"));
    }

    Ok(())
}
