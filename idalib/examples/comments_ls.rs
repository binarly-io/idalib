use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    let idb = IDB::open_with("./tests/ls", true)?;

    // TODO: has_cmt(), f_has_cmt()
    // TODO: has_extra_cmts(), f_has_extra_cmts()

    // TODO: get_predef_insn_cmt()

    // TODO: add some meaningful output
    // TODO: edit also README.md

    println!("Testing set_cmt() and get_cmt()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let comm = format!(
            "Comment added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        // set_cmt()
        idb.set_cmt(addr, comm, false)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr.into(), false);
        assert!(read_comment.starts_with("Comment added by idalib"));
    }

    println!("Testing append_cmt() and get_cmt()");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();
        let comm = "Comment appended by idalib";

        // append_cmt()
        idb.append_cmt(addr, comm, false)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr.into(), false);
        assert!(read_comment.ends_with("appended by idalib"));
    }

    Ok(())
}
