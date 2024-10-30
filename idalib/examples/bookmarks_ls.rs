use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database... ");

    // Open IDA database
    let idb = IDB::open_with("./tests/ls", true)?;

    println!("Testing bookmarks_size()");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // bookmarks_size()
        let n = idb.bookmarks_size(addr);
        println!("{n}");

        idb.bookmarks_mark(addr, n, "test_title", "test_description")?;

        // get_cmt()
        //let read_comment = idb.get_cmt(addr);
        //assert!(read_comment.is_empty());
    }

    /*
    println!("Testing set_cmt() and get_cmt()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let comm = format!(
            "Comment added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        // set_cmt()
        idb.set_cmt(addr, comm)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.starts_with("Comment added by idalib"));
    }

    println!("Testing append_cmt() and get_cmt()");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();
        let comm = "Comment appended by idalib";

        // append_cmt()
        idb.append_cmt(addr, comm)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.ends_with("appended by idalib"));
    }

    println!("Testing remove_cmt() and get_cmt() (pass 2)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // remove_cmt()
        idb.remove_cmt(addr)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.is_empty());
    }
    */

    Ok(())
}
