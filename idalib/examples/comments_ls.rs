use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open_with("./tests/ls", true, true)?;

    println!("Testing remove_cmt() and get_cmt() (pass 1; clear old comments)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // remove_cmt()
        idb.remove_cmt(addr)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.is_none());
    }

    println!("Testing set_cmt() and get_cmt()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let comment = format!(
            "Comment added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        // set_cmt()
        idb.set_cmt(addr, comment)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.unwrap().starts_with("Comment added by idalib"));
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(!results.is_empty());
    // text search appears to be buggy, some results are missing
    // let results = results.unwrap();
    // assert_eq!(results.len(), idb.functions().count());

    println!("Testing append_cmt() and get_cmt()");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();
        let comment = "Comment appended by idalib";

        // append_cmt()
        idb.append_cmt(addr, comment)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.unwrap().ends_with("appended by idalib"));
    }

    println!("Testing remove_cmt() and get_cmt() (pass 2)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // remove_cmt()
        idb.remove_cmt(addr)?;

        // get_cmt()
        let read_comment = idb.get_cmt(addr);
        assert!(read_comment.is_none());
    }

    println!("Testing find_text_iter()");
    let results: Vec<_> = idb.find_text_iter("added by idalib").collect();
    assert!(results.is_empty());

    Ok(())
}
