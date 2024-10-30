use idalib::idb::IDB;

// TODO
fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open_with("./tests/ls", true)?;

    //println!("Testing remove_cmt() and get_cmt() (pass 1; clear old comments)");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let desc = format!(
            "Bookmark added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        println!("{}", idb.bookmarks_size());

        idb.bookmarks_mark(addr, idb.bookmarks_size(), &desc)?;

        // bookmarks_size()
        /*
        let mut i = 0;
        while i < idb.bookmarks_size() {
            if idb.bookmarks_get_desc(i).is_empty() {
                break;
            }
            i += 1;
        }
        idb.bookmarks_mark(addr, i, &desc)?;
         */
    }

    for i in 0..idb.bookmarks_size() {
        let read_desc = idb.bookmarks_get_desc(i);
        println!("{read_desc}");
    }

    /*
    println!("Testing bookmarks_size()");
    for i in 0..idb.bookmarks_size() {
        println!("{i}");
    }
    */

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
