use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open_with("./tests/ls", true)?;

    println!("Testing bookmarks_erase(), bookmarks_get_desc(), and bookmarks_size() (pass 1; clear old bookmarks)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // bookmarks_erase(), ignore errors
        let _ = idb.bookmarks_erase(addr);

        // bookmarks_get_desc()
        let result = idb.bookmarks_get_desc(addr);
        assert!(result.is_err());

        // bookmarks_size()
        assert_eq!(idb.bookmarks_size(), 0);
    }

    println!("Testing bookmarks_mark() and bookmarks_get_desc()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let desc = format!(
            "Bookmark added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        // bookmarks_mark()
        let _slot = idb.bookmarks_mark(addr, &desc)?;

        // bookmarks_get_desc()
        let read_desc = idb.bookmarks_get_desc(addr)?;
        assert_eq!(read_desc, desc);
    }

    println!("Testing bookmarks_erase(), bookmarks_get_desc(), and bookmarks_size() (pass 2)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // bookmarks_erase()
        idb.bookmarks_erase(addr)?;

        // bookmarks_get_desc()
        let result = idb.bookmarks_get_desc(addr);
        assert!(result.is_err());
    }

    // bookmarks_size()
    assert_eq!(idb.bookmarks_size(), 0);

    Ok(())
}
