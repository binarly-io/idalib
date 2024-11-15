use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    println!("Testing erase(), get_description(), and len() (pass 1; clear old bookmarks)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // erase(), ignore errors
        let _ = idb.bookmarks().erase(addr);

        // get_description()
        let read_desc = idb.bookmarks().get_description(addr);
        assert!(read_desc.is_none());
    }

    // len()
    assert_eq!(idb.bookmarks().len(), 0);

    println!("Testing mark() and get_description()");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let desc = format!(
            "Bookmark added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        // mark()
        let _slot = idb.bookmarks().mark(addr, &desc)?;

        // get_description()
        let read_desc = idb.bookmarks().get_description(addr);
        assert_eq!(read_desc.unwrap(), desc);
    }

    println!("Testing erase(), get_description(), and len() (pass 2)");
    for (_id, f) in idb.functions() {
        let addr = f.start_address();

        // erase()
        idb.bookmarks().erase(addr)?;

        // bookmarks_get_desc()
        let read_desc = idb.bookmarks().get_description(addr);
        assert!(read_desc.is_none());
    }

    // bookmarks_size()
    assert_eq!(idb.bookmarks().len(), 0);

    Ok(())
}
