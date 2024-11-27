use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    let len = idb.strings().len();
    println!("{len}");

    idb.strings().clear();
    let len = idb.strings().len();
    println!("{len}");

    idb.strings().build();
    let len = idb.strings().len();
    println!("{len}");

    let addr = idb.strings().get_item_addr(0).unwrap();
    println!("{addr:#x}");

    let l = idb.strings().get_item_length(0);
    println!("length: {l}");

    let s = idb.get_string(0).unwrap();
    println!("{s}");
    println!();

    // TODO
    println!("Testing len(), get_item_addr(), get_item_length()...");
    for i in 0..idb.strings().len() {
        let a = idb.strings().get_item_addr(i).unwrap();
        let l = idb.strings().get_item_length(i);
        println!("{a:#x} {l}");

        let s = idb.get_string(i).unwrap();
        println!("{s}");
        println!();
    }

    /*
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
            "Bookmark added by idalib: {id} {} {addr:#x}",
            f.name().unwrap(),
        );

        // mark()
        let _slot = idb.bookmarks().mark(addr, &desc)?;

        // get_description()
        let read_desc = idb.bookmarks().get_description(addr);
        assert_eq!(read_desc.unwrap(), desc);
    }

    println!("Testing len(), get_address(), and get_description()");
    // len()
    for i in 0..idb.bookmarks().len() {
        // get_address()
        let read_addr = idb.bookmarks().get_address(i).unwrap();
        let addr_str = format!("{read_addr:#x}");

        // get_description()
        let read_desc = idb.bookmarks().get_description(read_addr).unwrap();

        assert!(read_desc.ends_with(addr_str.as_str()));
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

     */

    Ok(())
}
