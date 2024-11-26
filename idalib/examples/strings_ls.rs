use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    let strlist_qty = idb.get_strlist_qty();
    println!("{strlist_qty}");

    idb.clear_strlist();
    let strlist_qty = idb.get_strlist_qty();
    println!("{strlist_qty}");

    idb.build_strlist();
    let strlist_qty = idb.get_strlist_qty();
    println!("{strlist_qty}");

    let addr = idb.get_strlist_item_addr(0).unwrap();
    println!("{addr:#x}");

    println!("Testing get_strlist_qty(), get_strlist_item(), and ea2str()");
    for i in 0..idb.get_strlist_qty() {
        let a = idb.get_strlist_item_addr(i).unwrap();
        let l = idb.get_strlist_item_length(i);
        let t = idb.get_strlist_item_type(i);
        println!("{a:#x} {l} {t}");

        let bytes = idb.get_bytes(a, l as usize);
        let string = String::from_utf8(bytes)?;
        //let string = string.escape_default().to_string();

        println!("{string:?}");
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
