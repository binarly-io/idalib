use idalib::enable_console_messages;
use idalib::idb::IDB;

// TODO
fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    enable_console_messages(true);

    // Open IDA database
    let idb = IDB::open_with("./tests/ls", true)?;

    println!("bookmarks_size => {}", idb.bookmarks_size());

    //println!("Testing remove_cmt() and get_cmt() (pass 1; clear old comments)");
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let desc = format!(
            "Bookmark added by idalib: {id} {} {:#x}",
            f.name().unwrap(),
            addr
        );

        //println!("{}", idb.bookmarks_size());

        let slot = idb.bookmarks_mark(addr, &desc)?;
        println!("bookmarks_mark => {slot}");

        let read_desc = idb.bookmarks_get_desc(addr)?;
        println!("{addr:#x} {read_desc}");

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
        let slot = idb.bookmarks_mark_with(0xc380, 0, "test")?;
        //let read_desc = idb.bookmarks_get_desc(i);
        //let read_desc = idb.bookmarks_get_desc_with(0xc380);
        //println!("{i} {read_desc}");
    }

    for i in 0..=10 {
        idb.bookmarks_erase(i)?;
        println!("bookmarks_size => {}", idb.bookmarks_size());
    }

    for i in 0..idb.bookmarks_size() {
        //let read_desc = idb.bookmarks_get_desc(i);
        //println!("bookmarks_get_desc => {i} {read_desc}");
    }

    idb.bookmarks_erase(idb.bookmarks_size() - 1)?;

    /*
    for (id, f) in idb.functions() {
        let addr = f.start_address();
        let index = idb.bookmarks_find_index(addr)?;
        println!("{addr:#x} {index}");

        //idb.bookmarks_erase(index)?;
    }

    idb.bookmarks_erase(1)?; // TODO: beware that indexes are translated left when an entry is deleted...
                             //idb.bookmarks_erase(1000)?; // TODO: this causes internal error 1312 with leftover project files... Implement a check that index is not higher than size
    idb.bookmarks_erase(idb.bookmarks_size() - 1)?; //

    for i in 0..idb.bookmarks_size() {
        let read_desc = idb.bookmarks_get_desc(i);
        println!("XXX {read_desc}");

        //idb.bookmarks_erase(i)?;
    }
    */

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
