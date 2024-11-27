use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    println!("Testing len(), get_item_addr(), get_item_length(), and get_string() (valid indexes)");
    // len()
    for i in 0..idb.strings().len() {
        // get_item_addr()
        assert!(idb.strings().get_item_addr(i).is_some());
        // get_item_length()
        assert_ne!(idb.strings().get_item_length(i), 0);
        // get_string()
        assert!(idb.get_string(i).is_some());
    }

    println!("Testing len(), get_item_addr(), get_item_length(), and get_string() (invalid index)");
    // len()
    let len = idb.strings().len();
    // get_item_addr()
    assert!(idb.strings().get_item_addr(len).is_none());
    // get_item_length()
    assert_eq!(idb.strings().get_item_length(len), 0);
    // get_string()
    assert!(idb.get_string(len).is_none());

    Ok(())
}
