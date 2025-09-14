use idalib::idb::IDB;

fn main() -> anyhow::Result<()> {
    println!("Trying to open IDA database...");

    // Open IDA database
    let idb = IDB::open("./tests/ls")?;

    println!("Testing len(), get_by_index(), and get_address_by_index() (valid indexes)");
    // len()
    for i in 0..idb.strings().len() {
        /*
        println!(
            "\t{:#x}\t{:?}",
            idb.strings().get_address_by_index(i).unwrap(),
            idb.strings().get_by_index(i).unwrap()
        );
        */
        // get_by_index()
        assert!(idb.strings().get_by_index(i).is_some());
        // get_address_by_index()
        assert!(idb.strings().get_address_by_index(i).is_some());
    }

    println!("Testing len(), get_by_index(), and get_address_by_index() (invalid index)");
    // len()
    let len = idb.strings().len();
    // get_by_index()
    assert!(idb.strings().get_by_index(len).is_none());
    // get_address_by_index()
    assert!(idb.strings().get_address_by_index(len).is_none());

    println!("\nTesting iterator");
    for (_address, _content) in idb.strings().iter() {
        /*
        println!(
            "\t{:#x}\t{:?}",
            _address,
            _content
        );
        */
    }

    Ok(())
}
