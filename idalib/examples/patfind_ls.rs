use idalib::enable_console_messages;
use idalib::idb::*;

fn main() -> anyhow::Result<()> {
    enable_console_messages(true);

    let idb = IDB::open("./tests/ls")?;

    let patfind = idb.find_plugin("patfind", true)?;

    println!("patfind version: {}", patfind.version());
    println!("patfind flags: {:#?}", patfind.flags());

    patfind.run(0);

    Ok(())
}
