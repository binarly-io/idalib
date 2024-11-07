use idalib::{is_valid_license, license_id};

fn main() -> anyhow::Result<()> {
    if !is_valid_license() {
        println!("invalid license!");
        return Ok(());
    }

    let id = license_id()?;

    println!("license: {id}");

    Ok(())
}
