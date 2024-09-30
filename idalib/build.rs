fn main() -> Result<(), Box<dyn std::error::Error>> {
    idalib_build::configure_linkage()?;
    Ok(())
}
