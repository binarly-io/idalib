# idalib

[![crates.io](https://img.shields.io/crates/v/idalib)](https://crates.io/crates/idalib)
[![documentation](https://img.shields.io/badge/documentation-0.1.1%2B9.0.240930-blue?link=https%3A%2F%2Fbinarly-io.github.io%2Fidalib%2Fidalib)](https://binarly-io.github.io/idalib/idalib/)
[![license](https://img.shields.io/crates/l/idalib)](https://github.com/binarly-io/idalib)
[![crates.io downloads](https://img.shields.io/crates/d/idalib)](https://crates.io/crates/idalib)

Idiomatic Rust bindings for the IDA SDK, enabling the development of standalone
analysis tools using IDA v9.0’s idalib.

## IDA support and dependencies

The bindings and examples have been tested against IDA Pro v9.0 on Windows
(11), Linux (Ubuntu 24.04 LTS), and macOS Sequoia (Apple Silicon).

In addition to the latest v9.0 IDA SDK and IDA itself, a recent version of
LLVM/Clang is required (this is to help generate bindings from the SDK), it can
be obtained from, e.g., [here](https://github.com/llvm/llvm-project/releases).

## Developing with idalib

For development, only the IDA SDK is required, whereas to run tests, an IDA
installation (with a valid license) is required. During build, the crates
locate the SDK and IDA installation using the following environment variables:

- `IDASDKDIR` set to the IDA Pro v9.0 SDK
- `IDADIR` (optional) set to the directory containing the `ida` executable
  (e.g., `/Applications/IDA Professional v9.0/Contents/macOS` for macOS, or
  `$HOME/ida-pro-9.0` for Linux). If not set, the build script will check
  common locations.

### Projects using idalib

- [xorpse/idalib-mp](https://github.com/xorpse/idalib-mp): example project demonstrating idalib + multi-processing.
- [xorpse/wegglir](https://github.com/xorpse/wegglir): mass-scan source/decompiled code using weggli rulesets.
- [0xdea/rhabdomancer](https://github.com/0xdea/rhabdomancer): locate calls to insecure API functions in a binary file.

### Examples

A minimal project to working with `idalib` requires the following components:

`Cargo.toml`:

```toml
name = "example-analyser"

# ...

[dependencies]
idalib = "0.1.0"

[build-dependencies]
idalib-build = "0.1.0"
```

`build.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    idalib_build::configure_linkage()?;
    Ok(())
}
```

`src/main.rs`:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let idb = idalib::IDB::open("/path/to/binary")?;

    // ...

    Ok(())
}
```

More comprehensive examples can be found in `idalib/examples`. To run them:

Linux/macOS:

```sh
export IDASDKDIR=...
export IDADIR=...

cargo run --example=dump_ls
```

Windows:

```powershell
$env:PATH="C:\Program Files\IDA Professional 9.0;$env:PATH"
$env:IDADIR="C:\Program Files\IDA Professional 9.0"
$env:IDASDKDIR=...

cargo run --example=dump_ls
```

### Linking

The `idalib-build` crate provides various build script helpers to simplify
linking:

- `idalib_build::configure_idalib_linkage`: links against `(lib)ida` and
  `(lib)idalib` in the IDA installation directory.
- `idalib_build::configure_idasdk_linkage`: links against the `(lib)ida` and
  `(lib)idalib` stub libraries bundled with the SDK.
- `idalib_build::configure_linkage`: links against the `(lib)ida` and
  `(lib)idalib` stub libraries and for Linux/macOS sets the RPATH to refer to
  the detected (or specified via `IDADIR`) installation directory.

## Extending idalib

To expose unimplemented IDA SDK functionality, modify the `idasdk-sys` crate,
add appropriate high-level wrappers in `idalib`, and submit a pull request.
Ensure that the additions are portable and build with the latest SDK. We won't
accept PRs to support older beta releases.

## Contributors

Please see [CONTRIBUTORS.md](CONTRIBUTORS.md) for a full list of acknowledgments.
