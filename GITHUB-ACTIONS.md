# GitHub Actions for users of idalib

Due to the fact we cannot redistribute the IDA SDK, setting up workflows is a
little bit more involved than for regular Rust projects--it also means that we
cannot rely on [docs.rs](https://docs.rs) to handle documentation
hosting/generation. To help downstream consumers of idalib avoid headaches, we
have documented how we've setup GitHub Actions for idalib to perform a build a
viability test on each supported OS, and to generate and deploy documentation.

## Prerequisites

To adapt the workflows in this document in your own project, you need to
configure two repository secrets via Settings -> Secrets and variables ->
Actions:

- `IDASDK91_URL`: a publicly accessible encrypted/password-protected archive
  containing he latest IDA SDK. We are using a zip in our workflow below, but
  it should be straightforward to use an approach like
  [binexport](https://github.com/google/binexport/blob/23619ba62d88b3b93615d28fe3033489d12b38ac/.github/workflows/cmake.yml#L25),
  where the SDK is [stored encrypted alongside the source
  code](https://github.com/google/binexport/tree/main/ida/idasdk).
- `IDASDK91_PASSWORD`: the password/encryption key for the SDK archive.

You will also need to make sure your `build.rs` gracefully falls back to link
against the IDA SDK stub libraries if an IDA installation cannot be located,
otherwise the build script will panic and abort the build. This can be done as
follows:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_, ida_path, idalib_path) = idalib_build::idalib_install_paths_with(false);
    if !ida_path.exists() || !idalib_path.exists() {
        println!("cargo::warning=IDA installation not found.");
        idalib_build::configure_idasdk_linkage();
    } else {
        idalib_build::configure_linkage()?;
    }
    Ok(())
}
```

## Build testing

The workflow below will perform a basic build test for all supported OSes:

```yml
name: build

on:
  push:
    branches: [ master ]
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          submodules: true
      - name: prepare IDA SDK
        env:
          IDASDK91_URL: ${{ secrets.IDASDK91_URL }}
          IDASDK91_PASSWORD: ${{ secrets.IDASDK91_PASSWORD }}
        run: |
          curl -o "${{ runner.temp }}/idasdk91.zip" -L "$IDASDK91_URL"
          unzip -d "${{ runner.temp }}" -P "$IDASDK91_PASSWORD" "${{ runner.temp }}/idasdk91.zip"
      - name: build
        env:
          IDASDKDIR: "${{ runner.temp }}/idasdk91"
        run: cargo build

  build-macos:
    runs-on: macOS-latest
    steps:
      - name: checkout
        uses: actions/checkout@v4
        with:
          submodules: true
      - name: prepare IDA SDK
        env:
          IDASDK91_URL: ${{ secrets.IDASDK91_URL }}
          IDASDK91_PASSWORD: ${{ secrets.IDASDK91_PASSWORD }}
        run: |
          curl -o "${{ runner.temp }}/idasdk91.zip" -L "$IDASDK91_URL"
          unzip -d "${{ runner.temp }}" -P "$IDASDK91_PASSWORD" "${{ runner.temp }}/idasdk91.zip"
      - name: build
        env:
          IDASDKDIR: "${{ runner.temp }}/idasdk91"
        run: cargo build

  build-windows:
    runs-on: windows-latest
    steps:
      - name: install clang/llvm
        uses: KyleMayes/install-llvm-action@e0a8dc9cb8a22e8a7696e8a91a4e9581bec13181
        with:
          version: "18.1.8"
          directory: "${{ runner.temp }}/llvm-18"
      - name: configure clang/llvm environment
        run: echo "LIBCLANG_PATH=$((gcm clang).source -replace "clang.exe")" >> $env:GITHUB_ENV
      - name: checkout
        uses: actions/checkout@v4
        with:
          submodules: true
      - name: prepare IDA SDK
        env:
          IDASDK91_URL: ${{ secrets.IDASDK91_URL }}
          IDASDK91_PASSWORD: ${{ secrets.IDASDK91_PASSWORD }}
        run: |
          curl -o "${{ runner.temp }}/idasdk91.zip" -L $env:IDASDK91_URL
          unzip -d "${{ runner.temp }}" -P $env:IDASDK91_PASSWORD "${{ runner.temp }}/idasdk91.zip"
      - name: build
        env:
          IDASDKDIR: "${{ runner.temp }}/idasdk91"
        run: cargo build

```

## Documentation

To generate and deploy documentation, some additional configuration is
necessary if you want to use GitHub Pages, as we do for idalib. First, we need
a branch to keep the documentation separate from the source code, e.g.,
`gh-pages`, which can be created via `git switch --orphan gh-pages`. Then
GitHub Pages needs to be configured via Settings -> Pages by setting "Source"
to "Deploy from a branch" and "branch" to "gh-pages".

```yml
name: document

permissions:
  contents: write

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - name: prepare IDA SDK
        env:
          IDASDK91_URL: ${{ secrets.IDASDK91_URL }}
          IDASDK91_PASSWORD: ${{ secrets.IDASDK91_PASSWORD }}
        run: |
          curl -o "${{ runner.temp }}/idasdk91.zip" -L "$IDASDK91_URL"
          unzip -d "${{ runner.temp }}" -P "$IDASDK91_PASSWORD" "${{ runner.temp }}/idasdk91.zip"
      - name: generate documentation
        env:
          IDASDKDIR: "${{ runner.temp }}/idasdk91"
        run: cargo doc --no-deps
      - name: git configuration
        run: |
          git config user.name "GitHub Actions for idalib"
          git config user.email "idalib@binarly.io"
          git config push.autosetupremote true
      - name: deploy
        run: |
          git fetch --all
          git checkout gh-pages
          cp -R target/doc/* .
          rm -rf target Cargo.lock
          git add .
          git config push.autosetupremote true
          git commit -m 'update documentation'
          git push
```
