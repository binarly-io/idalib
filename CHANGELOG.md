# Changelog

## 0.5.1 (2025-02-28)

Bugfix:
- Make `idalib::force_batch_mode` a no-op on Windows.

## 0.5.0 (2025-02-28)

Compatibility release for IDA 9.1.

## 0.4.1 (2025-02-24)

Features:
- Add additional sanity checks when creating/opening an IDB to prevent IDA
  causing the consumer to exit.
- Bump autocxx dependency.

## 0.4.0 (2024-12-19)

Compatibility release for IDA 9.0sp1.

## 0.3.0 (2024-12-04)

Features:
- Improved error reporting for decompiler.
- Add string list API (contributor: [@0xdea](https://github.com/0xdea)).

## 0.2.2 (2024-11-16)

Fix:
- Documentation generation and workflow.

## 0.2.1 (2024-11-16)

Features:
- Add `Bookmarks::get_address` (contributor: [@0xdea](https://github.com/0xdea)).
- Add search API (contributor: [@0xdea](https://github.com/0xdea)).
- Add "set show" family of functions.

## 0.2.0 (2024-11-13)

Features:
- Bookmarks API (contributor: [@0xdea](https://github.com/0xdea)).
- Build system improvements to avoid idalib-sys rebuilds (contributor:
  [@Bobo1239](https://github.com/Bobo1239)).
- Documentation generation and build testing workflows.
- Initial Hex-rays support (basic decompiler support).
- License manager API.
- Plugin API.
- Reimplementation of `init_database` to workaround IDA not respecting
  `enable_console_messages(false)`.

## 0.1.1 (2024-10-27)

Features:
- Comments API (contributor: [@0xdea](https://github.com/0xdea)).

## 0.1.0 (2024-09-30)

Initial release.
