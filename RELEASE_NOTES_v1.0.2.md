# ZSTD-PE-Packer v1.0.2 Release Notes

## Overview

v1.0.2 adds full runtime initialization support in the unpacking stub, enabling packed executables that use implicit TLS, structured exception handling (SEH), and stack buffer security cookies (/GS). This release resolves all known issues with packing Rust, Tauri, and other complex native executables.

## What's New

### Implicit TLS Support
- The stub PE now declares its own TLS directory with a 16 KB template, ensuring the Windows loader allocates an implicit TLS slot large enough for typical targets.
- A TLS callback copies the original executable's thread-local template into each new thread, so `std::thread::spawn` (Rust) and similar APIs that rely on clean per-thread TLS work correctly.
- Packed executables using `__declspec(thread)` (C/C++), `thread_local` (Rust, modern C++), or Go goroutine-local storage now work correctly.
- The decompressed image's TLS DataDirectory is erased after migration to prevent the loader from double-processing it.

### SEH / Exception Handling (x64)
- `.pdata` (exception directory) is registered via `RtlAddFunctionTable` at unpack time.
- C++ exceptions and Rust panics now unwind correctly in packed executables.

### Security Cookie (/GS) Initialization
- The stub reads the original executable's Load Configuration Directory and randomizes the security cookie before transferring control.
- Prevents false `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409) crashes in executables compiled with `/GS` (the MSVC default).

### NT File-API Initialization Workaround
- A minimal `CreateFileW("NUL")` call before OEP ensures kernel32 internal state is fully initialized.
- Fixes a subtle crash in Rust/Tauri runtimes that depend on early file-system API readiness.

### VERSIONINFO Resource
- `zpp.exe` now embeds a standard Win32 VERSIONINFO resource with product name, version, and copyright.

## Tested Configurations

| Target | Result |
|---|---|
| Simple C console app (hello.exe) | Exit code 0 |
| Rust/Tauri GUI app (WithHelp.exe, ~8.6 MB) | All child processes alive, GUI functional |
| Rust/Tauri agent (WithHelpAgent.exe, ~12 MB, multi-threaded TLS) | All threads alive, no TLS errors |

## Upgrade Notes

- Drop-in replacement for v1.0.1. No CLI or format changes.
- Packed executables created with v1.0.1 are unaffected; only re-packing with v1.0.2 gains the new stub features.

## Full Changelog

- `86bf6a2` feat: add VERSIONINFO resource to zpp.exe
- `7ba602c` feat(stub): support packed executables using TLS, SEH and /GS
