# ZSTD-PE-Packer (`zpp`)

PE executable packer using **Zstandard** compression. Like UPX, but with zstd.

## Usage

```
zpp <input.exe>
```

That's it. Outputs `<input>.exe.packed.exe`.

| Option | Description |
|--------|-------------|
| `-o <file>` | Output path |
| `-l <1..22>` | Compression level (default: 22, max) |
| `--strip-metadata` | Don't copy original resources (version/icon/manifest) |
| `-v` | Verbose |

## Supported targets

Any **native PE** works — C, C++, Rust, Go, Nuitka, PyInstaller, .NET NativeAOT.
Managed .NET (CIL) assemblies are detected and refused.

### 🚀 Full Rust support — including multi-threaded GUIs

Unlike most PE packers, **zpp handles Rust binaries correctly**, including:

- **Tauri** apps (webview + async runtime + multiple worker threads)
- **egui / eframe** apps (render thread + windowing thread)
- Any Rust binary that uses `std::thread::spawn`, `thread_local!`, `tokio`, `rayon`, or `parking_lot`

Why it's hard: Rust's `thread_local!` compiles to implicit TLS (`__declspec(thread)`),
which requires the Windows loader to allocate and initialise a per-thread TLS block
for every spawned thread. Most packers either strip the TLS directory or leave the
stub's tiny TLS template in place, causing `thread spawn` to panic on the first
`std::thread::spawn` call.

`zpp` solves this with a **16 KB TLS template + per-thread TLS callback** that
in-place-copies the original executable's TLS template into each new thread's
loader-allocated buffer. The result: packed Rust apps run identically to the
original, with no runtime panics or thread-local corruption.

Tested: Tauri desktop apps, egui apps, multi-threaded Rust CLI tools.

## How it works

1. `zpp` parses the input PE and maps sections to their virtual layout
2. The mapped image is compressed with zstd
3. The original's resource section (version info, icons, manifest) is copied to the output
4. A tiny no-CRT unpacking stub (44 KB) is combined with the compressed payload into a new PE
5. At runtime the stub decompresses, applies relocations/imports, sets page protections, and jumps to the original entry point

Command-line arguments pass through transparently.

## Design (AV-friendly)

- No RWX memory — decompress to RW, then VirtualProtect to RX
- Normal import table — no PEB-walking or dynamic resolution
- No anti-debug / anti-VM
- Compatible with Authenticode code-signing

## Build

Requires CMake ≥ 3.20 and MSVC (or clang-cl) on Windows.

```bash
cmake -B build -G Ninja
cmake --build build --config Release
```

zstd is fetched automatically via FetchContent.

## License

MIT
