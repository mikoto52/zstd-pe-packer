/*
 * pe.h - Minimal PE parsing for the packer (CLI side only; uses CRT).
 */
#ifndef ZPP_PE_H
#define ZPP_PE_H

#include <stdint.h>
#include <stddef.h>

/*
 * How the OS executes the PE. The packer operates on the compiled PE, so the
 * source language (C/C++/Rust/Go/Nuitka/PyInstaller/NativeAOT) does not matter
 * for native images -- they all take the same code path. Managed .NET images
 * run through the CLR and need a different loader entirely.
 */
typedef enum zpp_exe_kind {
    ZPP_EXE_NATIVE = 0,      /* native machine code: C/C++/Rust/Go/NativeAOT/...   */
    ZPP_EXE_DOTNET_MANAGED   /* CLR/.NET managed assembly (CIL bytecode)           */
} zpp_exe_kind;

typedef struct zpp_pe {
    uint8_t *data;      /* raw file bytes (owned)        */
    size_t   size;      /* file size                     */

    int      is_pe32_plus; /* 1 => PE32+ (x64), 0 => PE32 */

    zpp_exe_kind kind;        /* native vs managed .NET                 */
    int      has_tls_callbacks; /* TLS directory present (Go, some C++) */
    uint32_t com_rva, com_size; /* data directory [COM_DESCRIPTOR]      */

    /* Parsed from the optional header. */
    uint64_t image_base;
    uint32_t size_of_image;
    uint32_t entry_rva;

    uint32_t reloc_rva, reloc_size;   /* data directory [BASERELOC] */
    uint32_t import_rva, import_size; /* data directory [IMPORT]    */

    /* Offsets into `data` for header fixups when writing the packed file. */
    size_t   nt_headers_off;          /* offset of IMAGE_NT_HEADERS  */
    uint16_t number_of_sections;
    uint16_t size_of_optional_header;
    size_t   section_table_off;       /* offset of first section header */
    uint32_t file_alignment;
    uint32_t section_alignment;
} zpp_pe;

/* Load and validate a PE from disk. Returns 0 on success. */
int  zpp_pe_load(const char *path, zpp_pe *out);
void zpp_pe_free(zpp_pe *pe);

/*
 * Produce the "mapped image" of the PE: a SizeOfImage-byte buffer with headers
 * and sections placed at their virtual addresses (zero-filled gaps). This is
 * what gets compressed as the stub payload.
 *
 * Caller frees *out_image. Returns 0 on success.
 */
int  zpp_pe_build_mapped_image(const zpp_pe *pe, uint8_t **out_image, uint32_t *out_size);

#endif /* ZPP_PE_H */
