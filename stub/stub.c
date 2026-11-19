/*
 * stub.c - ZSTD-PE-Packer unpacking stub.
 *
 * This runs first inside a packed executable. It finds the compressed payload
 * in its own ".zpp" section, decompresses the original PE image, fixes up
 * base relocations and imports, sets correct page protections, and jumps to
 * the original entry point (OEP).
 *
 * Build constraints:
 *   - No CRT (/NODEFAULTLIB, /ENTRY:zpp_stub_entry).
 *   - kernel32 APIs imported via normal import table.
 *   - No RWX memory — decompress to RW, then VirtualProtect to proper flags.
 *   - No anti-debug, no anti-VM, no obfuscation.
 */
#include "format.h"

/* zstd single-file decoder (decompression only). */
#include "zstd.h"

#include <windows.h>

/* ========================================================================= */
/* Minimal CRT replacements (no-CRT build has no memcpy/memset).             */
/* ========================================================================= */

#pragma function(memset)
void *memset(void *dst, int val, size_t cnt) {
    unsigned char *d = (unsigned char *)dst;
    while (cnt--) *d++ = (unsigned char)val;
    return dst;
}

#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t cnt) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (cnt--) *d++ = *s++;
    return dst;
}

#pragma function(memcmp)
int memcmp(const void *a, const void *b, size_t cnt) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    while (cnt--) {
        if (*pa != *pb) return *pa - *pb;
        pa++; pb++;
    }
    return 0;
}

#pragma function(memmove)
void *memmove(void *dst, const void *src, size_t cnt) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s) {
        while (cnt--) *d++ = *s++;
    } else {
        d += cnt; s += cnt;
        while (cnt--) *--d = *--s;
    }
    return dst;
}

/* ========================================================================= */
/* Helpers                                                                   */
/* ========================================================================= */

static void fatal(const wchar_t *msg) {
    MessageBoxW(NULL, msg, L"ZPP Stub Error", MB_ICONERROR | MB_OK);
    ExitProcess(1);
}

/* Compare 8-byte section name (not necessarily null-terminated). */
static int name_eq(const BYTE name[8], const char *want) {
    for (int i = 0; i < 8; i++) {
        if (name[i] != (BYTE)want[i]) return 0;
        if (want[i] == '\0') return 1;
    }
    return (want[8] == '\0'); /* exact 8-char match */
}

/* Map PE section characteristics to VirtualProtect page flags. Never RWX. */
static DWORD section_protect(DWORD ch) {
    int r = (ch & IMAGE_SCN_MEM_READ)    != 0;
    int w = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    int x = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;  /* rare but respect it */
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE_READ;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/* ========================================================================= */
/* find_payload: walk our own PE section table for ".zpp".                   */
/* ========================================================================= */

static const zpp_header_t *find_payload(HMODULE self) {
    BYTE *base = (BYTE *)self;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nsec; i++) {
        if (name_eq(sec[i].Name, ZPP_SECTION_NAME)) {
            const zpp_header_t *hdr =
                (const zpp_header_t *)(base + sec[i].VirtualAddress);
            /* Validate magic. */
            if (hdr->magic[0] == ZPP_MAGIC0 && hdr->magic[1] == ZPP_MAGIC1 &&
                hdr->magic[2] == ZPP_MAGIC2 && hdr->magic[3] == ZPP_MAGIC3 &&
                hdr->version  == ZPP_FORMAT_VERSION)
                return hdr;
        }
    }
    return NULL;
}

/* ========================================================================= */
/* apply_relocations: adjust addresses when loaded at a different base.      */
/* ========================================================================= */

static void apply_relocations(BYTE *image, uint64_t actual_base,
                              const zpp_header_t *hdr)
{
    if (hdr->reloc_size == 0 || hdr->reloc_rva == 0) return;

    int64_t delta = (int64_t)actual_base - (int64_t)hdr->orig_image_base;
    if (delta == 0) return;

    BYTE *reloc = image + hdr->reloc_rva;
    BYTE *end   = reloc + hdr->reloc_size;

    while (reloc < end) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)reloc;
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                      / sizeof(WORD);
        WORD *entries = (WORD *)(block + 1);

        for (DWORD j = 0; j < count; j++) {
            WORD type   = entries[j] >> 12;
            WORD offset = entries[j] & 0x0FFF;
            BYTE *patch = image + block->VirtualAddress + offset;

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break; /* padding, skip */
            case IMAGE_REL_BASED_HIGHLOW:
                *(uint32_t *)patch += (uint32_t)delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                *(uint64_t *)patch += (uint64_t)delta;
                break;
            default:
                break; /* ignore unknown types */
            }
        }
        reloc += block->SizeOfBlock;
    }
}

/* ========================================================================= */
/* resolve_imports: walk the import directory and fill the IAT.              */
/* ========================================================================= */

static int resolve_imports(BYTE *image, const zpp_header_t *hdr) {
    if (hdr->import_size == 0 || hdr->import_rva == 0) return 0;

    IMAGE_IMPORT_DESCRIPTOR *imp =
        (IMAGE_IMPORT_DESCRIPTOR *)(image + hdr->import_rva);

    for (; imp->Name != 0; imp++) {
        const char *dll_name = (const char *)(image + imp->Name);
        HMODULE dll = LoadLibraryA(dll_name);
        if (!dll) return -1;

        /*
         * OriginalFirstThunk (ILT/HNT) holds the lookup entries.
         * FirstThunk (IAT) is what we fill with resolved addresses.
         * If OriginalFirstThunk is 0 (some linkers), use FirstThunk for both.
         */
        BYTE *ilt_base = image + (imp->OriginalFirstThunk
                                  ? imp->OriginalFirstThunk
                                  : imp->FirstThunk);
        BYTE *iat_base = image + imp->FirstThunk;

#ifdef _WIN64
        IMAGE_THUNK_DATA64 *ilt = (IMAGE_THUNK_DATA64 *)ilt_base;
        IMAGE_THUNK_DATA64 *iat = (IMAGE_THUNK_DATA64 *)iat_base;
        const uint64_t ordinal_flag = IMAGE_ORDINAL_FLAG64;
        for (; ilt->u1.AddressOfData; ilt++, iat++) {
            FARPROC proc;
            if (ilt->u1.Ordinal & ordinal_flag) {
                proc = GetProcAddress(dll,
                           (LPCSTR)(ilt->u1.Ordinal & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(image + ilt->u1.AddressOfData);
                proc = GetProcAddress(dll, (const char *)ibn->Name);
            }
            if (!proc) return -1;
            iat->u1.Function = (ULONGLONG)proc;
        }
#else
        IMAGE_THUNK_DATA32 *ilt = (IMAGE_THUNK_DATA32 *)ilt_base;
        IMAGE_THUNK_DATA32 *iat = (IMAGE_THUNK_DATA32 *)iat_base;
        const uint32_t ordinal_flag = IMAGE_ORDINAL_FLAG32;
        for (; ilt->u1.AddressOfData; ilt++, iat++) {
            FARPROC proc;
            if (ilt->u1.Ordinal & ordinal_flag) {
                proc = GetProcAddress(dll,
                           (LPCSTR)(ilt->u1.Ordinal & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(image + ilt->u1.AddressOfData);
                proc = GetProcAddress(dll, (const char *)ibn->Name);
            }
            if (!proc) return -1;
            iat->u1.Function = (ULONG_PTR)proc;
        }
#endif
    }
    return 0;
}

/* ========================================================================= */
/* apply_section_protections: read the decompressed PE headers and set each  */
/* section to its proper page protection (never RWX where avoidable).        */
/* ========================================================================= */

static void apply_section_protections(BYTE *image) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(image + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;
    DWORD old;

    for (WORD i = 0; i < nsec; i++) {
        DWORD prot = section_protect(sec[i].Characteristics);
        DWORD size = sec[i].Misc.VirtualSize;
        if (size == 0) continue;
        VirtualProtect(image + sec[i].VirtualAddress, size, prot, &old);
    }

    /* Mark headers read-only. */
    VirtualProtect(image, nt->OptionalHeader.SizeOfHeaders,
                   PAGE_READONLY, &old);
}

/* ========================================================================= */
/* unpack_and_run: decompress, fixup, protect, jump.                         */
/* ========================================================================= */

typedef void (*entry_point_fn)(void);

static int unpack_and_run(const zpp_header_t *hdr) {
    const BYTE *comp_data = (const BYTE *)(hdr + 1); /* payload follows header */

    /* 1. Allocate RW memory for the decompressed image.
     *    Try the original base first so relocations may be skipped. */
    BYTE *image = (BYTE *)VirtualAlloc(
        (LPVOID)(uintptr_t)hdr->orig_image_base,
        hdr->orig_image_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (!image) {
        /* Original base taken; let the OS pick and we'll relocate. */
        image = (BYTE *)VirtualAlloc(
            NULL,
            hdr->orig_image_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
    }
    if (!image) {
        fatal(L"VirtualAlloc failed for image");
        return -1;
    }

    /* 2. Decompress the payload into the allocated region. */
    size_t result = ZSTD_decompress(
        image, hdr->payload_raw_size,
        comp_data, hdr->payload_comp_size);

    if (ZSTD_isError(result) || result != hdr->payload_raw_size) {
        fatal(L"ZSTD decompression failed");
        VirtualFree(image, 0, MEM_RELEASE);
        return -1;
    }

    /* 3. Apply base relocations if loaded at a different address. */
    apply_relocations(image, (uint64_t)(uintptr_t)image, hdr);

    /* 4. Resolve imports (LoadLibraryA + GetProcAddress). */
    if (resolve_imports(image, hdr) != 0) {
        fatal(L"Import resolution failed");
        VirtualFree(image, 0, MEM_RELEASE);
        return -1;
    }

    /* 5. Set per-section page protections (RX for code, RW for data). */
    apply_section_protections(image);

    /* 6. Transfer control to the original entry point.
     *    The OS command line and environment are untouched — arguments passed
     *    to the packed executable reach the original program unchanged. */
    entry_point_fn oep = (entry_point_fn)(image + hdr->orig_entry_rva);
    oep();

    /* Normally the OEP never returns, but if it does: */
    return 0;
}

/* ========================================================================= */
/* No-CRT entry point (see CMake /ENTRY:zpp_stub_entry).                    */
/* ========================================================================= */

void zpp_stub_entry(void) {
    HMODULE self = GetModuleHandleW(NULL);
    const zpp_header_t *hdr = find_payload(self);
    if (!hdr) {
        fatal(L"Cannot find .zpp payload section");
    }
    int rc = unpack_and_run(hdr);
    ExitProcess((UINT)rc);
}
