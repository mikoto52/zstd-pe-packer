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
/* Stub TLS directory — ensures the Windows loader allocates an implicit     */
/* TLS slot for the main module. Without this, any packed executable that    */
/* uses __declspec(thread) / thread_local (Rust, Go, modern C++) would      */
/* crash because the TLS array wouldn't have an entry for the main module.  */
/* ========================================================================= */

#pragma section(".tls",     long, read, write)
#pragma section(".tls$ZZZ", long, read, write)

__declspec(allocate(".tls"))      char _tls_start = 0;
__declspec(allocate(".tls"))      char _tls_pad[16384] = {0};
__declspec(allocate(".tls$ZZZ"))  char _tls_end   = 0;

DWORD _tls_index = 0;

/* Globals filled by the main thread's TLS init (step 6) so the TLS
 * callback can set up proper TLS data for new threads. */
static const BYTE *g_tls_template_ptr = NULL;
static SIZE_T      g_tls_template_raw_len = 0;
static SIZE_T      g_tls_total_len = 0;

static void NTAPI zpp_tls_callback(PVOID, DWORD, PVOID);
static PIMAGE_TLS_CALLBACK _zpp_tls_cbs[] = { zpp_tls_callback, NULL };

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
extern const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)(ULONG_PTR)&_tls_start,
    (ULONGLONG)(ULONG_PTR)&_tls_end,
    (ULONGLONG)(ULONG_PTR)&_tls_index,
    (ULONGLONG)(ULONG_PTR)&_zpp_tls_cbs,
    0, 0
};
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
extern const IMAGE_TLS_DIRECTORY32 _tls_used = {
    (ULONG)(ULONG_PTR)&_tls_start,
    (ULONG)(ULONG_PTR)&_tls_end,
    (ULONG)(ULONG_PTR)&_tls_index,
    (ULONG)(ULONG_PTR)&_zpp_tls_cbs,
    0, 0
};
#endif

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
/* TLS callback — runs on every new thread (DLL_THREAD_ATTACH).             */
/* The Windows loader's internal TLS template copy dates from module load   */
/* time (the stub's tiny 1-byte template). New threads therefore get a     */
/* buffer too small for the decompressed image's thread_locals. This       */
/* callback replaces it with a correctly-sized copy of the original        */
/* template, so implicit TLS works on all threads.                         */
/* ========================================================================= */

static void NTAPI zpp_tls_callback(PVOID dll, DWORD reason, PVOID reserved) {
    (void)dll; (void)reserved;
    if (reason == DLL_THREAD_ATTACH && g_tls_template_ptr) {
#ifdef _WIN64
        BYTE **arr = (BYTE **)(uintptr_t)__readgsqword(0x58);
#else
        BYTE **arr = (BYTE **)(uintptr_t)__readfsdword(0x2C);
#endif
        if (arr && arr[_tls_index]) {
            memcpy(arr[_tls_index],
                   g_tls_template_ptr, g_tls_template_raw_len);
        }
    }
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
    if (x && w) return PAGE_EXECUTE_READWRITE;
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
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *(uint32_t *)patch += (uint32_t)delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                *(uint64_t *)patch += (uint64_t)delta;
                break;
            default:
                break;
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

    VirtualProtect(image, nt->OptionalHeader.SizeOfHeaders,
                   PAGE_READONLY, &old);
}

/* ========================================================================= */
/* unpack_and_run: decompress, fixup, protect, jump.                         */
/* ========================================================================= */

typedef void (*entry_point_fn)(void);

static int unpack_and_run(const zpp_header_t *hdr) {
    const BYTE *comp_data = (const BYTE *)(hdr + 1);

    /* 1. Allocate RW memory for the decompressed image.
     *    Try the original base first so relocations may be skipped. */
    BYTE *image = (BYTE *)VirtualAlloc(
        (LPVOID)(uintptr_t)hdr->orig_image_base,
        hdr->orig_image_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (!image) {
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

    /* 5. Register exception handlers (.pdata) so SEH unwinding works.
     *    On x64, without this any C++ exception or SEH causes a crash. */
#ifdef _WIN64
    {
        IMAGE_DOS_HEADER *img_dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS64 *img_nt =
            (IMAGE_NT_HEADERS64 *)(image + img_dos->e_lfanew);
        if (img_nt->OptionalHeader.NumberOfRvaAndSizes >
            IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            DWORD exc_rva  = img_nt->OptionalHeader.DataDirectory
                                 [IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
            DWORD exc_size = img_nt->OptionalHeader.DataDirectory
                                 [IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
            if (exc_rva && exc_size) {
                RUNTIME_FUNCTION *funcs =
                    (RUNTIME_FUNCTION *)(image + exc_rva);
                DWORD count = exc_size / (DWORD)sizeof(RUNTIME_FUNCTION);
                RtlAddFunctionTable(funcs, count,
                                    (DWORD64)(uintptr_t)image);
            }
        }
    }
#endif

    /* 6. Initialize TLS: copy template data into the stub's loader-assigned
     *    TLS slot, update the index. */
    {
        IMAGE_DOS_HEADER *img_dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS *img_nt =
            (IMAGE_NT_HEADERS *)(image + img_dos->e_lfanew);
        DWORD tls_rva  = 0, tls_size = 0;
#ifdef _WIN64
        {
            IMAGE_NT_HEADERS64 *nt64 = (IMAGE_NT_HEADERS64 *)img_nt;
            if (nt64->OptionalHeader.NumberOfRvaAndSizes >
                IMAGE_DIRECTORY_ENTRY_TLS) {
                tls_rva  = nt64->OptionalHeader.DataDirectory
                               [IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                tls_size = nt64->OptionalHeader.DataDirectory
                               [IMAGE_DIRECTORY_ENTRY_TLS].Size;
            }
        }
#else
        {
            IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32 *)img_nt;
            if (nt32->OptionalHeader.NumberOfRvaAndSizes >
                IMAGE_DIRECTORY_ENTRY_TLS) {
                tls_rva  = nt32->OptionalHeader.DataDirectory
                               [IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                tls_size = nt32->OptionalHeader.DataDirectory
                               [IMAGE_DIRECTORY_ENTRY_TLS].Size;
            }
        }
#endif
        if (tls_rva && tls_size) {
            IMAGE_TLS_DIRECTORY *tls =
                (IMAGE_TLS_DIRECTORY *)(image + tls_rva);

            DWORD stub_idx = _tls_index;

            size_t raw_len = (size_t)(
                tls->EndAddressOfRawData - tls->StartAddressOfRawData);
            size_t total_len = raw_len + tls->SizeOfZeroFill;
            {
#ifdef _WIN64
                BYTE **tls_array =
                    (BYTE **)(uintptr_t)__readgsqword(0x58);
#else
                BYTE **tls_array =
                    (BYTE **)(uintptr_t)__readfsdword(0x2C);
#endif
                if (tls_array && tls_array[stub_idx] && raw_len > 0) {
                    memcpy(tls_array[stub_idx],
                           (const void *)(uintptr_t)
                               tls->StartAddressOfRawData,
                           raw_len);
                }
            }

            *(DWORD *)(uintptr_t)tls->AddressOfIndex = stub_idx;

            /* Publish template info so the stub's TLS callback
             * (zpp_tls_callback) can set up proper TLS for new threads. */
            g_tls_template_ptr     = (const BYTE *)(uintptr_t)
                                         tls->StartAddressOfRawData;
            g_tls_template_raw_len = raw_len;
            g_tls_total_len        = total_len;

            /* Update _tls_used so anything that reads it at runtime
             * sees the decompressed image's template, not the stub's. */
            {
                DWORD old_prot;
                VirtualProtect((void *)&_tls_used, sizeof(_tls_used),
                               PAGE_READWRITE, &old_prot);
                IMAGE_TLS_DIRECTORY *stub_tls =
                    (IMAGE_TLS_DIRECTORY *)(uintptr_t)&_tls_used;
                stub_tls->StartAddressOfRawData = tls->StartAddressOfRawData;
                stub_tls->EndAddressOfRawData   = tls->EndAddressOfRawData;
                stub_tls->SizeOfZeroFill        = tls->SizeOfZeroFill;
                VirtualProtect((void *)&_tls_used, sizeof(_tls_used),
                               old_prot, &old_prot);
            }

            tls->AddressOfCallBacks = 0;
        }
    }

    /* 6b. Erase the TLS DataDirectory entry in the decompressed image's
     *     PE headers so the loader never processes it as a TLS-bearing
     *     module (we already migrated everything into the stub's slot). */
#ifdef _WIN64
    {
        IMAGE_DOS_HEADER *img_dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS64 *img_nt64 =
            (IMAGE_NT_HEADERS64 *)(image + img_dos->e_lfanew);
        if (img_nt64->OptionalHeader.NumberOfRvaAndSizes >
            IMAGE_DIRECTORY_ENTRY_TLS) {
            img_nt64->OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
            img_nt64->OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
        }
    }
#else
    {
        IMAGE_DOS_HEADER *img_dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS32 *img_nt32 =
            (IMAGE_NT_HEADERS32 *)(image + img_dos->e_lfanew);
        if (img_nt32->OptionalHeader.NumberOfRvaAndSizes >
            IMAGE_DIRECTORY_ENTRY_TLS) {
            img_nt32->OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
            img_nt32->OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
        }
    }
#endif

    /* 7. Initialize security cookie (/GS) from the Load Configuration
     *    Directory. The Windows loader normally does this, but we bypass it. */
#ifdef _WIN64
    {
        IMAGE_DOS_HEADER *img_dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS64 *img_nt =
            (IMAGE_NT_HEADERS64 *)(image + img_dos->e_lfanew);
        if (img_nt->OptionalHeader.NumberOfRvaAndSizes >
            IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
            DWORD lc_rva = img_nt->OptionalHeader.DataDirectory
                               [IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
            if (lc_rva) {
                IMAGE_LOAD_CONFIG_DIRECTORY64 *lc =
                    (IMAGE_LOAD_CONFIG_DIRECTORY64 *)(image + lc_rva);
                if (lc->SecurityCookie) {
                    DWORD64 *cookie = (DWORD64 *)(uintptr_t)lc->SecurityCookie;
                    LARGE_INTEGER pc;
                    QueryPerformanceCounter(&pc);
                    DWORD64 val = pc.QuadPart;
                    val ^= GetCurrentProcessId();
                    val ^= GetCurrentThreadId();
                    val ^= (DWORD64)(uintptr_t)&val;
                    if (val == 0x2B992DDFA232ULL) val++;
                    if ((val & 0x0000FFFFFFFFFFFFULL) == 0) val = 0x2B992DDFA233ULL;
                    *cookie = val;
                }
            }
        }
    }
#endif

    /* 8. Set per-section page protections (RX for code, RW for data). */
    apply_section_protections(image);

    /* 8a. Touch the file system API so internal NT state is initialized.
     *     Without this, some runtimes (Rust/Tauri) crash on startup. */
    {
        HANDLE h = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    /* 8b. Patch PEB and LDR so the OS and runtime see the unpacked image
     *     as the main module (GetModuleHandle, FindResource, etc.). */
#ifdef _WIN64
    {
        BYTE *peb = (BYTE *)(uintptr_t)__readgsqword(0x60);
        *(ULONGLONG *)(peb + 0x10) = (ULONGLONG)(uintptr_t)image;
        BYTE *ldr = *(BYTE **)(peb + 0x18);
        BYTE *first = *(BYTE **)(ldr + 0x10);
        *(ULONGLONG *)(first + 0x30) = (ULONGLONG)(uintptr_t)image;
        *(ULONGLONG *)(first + 0x38) = (ULONGLONG)(uintptr_t)(image + hdr->orig_entry_rva);
        *(ULONG     *)(first + 0x40) = (ULONG)hdr->orig_image_size;
    }
#else
    {
        BYTE *peb = (BYTE *)(uintptr_t)__readfsdword(0x30);
        *(DWORD *)(peb + 0x08) = (DWORD)(uintptr_t)image;
        BYTE *ldr = *(BYTE **)(peb + 0x0C);
        BYTE *first = *(BYTE **)(ldr + 0x0C);
        *(DWORD *)(first + 0x18) = (DWORD)(uintptr_t)image;
        *(DWORD *)(first + 0x1C) = (DWORD)(uintptr_t)(image + hdr->orig_entry_rva);
        *(DWORD *)(first + 0x20) = (DWORD)hdr->orig_image_size;
    }
#endif

    /* 9. Transfer control to the original entry point. */
    entry_point_fn oep = (entry_point_fn)(image + hdr->orig_entry_rva);
    oep();

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
