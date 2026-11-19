/*
 * pe.c - Minimal PE parsing (CLI side; uses CRT + <windows.h>).
 *
 * Responsibilities:
 *   - Read a PE file from disk and validate the MZ/PE signatures.
 *   - Extract the fields the packer and stub need (image base/size, OEP,
 *     relocation and import directory locations).
 *   - Lay the file's sections out at their virtual addresses to form the
 *     "mapped image" buffer that becomes the compressed payload.
 *
 * This file does no memory execution or runtime patching; it only reads bytes
 * and rearranges them into a buffer that is handed to the compressor.
 */
#include "pe.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)n;
    return buf;
}

static int in_bounds(const zpp_pe *pe, size_t off, size_t len) {
    return off <= pe->size && len <= pe->size - off;
}

int zpp_pe_load(const char *path, zpp_pe *out) {
    memset(out, 0, sizeof(*out));
    out->data = read_file(path, &out->size);
    if (!out->data) { fprintf(stderr, "zpp: cannot read '%s'\n", path); return 1; }

    if (out->size < sizeof(IMAGE_DOS_HEADER)) { fprintf(stderr, "zpp: file too small\n"); return 1; }
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)out->data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { fprintf(stderr, "zpp: not a PE (no MZ)\n"); return 1; }

    size_t nt_off = (size_t)dos->e_lfanew;
    if (!in_bounds(out, nt_off, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        fprintf(stderr, "zpp: bad e_lfanew\n"); return 1;
    }
    out->nt_headers_off = nt_off;

    DWORD sig = *(DWORD *)(out->data + nt_off);
    if (sig != IMAGE_NT_SIGNATURE) { fprintf(stderr, "zpp: not a PE (no PE\\0\\0)\n"); return 1; }

    IMAGE_FILE_HEADER *fh =
        (IMAGE_FILE_HEADER *)(out->data + nt_off + sizeof(DWORD));
    out->number_of_sections      = fh->NumberOfSections;
    out->size_of_optional_header = fh->SizeOfOptionalHeader;

    size_t opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!in_bounds(out, opt_off, sizeof(WORD))) { fprintf(stderr, "zpp: no optional header\n"); return 1; }
    WORD magic = *(WORD *)(out->data + opt_off);

    const IMAGE_DATA_DIRECTORY *dirs = NULL;
    uint32_t num_dirs = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        out->is_pe32_plus = 1;
        IMAGE_OPTIONAL_HEADER64 *oh = (IMAGE_OPTIONAL_HEADER64 *)(out->data + opt_off);
        out->image_base       = oh->ImageBase;
        out->size_of_image    = oh->SizeOfImage;
        out->entry_rva        = oh->AddressOfEntryPoint;
        out->file_alignment   = oh->FileAlignment;
        out->section_alignment= oh->SectionAlignment;
        dirs = oh->DataDirectory;
        num_dirs = oh->NumberOfRvaAndSizes;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        out->is_pe32_plus = 0;
        IMAGE_OPTIONAL_HEADER32 *oh = (IMAGE_OPTIONAL_HEADER32 *)(out->data + opt_off);
        out->image_base       = oh->ImageBase;
        out->size_of_image    = oh->SizeOfImage;
        out->entry_rva        = oh->AddressOfEntryPoint;
        out->file_alignment   = oh->FileAlignment;
        out->section_alignment= oh->SectionAlignment;
        dirs = oh->DataDirectory;
        num_dirs = oh->NumberOfRvaAndSizes;
    } else {
        fprintf(stderr, "zpp: unknown optional header magic 0x%04x\n", magic);
        return 1;
    }

    if (num_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        out->reloc_rva  = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        out->reloc_size = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        out->import_rva = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        out->import_size= dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    /* TLS callbacks (e.g. Go runtime, some C++): needed by the stub later. */
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_TLS)
        out->has_tls_callbacks = (dirs[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0);

    /* .NET COM descriptor (index 14): presence => managed CIL assembly, which
     * runs through the CLR rather than a native entry point. Detect so the
     * packer can take a different path (or refuse, in v1). */
    if (num_dirs > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) {
        out->com_rva  = dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        out->com_size = dirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
    }
    out->kind = (out->com_size != 0) ? ZPP_EXE_DOTNET_MANAGED : ZPP_EXE_NATIVE;

    out->section_table_off = opt_off + out->size_of_optional_header;
    return 0;
}

void zpp_pe_free(zpp_pe *pe) {
    if (pe && pe->data) { free(pe->data); pe->data = NULL; pe->size = 0; }
}

int zpp_pe_build_mapped_image(const zpp_pe *pe, uint8_t **out_image, uint32_t *out_size) {
    uint32_t image_size = pe->size_of_image;
    if (image_size == 0) { fprintf(stderr, "zpp: SizeOfImage is 0\n"); return 1; }

    uint8_t *img = (uint8_t *)calloc(1, image_size);
    if (!img) { fprintf(stderr, "zpp: out of memory (%u)\n", image_size); return 1; }

    /* Copy headers (up to the first section's file offset) at RVA 0. */
    size_t headers_size = pe->section_table_off +
                          (size_t)pe->number_of_sections * sizeof(IMAGE_SECTION_HEADER);
    if (headers_size > image_size || headers_size > pe->size) {
        free(img); fprintf(stderr, "zpp: header size inconsistent\n"); return 1;
    }
    memcpy(img, pe->data, headers_size);

    /* Place each section at its virtual address. */
    const IMAGE_SECTION_HEADER *sec =
        (const IMAGE_SECTION_HEADER *)(pe->data + pe->section_table_off);
    for (uint16_t i = 0; i < pe->number_of_sections; ++i) {
        uint32_t va  = sec[i].VirtualAddress;
        uint32_t vsz = sec[i].Misc.VirtualSize;
        uint32_t rsz = sec[i].SizeOfRawData;
        uint32_t ptr = sec[i].PointerToRawData;
        uint32_t copy = (rsz < vsz) ? rsz : vsz;

        if ((uint64_t)va + vsz > image_size) {
            free(img); fprintf(stderr, "zpp: section %u exceeds image\n", i); return 1;
        }
        if (copy) {
            if ((uint64_t)ptr + copy > pe->size) {
                free(img); fprintf(stderr, "zpp: section %u raw data out of bounds\n", i); return 1;
            }
            memcpy(img + va, pe->data + ptr, copy);
        }
    }

    *out_image = img;
    *out_size  = image_size;
    return 0;
}
