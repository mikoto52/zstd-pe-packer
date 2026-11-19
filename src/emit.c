/*
 * emit.c - Packed PE emitter.
 *
 * Takes the prebuilt stub PE, appends a ".zpp" section holding the
 * zpp_header_t + compressed payload, and adjusts PE headers so the result is
 * a valid, runnable executable whose entry point is the stub code.
 *
 * This is a build-time file manipulation tool (like a linker post-processor).
 * It does no execution, no memory mapping — just byte shuffling.
 */
#include "emit.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Round `v` up to the next multiple of `align`. */
static uint32_t align_up(uint32_t v, uint32_t align) {
    if (align == 0) return v;
    return (v + align - 1) & ~(align - 1);
}

int zpp_emit_packed_pe(
    const uint8_t *stub_pe, size_t stub_pe_size,
    const zpp_header_t *hdr,
    const uint8_t *comp_data, size_t comp_size,
    uint8_t **out_data, size_t *out_size)
{
    *out_data = NULL;
    *out_size = 0;

    /* ----- 1. Parse the stub PE headers ----- */

    if (stub_pe_size < sizeof(IMAGE_DOS_HEADER)) {
        fprintf(stderr, "emit: stub too small\n"); return 1;
    }
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)stub_pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "emit: stub not MZ\n"); return 1;
    }
    size_t nt_off = (size_t)dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > stub_pe_size) {
        fprintf(stderr, "emit: stub NT headers out of bounds\n"); return 1;
    }
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(stub_pe + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "emit: stub not PE\n"); return 1;
    }

    WORD  num_sections = nt->FileHeader.NumberOfSections;
    WORD  opt_hdr_size = nt->FileHeader.SizeOfOptionalHeader;
    WORD  magic        = *(WORD *)(stub_pe + nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    uint32_t file_align, sect_align, old_size_of_image;
    size_t   opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64 *oh = (const IMAGE_OPTIONAL_HEADER64 *)(stub_pe + opt_off);
        file_align        = oh->FileAlignment;
        sect_align        = oh->SectionAlignment;
        old_size_of_image = oh->SizeOfImage;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32 *oh = (const IMAGE_OPTIONAL_HEADER32 *)(stub_pe + opt_off);
        file_align        = oh->FileAlignment;
        sect_align        = oh->SectionAlignment;
        old_size_of_image = oh->SizeOfImage;
    } else {
        fprintf(stderr, "emit: stub unknown optional header magic\n"); return 1;
    }

    /* Section table follows the optional header. */
    size_t sec_table_off = opt_off + opt_hdr_size;
    const IMAGE_SECTION_HEADER *sections =
        (const IMAGE_SECTION_HEADER *)(stub_pe + sec_table_off);

    /* ----- 2. Check room for one more section header ----- */

    /*
     * The section table sits right after the optional header. We need space for
     * one more IMAGE_SECTION_HEADER before the first section's raw data starts.
     * The headers area is typically padded to FileAlignment, so there is usually
     * plenty of room (the stub is small).
     */
    size_t new_sec_hdr_off = sec_table_off +
                             (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER);
    size_t end_of_new_hdr  = new_sec_hdr_off + sizeof(IMAGE_SECTION_HEADER);

    /* Find the smallest PointerToRawData among existing sections. */
    uint32_t first_raw = UINT32_MAX;
    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].PointerToRawData && sections[i].PointerToRawData < first_raw)
            first_raw = sections[i].PointerToRawData;
    }
    if (first_raw == UINT32_MAX) first_raw = align_up((uint32_t)end_of_new_hdr, file_align);

    if (end_of_new_hdr > first_raw) {
        fprintf(stderr, "emit: no room for extra section header in stub "
                        "(need %zu, first raw at %u)\n", end_of_new_hdr, first_raw);
        return 1;
    }

    /* ----- 3. Compute the .zpp section layout ----- */

    /* Find the last section to determine where new raw data and VA go. */
    uint32_t last_raw_end = 0;
    uint32_t last_va_end  = 0;
    for (WORD i = 0; i < num_sections; i++) {
        uint32_t re = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        uint32_t ve = sections[i].VirtualAddress +
                      align_up(sections[i].Misc.VirtualSize, sect_align);
        if (re > last_raw_end) last_raw_end = re;
        if (ve > last_va_end)  last_va_end  = ve;
    }

    uint32_t zpp_raw_size  = (uint32_t)(sizeof(zpp_header_t) + comp_size);
    uint32_t zpp_file_size = align_up(zpp_raw_size, file_align);
    uint32_t zpp_va        = align_up(last_va_end, sect_align);
    uint32_t zpp_virt_size = zpp_raw_size; /* actual data length */
    uint32_t zpp_file_off  = align_up(last_raw_end, file_align);

    uint32_t new_size_of_image = align_up(zpp_va + zpp_virt_size, sect_align);

    /* ----- 4. Build the output buffer ----- */

    size_t total = (size_t)zpp_file_off + zpp_file_size;
    uint8_t *out = (uint8_t *)calloc(1, total);
    if (!out) { fprintf(stderr, "emit: OOM (%zu)\n", total); return 1; }

    /* Copy the original stub bytes. */
    memcpy(out, stub_pe, stub_pe_size < total ? stub_pe_size : total);
    /* Zero any gap between original stub end and our new section. */
    if (stub_pe_size < (size_t)zpp_file_off)
        memset(out + stub_pe_size, 0, (size_t)zpp_file_off - stub_pe_size);

    /* ----- 5. Write the new .zpp section header ----- */

    IMAGE_SECTION_HEADER *new_sec = (IMAGE_SECTION_HEADER *)(out + new_sec_hdr_off);
    memset(new_sec, 0, sizeof(*new_sec));
    memcpy(new_sec->Name, ZPP_SECTION_NAME, strlen(ZPP_SECTION_NAME));
    new_sec->Misc.VirtualSize  = zpp_virt_size;
    new_sec->VirtualAddress    = zpp_va;
    new_sec->SizeOfRawData     = zpp_file_size;
    new_sec->PointerToRawData  = zpp_file_off;
    new_sec->Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    /* ----- 6. Write the .zpp section data: [hdr][compressed payload] ----- */

    uint8_t *sec_data = out + zpp_file_off;
    memcpy(sec_data, hdr, sizeof(zpp_header_t));
    memcpy(sec_data + sizeof(zpp_header_t), comp_data, comp_size);

    /* ----- 7. Patch PE headers in the output ----- */

    IMAGE_NT_HEADERS *out_nt = (IMAGE_NT_HEADERS *)(out + nt_off);
    out_nt->FileHeader.NumberOfSections = num_sections + 1;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 *oh =
            (IMAGE_OPTIONAL_HEADER64 *)(out + opt_off);
        oh->SizeOfImage = new_size_of_image;
        /* Clear bound import and certificate directories (they're invalidated). */
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        /* Update checksum to 0 (must be re-signed anyway if signing). */
        oh->CheckSum = 0;
    } else {
        IMAGE_OPTIONAL_HEADER32 *oh =
            (IMAGE_OPTIONAL_HEADER32 *)(out + opt_off);
        oh->SizeOfImage = new_size_of_image;
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        oh->CheckSum = 0;
    }

    *out_data = out;
    *out_size = total;
    return 0;
}
