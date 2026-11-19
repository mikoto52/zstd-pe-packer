/*
 * emit.c - Packed PE emitter.
 *
 * Takes the prebuilt stub PE, appends a ".zpp" section holding the
 * zpp_header_t + compressed payload, and optionally copies the original PE's
 * .rsrc section (version info, icons, manifest) so the packed executable
 * retains the original metadata. Adjusts PE headers accordingly.
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

/* ========================================================================= */
/* Resource directory RVA fixup.                                             */
/*                                                                           */
/* The resource tree uses IMAGE_RESOURCE_DATA_ENTRY.OffsetToData which are   */
/* absolute RVAs (from image base). When we copy .rsrc to a new VA, we need  */
/* to adjust every such RVA by (new_rsrc_va - old_rsrc_va).                  */
/* ========================================================================= */

static void fixup_rsrc_dir(uint8_t *rsrc_base, uint32_t rsrc_size,
                           uint32_t offset, int32_t delta, int depth)
{
    if (depth > 10) return;  /* guard against malformed trees */
    if (offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > rsrc_size) return;

    IMAGE_RESOURCE_DIRECTORY *dir =
        (IMAGE_RESOURCE_DIRECTORY *)(rsrc_base + offset);
    WORD total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    uint32_t entries_off = offset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    for (WORD i = 0; i < total; i++) {
        uint32_t entry_off = entries_off + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        if (entry_off + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > rsrc_size) break;

        IMAGE_RESOURCE_DIRECTORY_ENTRY *ent =
            (IMAGE_RESOURCE_DIRECTORY_ENTRY *)(rsrc_base + entry_off);

        if (ent->OffsetToData & 0x80000000u) {
            /* Subdirectory — recurse. */
            uint32_t sub_off = ent->OffsetToData & 0x7FFFFFFFu;
            fixup_rsrc_dir(rsrc_base, rsrc_size, sub_off, delta, depth + 1);
        } else {
            /* Leaf — IMAGE_RESOURCE_DATA_ENTRY with an absolute RVA. */
            uint32_t leaf_off = ent->OffsetToData;
            if (leaf_off + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > rsrc_size) continue;

            IMAGE_RESOURCE_DATA_ENTRY *data =
                (IMAGE_RESOURCE_DATA_ENTRY *)(rsrc_base + leaf_off);
            data->OffsetToData += delta;
        }
    }
}

int zpp_emit_packed_pe(
    const uint8_t *stub_pe, size_t stub_pe_size,
    const zpp_header_t *hdr,
    const uint8_t *comp_data, size_t comp_size,
    const zpp_pe *orig,
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

    uint32_t file_align, sect_align;
    size_t   opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64 *oh = (const IMAGE_OPTIONAL_HEADER64 *)(stub_pe + opt_off);
        file_align = oh->FileAlignment;
        sect_align = oh->SectionAlignment;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32 *oh = (const IMAGE_OPTIONAL_HEADER32 *)(stub_pe + opt_off);
        file_align = oh->FileAlignment;
        sect_align = oh->SectionAlignment;
    } else {
        fprintf(stderr, "emit: stub unknown optional header magic\n"); return 1;
    }

    size_t sec_table_off = opt_off + opt_hdr_size;
    const IMAGE_SECTION_HEADER *sections =
        (const IMAGE_SECTION_HEADER *)(stub_pe + sec_table_off);

    /* ----- 2. Determine how many extra sections we need ----- */

    int has_rsrc = (orig && orig->rsrc_rva && orig->rsrc_raw_size &&
                    orig->rsrc_file_off + orig->rsrc_raw_size <= orig->size);
    int extra_sections = 1 + (has_rsrc ? 1 : 0);  /* .zpp + optionally .rsrc */

    size_t new_sec_hdr_off = sec_table_off +
                             (size_t)num_sections * sizeof(IMAGE_SECTION_HEADER);
    size_t end_of_new_hdrs = new_sec_hdr_off +
                             (size_t)extra_sections * sizeof(IMAGE_SECTION_HEADER);

    uint32_t first_raw = UINT32_MAX;
    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].PointerToRawData && sections[i].PointerToRawData < first_raw)
            first_raw = sections[i].PointerToRawData;
    }
    if (first_raw == UINT32_MAX) first_raw = align_up((uint32_t)end_of_new_hdrs, file_align);

    if (end_of_new_hdrs > first_raw) {
        fprintf(stderr, "emit: no room for %d extra section header(s) in stub "
                        "(need %zu, first raw at %u)\n",
                extra_sections, end_of_new_hdrs, first_raw);
        return 1;
    }

    /* ----- 3. Compute section layouts ----- */

    uint32_t last_raw_end = 0;
    uint32_t last_va_end  = 0;
    for (WORD i = 0; i < num_sections; i++) {
        uint32_t re = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        uint32_t ve = sections[i].VirtualAddress +
                      align_up(sections[i].Misc.VirtualSize, sect_align);
        if (re > last_raw_end) last_raw_end = re;
        if (ve > last_va_end)  last_va_end  = ve;
    }

    /* .rsrc section (placed before .zpp so it's visible to tools). */
    uint32_t rsrc_va = 0, rsrc_virt_size = 0, rsrc_file_size = 0, rsrc_file_off_out = 0;
    if (has_rsrc) {
        rsrc_va           = align_up(last_va_end, sect_align);
        rsrc_virt_size    = orig->rsrc_raw_size;
        rsrc_file_size    = align_up(rsrc_virt_size, file_align);
        rsrc_file_off_out = align_up(last_raw_end, file_align);

        last_raw_end = rsrc_file_off_out + rsrc_file_size;
        last_va_end  = rsrc_va + align_up(rsrc_virt_size, sect_align);
    }

    /* .zpp section. */
    uint32_t zpp_raw_size  = (uint32_t)(sizeof(zpp_header_t) + comp_size);
    uint32_t zpp_file_size = align_up(zpp_raw_size, file_align);
    uint32_t zpp_va        = align_up(last_va_end, sect_align);
    uint32_t zpp_virt_size = zpp_raw_size;
    uint32_t zpp_file_off  = align_up(last_raw_end, file_align);

    uint32_t new_size_of_image = align_up(zpp_va + zpp_virt_size, sect_align);

    /* ----- 4. Build the output buffer ----- */

    size_t total = (size_t)zpp_file_off + zpp_file_size;
    uint8_t *out = (uint8_t *)calloc(1, total);
    if (!out) { fprintf(stderr, "emit: OOM (%zu)\n", total); return 1; }

    /* Copy the original stub bytes. */
    memcpy(out, stub_pe, stub_pe_size < total ? stub_pe_size : total);
    if (stub_pe_size < total)
        memset(out + stub_pe_size, 0, total - stub_pe_size);

    /* ----- 5. Write section headers ----- */

    int sec_idx = 0;

    /* .rsrc header */
    if (has_rsrc) {
        IMAGE_SECTION_HEADER *rsrc_sec =
            (IMAGE_SECTION_HEADER *)(out + new_sec_hdr_off +
                                     (size_t)sec_idx * sizeof(IMAGE_SECTION_HEADER));
        memset(rsrc_sec, 0, sizeof(*rsrc_sec));
        memcpy(rsrc_sec->Name, ".rsrc\0\0\0", 8);
        rsrc_sec->Misc.VirtualSize  = rsrc_virt_size;
        rsrc_sec->VirtualAddress    = rsrc_va;
        rsrc_sec->SizeOfRawData     = rsrc_file_size;
        rsrc_sec->PointerToRawData  = rsrc_file_off_out;
        rsrc_sec->Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        sec_idx++;
    }

    /* .zpp header */
    {
        IMAGE_SECTION_HEADER *zpp_sec =
            (IMAGE_SECTION_HEADER *)(out + new_sec_hdr_off +
                                     (size_t)sec_idx * sizeof(IMAGE_SECTION_HEADER));
        memset(zpp_sec, 0, sizeof(*zpp_sec));
        memcpy(zpp_sec->Name, ZPP_SECTION_NAME, strlen(ZPP_SECTION_NAME));
        zpp_sec->Misc.VirtualSize  = zpp_virt_size;
        zpp_sec->VirtualAddress    = zpp_va;
        zpp_sec->SizeOfRawData     = zpp_file_size;
        zpp_sec->PointerToRawData  = zpp_file_off;
        zpp_sec->Characteristics   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        sec_idx++;
    }

    /* ----- 6. Write section data ----- */

    /* .rsrc data: copy from original and fix up RVAs. */
    if (has_rsrc) {
        memcpy(out + rsrc_file_off_out,
               orig->data + orig->rsrc_file_off,
               orig->rsrc_raw_size);

        int32_t rva_delta = (int32_t)rsrc_va - (int32_t)orig->rsrc_rva;
        if (rva_delta != 0) {
            fixup_rsrc_dir(out + rsrc_file_off_out, rsrc_virt_size,
                           0, rva_delta, 0);
        }
    }

    /* .zpp data */
    {
        uint8_t *sec_data = out + zpp_file_off;
        memcpy(sec_data, hdr, sizeof(zpp_header_t));
        memcpy(sec_data + sizeof(zpp_header_t), comp_data, comp_size);
    }

    /* ----- 7. Patch PE headers in the output ----- */

    IMAGE_NT_HEADERS *out_nt = (IMAGE_NT_HEADERS *)(out + nt_off);
    out_nt->FileHeader.NumberOfSections = num_sections + (WORD)extra_sections;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 *oh =
            (IMAGE_OPTIONAL_HEADER64 *)(out + opt_off);
        oh->SizeOfImage = new_size_of_image;
        /* Point resource directory to the copied .rsrc section. */
        if (has_rsrc && oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = rsrc_va;
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size           = orig->rsrc_size;
        }
        /* Clear invalidated directories. */
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
            memset(&oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY], 0,
                   sizeof(IMAGE_DATA_DIRECTORY));
        oh->CheckSum = 0;
    } else {
        IMAGE_OPTIONAL_HEADER32 *oh =
            (IMAGE_OPTIONAL_HEADER32 *)(out + opt_off);
        oh->SizeOfImage = new_size_of_image;
        if (has_rsrc && oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_RESOURCE) {
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = rsrc_va;
            oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size           = orig->rsrc_size;
        }
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
