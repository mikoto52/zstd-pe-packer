/*
 * format.h - ZSTD-PE-Packer on-disk packed format.
 *
 * Shared between the CLI (zpp) and the unpacking stub.
 * Keep this header free of CRT dependencies so the no-CRT stub can include it.
 */
#ifndef ZPP_FORMAT_H
#define ZPP_FORMAT_H

#include <stdint.h>

#define ZPP_MAGIC0 'Z'
#define ZPP_MAGIC1 'P'
#define ZPP_MAGIC2 'P'
#define ZPP_MAGIC3 '1'

#define ZPP_VERSION_MAJOR 1
#define ZPP_VERSION_MINOR 0
#define ZPP_VERSION_PATCH 0
#define ZPP_VERSION_STRING "1.0.0"

#define ZPP_FORMAT_VERSION 1u

/* Flags in zpp_header_t.flags */
#define ZPP_FLAG_KEEP_ORIGINAL 0x00000001u /* original metadata/hash preserved */

#pragma pack(push, 1)

/*
 * The packer stores one zpp_header_t followed by the zstd-compressed payload.
 *
 * The payload is the original PE's *mapped image* (sections laid out at their
 * virtual addresses, i.e. SizeOfImage bytes), so the stub can reconstruct it in
 * memory with a single VirtualAlloc + ZSTD_decompress, then fix up relocations
 * and imports and jump to OEP.
 *
 * This whole blob (header + payload) is embedded as a dedicated section in the
 * packed output; the stub locates it relative to its own module base.
 */
typedef struct zpp_header {
    uint8_t  magic[4];          /* 'Z','P','P','1'                             */
    uint32_t version;           /* ZPP_FORMAT_VERSION                          */
    uint32_t flags;             /* ZPP_FLAG_*                                  */

    uint64_t orig_image_base;   /* original OptionalHeader.ImageBase           */
    uint32_t orig_image_size;   /* original SizeOfImage (bytes of mapped image)*/
    uint32_t orig_entry_rva;    /* original AddressOfEntryPoint (OEP RVA)      */

    /* Directories the stub needs to fix up after decompression (RVAs into the
     * decompressed image). 0 size => absent. */
    uint32_t reloc_rva;
    uint32_t reloc_size;
    uint32_t import_rva;
    uint32_t import_size;

    uint32_t payload_comp_size; /* bytes of zstd-compressed payload following  */
    uint32_t payload_raw_size;  /* == orig_image_size; ZSTD_decompress target  */

    uint32_t header_crc32;      /* crc32 of this header with this field as 0   */
    uint32_t reserved;
    /* ---- zstd-compressed payload follows immediately ---- */
} zpp_header_t;

#pragma pack(pop)

/* Name of the section zpp adds to the packed PE to hold header+payload. */
#define ZPP_SECTION_NAME ".zpp"

#endif /* ZPP_FORMAT_H */
