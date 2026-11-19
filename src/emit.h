/*
 * emit.h - Packed PE emitter.
 *
 * Takes the stub PE blob, the zpp_header and compressed payload, and produces
 * a valid PE file: the stub with an appended ".zpp" data section.
 */
#ifndef ZPP_EMIT_H
#define ZPP_EMIT_H

#include "format.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Build the packed PE file in memory.
 *
 *   stub_pe / stub_pe_size  — raw bytes of the stub PE (from zpp_stub_blob.h)
 *   hdr                     — filled-in zpp_header_t
 *   comp_data / comp_size   — zstd-compressed payload
 *   out_data / out_size     — receives malloc'd result; caller frees.
 *
 * Returns 0 on success.
 */
int zpp_emit_packed_pe(
    const uint8_t *stub_pe, size_t stub_pe_size,
    const zpp_header_t *hdr,
    const uint8_t *comp_data, size_t comp_size,
    uint8_t **out_data, size_t *out_size);

#endif /* ZPP_EMIT_H */
