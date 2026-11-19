/*
 * pack.h - Packing pipeline (CLI side).
 */
#ifndef ZPP_PACK_H
#define ZPP_PACK_H

#include "pe.h"

typedef struct zpp_options {
    const char *input_path;
    const char *output_path;   /* may be NULL -> derived */
    int         level;         /* zstd level 1..22 */
    int         strip_metadata; /* --strip-metadata: skip .rsrc copy */
    int         verbose;
} zpp_options;

/*
 * Full pipeline:
 *   1. load input PE
 *   2. build its mapped image
 *   3. compress the mapped image with zstd
 *   4. build the zpp header
 *   5. emit a new PE: stub code + a ".zpp" section holding header+payload,
 *      with the entry point pointing at the stub.
 *
 * Returns 0 on success.
 */
int zpp_pack(const zpp_options *opt);

#endif /* ZPP_PACK_H */
