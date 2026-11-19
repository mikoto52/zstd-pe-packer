/*
 * pack.c - Packing pipeline (CLI side).
 *
 * Reads a PE, compresses its mapped image with zstd, and (TODO) emits a new PE
 * whose entry point is the embedded unpacking stub. All work here is ordinary
 * file/byte manipulation performed at build time.
 */
#include "pack.h"
#include "emit.h"
#include "format.h"
#include "zpp_stub_blob.h"

#include <zstd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple CRC32 (IEEE) for header integrity. */
static uint32_t crc32_calc(const uint8_t *p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int b = 0; b < 8; ++b)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1)));
    }
    return ~crc;
}

int zpp_pack(const zpp_options *opt) {
    zpp_pe pe;
    if (zpp_pe_load(opt->input_path, &pe) != 0) return 1;

    if (opt->verbose) {
        printf("zpp: %s  (%s, %s%s, image_base=0x%llx, size_of_image=%u, OEP=0x%x)\n",
               opt->input_path, pe.is_pe32_plus ? "PE32+" : "PE32",
               pe.kind == ZPP_EXE_DOTNET_MANAGED ? ".NET managed" : "native",
               pe.has_tls_callbacks ? ", TLS callbacks" : "",
               (unsigned long long)pe.image_base, pe.size_of_image, pe.entry_rva);
    }

    /*
     * Managed .NET assemblies execute through the CLR, not a native entry point,
     * so the native-OEP stub cannot run them. Refuse clearly in v1.
     * (Native output of any language -- C/C++/Rust/Go/Nuitka/PyInstaller/
     *  NativeAOT -- takes the normal path below.)
     */
    if (pe.kind == ZPP_EXE_DOTNET_MANAGED) {
        fprintf(stderr,
            "zpp: '%s' is a .NET managed (CIL) assembly.\n"
            "     Native packing is not supported yet (needs a CLR-hosting loader).\n"
            "     Tip: .NET published with NativeAOT produces a native PE that works.\n",
            opt->input_path);
        zpp_pe_free(&pe);
        return 1;
    }

    /* 1-2. Build mapped image. */
    uint8_t *image = NULL;
    uint32_t image_size = 0;
    if (zpp_pe_build_mapped_image(&pe, &image, &image_size) != 0) { zpp_pe_free(&pe); return 1; }

    /* 3. Compress with zstd.
     *    Levels 20-22 are "ultra" and require enabling the long-distance
     *    matching window via ZSTD_c_windowLog, so we use the advanced API. */
    size_t bound = ZSTD_compressBound(image_size);
    uint8_t *comp = (uint8_t *)malloc(bound);
    if (!comp) { free(image); zpp_pe_free(&pe); fprintf(stderr, "zpp: OOM\n"); return 1; }

    int level = opt->level ? opt->level : 22;
    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    if (!cctx) { free(comp); free(image); zpp_pe_free(&pe); fprintf(stderr, "zpp: OOM\n"); return 1; }

    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    if (level >= 20) {
        /* Ultra mode: enable long window (27 = 128 MB, more than enough). */
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, 27);
    }

    size_t comp_size = ZSTD_compress2(cctx, comp, bound, image, image_size);
    ZSTD_freeCCtx(cctx);
    if (ZSTD_isError(comp_size)) {
        fprintf(stderr, "zpp: zstd error: %s\n", ZSTD_getErrorName(comp_size));
        free(comp); free(image); zpp_pe_free(&pe); return 1;
    }

    if (opt->verbose) {
        printf("zpp: compressed %u -> %zu bytes (%.1f%%, level %d)\n",
               image_size, comp_size, 100.0 * (double)comp_size / image_size, level);
    }

    /* 4. Build header. */
    zpp_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic[0] = ZPP_MAGIC0; hdr.magic[1] = ZPP_MAGIC1;
    hdr.magic[2] = ZPP_MAGIC2; hdr.magic[3] = ZPP_MAGIC3;
    hdr.version          = ZPP_FORMAT_VERSION;
    hdr.flags            = opt->strip_metadata ? 0 : ZPP_FLAG_KEEP_ORIGINAL;
    hdr.orig_image_base  = pe.image_base;
    hdr.orig_image_size  = pe.size_of_image;
    hdr.orig_entry_rva   = pe.entry_rva;
    hdr.reloc_rva        = pe.reloc_rva;
    hdr.reloc_size       = pe.reloc_size;
    hdr.import_rva       = pe.import_rva;
    hdr.import_size      = pe.import_size;
    hdr.payload_comp_size= (uint32_t)comp_size;
    hdr.payload_raw_size = image_size;
    hdr.header_crc32     = 0;
    hdr.header_crc32     = crc32_calc((const uint8_t *)&hdr, sizeof(hdr));

    /* 5. Emit the packed PE: stub + ".zpp" section. */
    uint8_t *packed = NULL;
    size_t   packed_size = 0;
    if (zpp_emit_packed_pe(zpp_stub_blob, zpp_stub_blob_size,
                           &hdr, comp, comp_size,
                           opt->strip_metadata ? NULL : &pe,
                           &packed, &packed_size) != 0) {
        fprintf(stderr, "zpp: emitter failed\n");
        free(comp); free(image); zpp_pe_free(&pe);
        return 1;
    }

    const char *out_path = opt->output_path ? opt->output_path : "out.packed.exe";
    FILE *f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "zpp: cannot write '%s'\n", out_path);
        free(packed); free(comp); free(image); zpp_pe_free(&pe);
        return 1;
    }
    fwrite(packed, 1, packed_size, f);
    fclose(f);

    if (opt->verbose) {
        printf("zpp: packed PE -> %s (%zu bytes, ratio %.1f%%)\n",
               out_path, packed_size,
               100.0 * (double)packed_size / pe.size);
    }

    free(packed);

    free(comp);
    free(image);
    zpp_pe_free(&pe);
    return 0;
}
