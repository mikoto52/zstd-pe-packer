/*
 * zpp.c - Command-line front end for ZSTD-PE-Packer.
 *
 *   zpp [options] <input.exe> [-o <output.exe>]
 */
#include "pack.h"
#include "format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *argv0) {
    fprintf(stderr,
        "ZSTD-PE-Packer v" ZPP_VERSION_STRING "\n"
        "usage: %s [options] <input.exe>\n"
        "\n"
        "  -o <file>          output path (default: <input>.packed.exe)\n"
        "  -l <1..22>         zstd compression level (default: 22, max)\n"
        "  --strip-metadata   do not copy original resources (version/icon/manifest)\n"
        "  -v                 verbose\n"
        "  -h, --help         this help\n",
        argv0);
}

int main(int argc, char **argv) {
    zpp_options opt;
    memset(&opt, 0, sizeof(opt));
    opt.level = 22; /* zstd max compression (--ultra) */

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(argv[0]); return 0; }
        else if (!strcmp(a, "-v")) { opt.verbose = 1; }
        else if (!strcmp(a, "--strip-metadata")) { opt.strip_metadata = 1; }
        else if (!strcmp(a, "-o")) {
            if (++i >= argc) { fprintf(stderr, "zpp: -o needs an argument\n"); return 2; }
            opt.output_path = argv[i];
        }
        else if (!strcmp(a, "-l")) {
            if (++i >= argc) { fprintf(stderr, "zpp: -l needs an argument\n"); return 2; }
            opt.level = atoi(argv[i]);
            if (opt.level < 1 || opt.level > 22) { fprintf(stderr, "zpp: level must be 1..22\n"); return 2; }
        }
        else if (a[0] == '-') { fprintf(stderr, "zpp: unknown option '%s'\n", a); usage(argv[0]); return 2; }
        else {
            if (opt.input_path) { fprintf(stderr, "zpp: multiple inputs given\n"); return 2; }
            opt.input_path = a;
        }
    }

    if (!opt.input_path) { usage(argv[0]); return 2; }

    /* Derive default output path: "<input>.packed.exe". */
    char derived[1024];
    if (!opt.output_path) {
        snprintf(derived, sizeof(derived), "%s.packed.exe", opt.input_path);
        opt.output_path = derived;
    }

    return zpp_pack(&opt);
}
