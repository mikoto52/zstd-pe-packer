/*
 * stub_intrinsics.c — Compiler intrinsics that zstd expects but the CRT provides.
 *
 * In a no-CRT build, _byteswap_ulong, _byteswap_uint64, and _rotl64 are not
 * available because they come from <stdlib.h> / <intrin.h> CRT stubs. We
 * provide inline implementations so the linker resolves them.
 */
#include <stdint.h>

unsigned long _cdecl _byteswap_ulong(unsigned long val) {
    return ((val & 0x000000FFu) << 24) |
           ((val & 0x0000FF00u) <<  8) |
           ((val & 0x00FF0000u) >>  8) |
           ((val & 0xFF000000u) >> 24);
}

unsigned __int64 _cdecl _byteswap_uint64(unsigned __int64 val) {
    return ((val & 0x00000000000000FFull) << 56) |
           ((val & 0x000000000000FF00ull) << 40) |
           ((val & 0x0000000000FF0000ull) << 24) |
           ((val & 0x00000000FF000000ull) <<  8) |
           ((val & 0x000000FF00000000ull) >>  8) |
           ((val & 0x0000FF0000000000ull) >> 24) |
           ((val & 0x00FF000000000000ull) >> 40) |
           ((val & 0xFF00000000000000ull) >> 56);
}

unsigned __int64 _cdecl _rotl64(unsigned __int64 val, int shift) {
    shift &= 63;
    return (val << shift) | (val >> (64 - shift));
}
