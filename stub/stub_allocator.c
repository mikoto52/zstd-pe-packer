/*
 * stub_allocator.c — Minimal heap for the no-CRT stub.
 *
 * zstd's decompressor calls malloc/calloc/free internally. We provide them
 * via Win32 HeapAlloc/HeapFree using the process default heap, which is
 * always available even without the CRT.
 */
#include <windows.h>
#include <stddef.h>

void *malloc(size_t size) {
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void *calloc(size_t count, size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, count * size);
}

void free(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}
