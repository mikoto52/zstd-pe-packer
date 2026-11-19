/*
 * hello.c - Simple test program for zpp packing validation.
 *
 * Tests that after unpacking:
 *   1. Code executes correctly
 *   2. Command-line arguments are passed through
 *   3. Data sections work (static/global data)
 *   4. Import resolution works (printf from msvcrt/ucrt)
 *   5. Exit code is preserved
 */
#include <stdio.h>
#include <string.h>

static const char greeting[] = "Hello from ZSTD-PE-Packer test!";
static int global_counter = 42;

int main(int argc, char **argv) {
    /* 1. Basic output */
    printf("%s\n", greeting);

    /* 2. Show arguments to verify passthrough */
    printf("argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("  argv[%d]=%s\n", i, argv[i]);

    /* 3. Data section: read + modify global */
    printf("global_counter=%d\n", global_counter);
    global_counter++;
    printf("global_counter=%d (after ++)\n", global_counter);

    /* 4. String length to exercise more code */
    printf("greeting_len=%zu\n", strlen(greeting));

    /* 5. Return a known exit code */
    if (argc > 1 && strcmp(argv[1], "--exit7") == 0)
        return 7;
    return 0;
}
