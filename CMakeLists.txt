cmake_minimum_required(VERSION 3.20)
project(zstd-pe-packer VERSION 1.0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT WIN32)
    message(FATAL_ERROR "zstd-pe-packer targets Windows PE executables only.")
endif()

# ---------------------------------------------------------------------------
# zstd dependency
#   - Default: fetch via FetchContent.
#   - Override: -DZPP_ZSTD_DIR=<path to a zstd checkout containing build/cmake>
# ---------------------------------------------------------------------------
set(ZPP_ZSTD_DIR "" CACHE PATH "Path to a local zstd source tree")

if(ZPP_ZSTD_DIR)
    add_subdirectory("${ZPP_ZSTD_DIR}/build/cmake" zstd_build)
else()
    include(FetchContent)
    FetchContent_Declare(
        zstd
        GIT_REPOSITORY https://github.com/facebook/zstd.git
        GIT_TAG        v1.5.6
        SOURCE_SUBDIR  build/cmake
    )
    set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(zstd)
    set(ZPP_ZSTD_SRC "${zstd_SOURCE_DIR}")
endif()

# ---------------------------------------------------------------------------
# zpp — the CLI packer (full zstd: compression + decompression)
# ---------------------------------------------------------------------------
add_executable(zpp
    src/zpp.c
    src/pe.c
    src/pack.c
    src/emit.c
)
target_include_directories(zpp PRIVATE
    src
    "${ZPP_ZSTD_SRC}/lib"
)
target_link_libraries(zpp PRIVATE libzstd_static)

# ---------------------------------------------------------------------------
# zstd decoder-only static library for the stub (no-CRT safe).
#
# Uses the single-file amalgamation (zstddeclib.c) generated from zstd's
# build/single_file_libs. This avoids pulling in the full zstd build for the
# stub target, and the amalgamation is designed to compile without CRT.
# ---------------------------------------------------------------------------
add_library(zstd_decoder_nocrt STATIC third_party/zstd/zstddeclib.c)
target_include_directories(zstd_decoder_nocrt PUBLIC "${ZPP_ZSTD_SRC}/lib")
if(MSVC)
    target_compile_options(zstd_decoder_nocrt PRIVATE
        /GS-        # no stack cookies (no __security_check_cookie)
        /O1         # minimize size
        /Oi-        # no intrinsics that pull CRT
        /Zl         # omit default library name in .obj
    )
    target_compile_definitions(zstd_decoder_nocrt PRIVATE
        ZSTD_NO_INLINE=1          # reduce code size
        ZSTD_STRIP_ERROR_STRINGS=1 # no string literals for error names
    )
endif()

# ---------------------------------------------------------------------------
# stub — the embedded unpacking loader (decompression only, no CRT)
#
#   Built as a standalone PE. zpp embeds its bytes into the packed output.
#   No-CRT: custom entry point, no default libraries. Imports kernel32 normally
#   (intentionally NOT hiding imports — see README design principles).
# ---------------------------------------------------------------------------
add_executable(zpp_stub WIN32
    stub/stub.c
    stub/stub_allocator.c
    stub/stub_intrinsics.c
)
target_include_directories(zpp_stub PRIVATE src "${ZPP_ZSTD_SRC}/lib")

if(MSVC)
    target_compile_options(zpp_stub PRIVATE /GS- /Gy /O1 /Oi- /Zl)
    target_link_options(zpp_stub PRIVATE
        /NODEFAULTLIB
        /ENTRY:zpp_stub_entry
        /SUBSYSTEM:WINDOWS
        /MERGE:.rdata=.text
    )
    target_link_libraries(zpp_stub PRIVATE zstd_decoder_nocrt kernel32)
endif()

# ---------------------------------------------------------------------------
# Post-build: embed stub binary into zpp as a C header (byte array).
# ---------------------------------------------------------------------------
set(STUB_BLOB_H "${CMAKE_BINARY_DIR}/generated/zpp_stub_blob.h")
add_custom_command(
    OUTPUT  "${STUB_BLOB_H}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/generated"
    COMMAND ${CMAKE_COMMAND}
        -DSTUB_EXE=$<TARGET_FILE:zpp_stub>
        -DOUT_H=${STUB_BLOB_H}
        -P "${CMAKE_SOURCE_DIR}/cmake/embed_stub.cmake"
    DEPENDS zpp_stub
    COMMENT "Embedding zpp_stub into C header"
)
add_custom_target(zpp_stub_blob DEPENDS "${STUB_BLOB_H}")
add_dependencies(zpp zpp_stub_blob)
target_include_directories(zpp PRIVATE "${CMAKE_BINARY_DIR}/generated")
