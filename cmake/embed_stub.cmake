# embed_stub.cmake — convert zpp_stub.exe into a C byte-array header.
#
# Input:  STUB_EXE  — path to built zpp_stub.exe
# Output: OUT_H     — path to generated zpp_stub_blob.h

cmake_minimum_required(VERSION 3.20)

file(READ "${STUB_EXE}" STUB_HEX HEX)
string(LENGTH "${STUB_HEX}" HEX_LEN)
math(EXPR BYTE_LEN "${HEX_LEN} / 2")

set(OUT "/* Auto-generated — do not edit. */\n")
string(APPEND OUT "#ifndef ZPP_STUB_BLOB_H\n#define ZPP_STUB_BLOB_H\n\n")
string(APPEND OUT "#include <stddef.h>\n\n")
string(APPEND OUT "static const unsigned char zpp_stub_blob[] = {\n")

set(POS 0)
set(LINE "    ")
set(COL 0)
while(POS LESS HEX_LEN)
    string(SUBSTRING "${STUB_HEX}" ${POS} 2 BYTE)
    string(APPEND LINE "0x${BYTE},")
    math(EXPR COL "${COL} + 1")
    math(EXPR POS "${POS} + 2")
    if(COL EQUAL 16)
        string(APPEND OUT "${LINE}\n")
        set(LINE "    ")
        set(COL 0)
    endif()
endwhile()
if(COL GREATER 0)
    string(APPEND OUT "${LINE}\n")
endif()

string(APPEND OUT "};\n\n")
string(APPEND OUT "static const size_t zpp_stub_blob_size = ${BYTE_LEN};\n\n")
string(APPEND OUT "#endif /* ZPP_STUB_BLOB_H */\n")

file(WRITE "${OUT_H}" "${OUT}")
message(STATUS "Embedded stub: ${BYTE_LEN} bytes -> ${OUT_H}")
