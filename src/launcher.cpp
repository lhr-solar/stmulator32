#include "utils.hpp"
#include "loader/binary.hpp"
#include <capstone/capstone.h>
#include <assert.h>
#include <inttypes.h>

#define THUMB_CODE "\x60\xf9\x1f\x04\xe0\xf9\x4f\x07\x70\x47\x00\xf0\x10\xe8\xeb\x46\x83\xb0\xc9\x68\x1f\xb1\x30\xbf\xaf\xf3\x20\x84\x52\xf8\x23\xf0"

int main(int argc, char** argv) {
    if (argc != 2) {
        println("Usage: ./stmulator <path-to-elf-file>");
        exit(-1);
    }

    println("Initializing STMulator...");
    Binary b(argv[1]);
    b.dumpSections();

    csh handle;
    cs_insn *insn;
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK)
		return -1;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    printf("First line: 0x%x\n", ((uint16_t*)b.code_ptr)[0]);
    
    size_t count = cs_disasm(handle, (uint8_t*)b.code_ptr, b.code_size, 0x80001d8, 0, &insn);
    printf("Count: %d\n", count);
    
    for(int i=0; i<count; i++){
        printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
    }
    
    cs_free(insn, count);
    cs_close(&handle);

    return 0;
}