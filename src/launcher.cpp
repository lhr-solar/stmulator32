#include "utils.hpp"
// https://www.capstone-engine.org/lang_c.html
#include "capstone/capstone.h"
#include "loader/binary.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        println("Usage: ./stmulator <path-to-elf-file>");
        exit(-1);
    }

    println("Initializing STMulator...");
    Binary b(argv[1]);

    // Capstone engine stuff
    csh handle;
    cs_insn *insn;
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return -1;
    }
    size_t count = cs_disasm(handle, b.code_ptr, b.code_size, b.header->e_entry, 4, &insn);
    if (count > 0) {
        for (size_t j = 0; j < count; j++) {
            printf("0x%X:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
        }
        cs_free(insn, count);
    }

    return 0;
}