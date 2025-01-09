#include "utils.hpp"
#include "loader/binary.hpp"
#include <capstone/capstone.h>
#include <assert.h>
#include <inttypes.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        println("Usage: ./stmulator <path-to-elf-file>");
        exit(-1);
    }

    println("Initializing STMulator...");
    Binary b(argv[1]);
    b.dumpSections();
    b.dumpInstructions();

    return 0;
}