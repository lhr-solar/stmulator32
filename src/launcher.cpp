#include "utils.hpp"
#include "loader/binary.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        println("Usage: ./stmulator <path-to-elf-file>");
        exit(-1);
    }

    println("Initializing STMulator...");
    Binary b(argv[1]);

    return 0;
}