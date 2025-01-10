#pragma once

#include "../loader/binary.hpp"
#include <bitset>

// Need to define register file and flags
typedef enum {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    SP = 13,
    LR = 14,
    PC = 15,
    CPSR = 16,
    NUM_REGS
} regs;

class Memory {
private:
    size_t size;
public:
    Memory(size_t size) : size(size) {
        // Create file for memory model
        FILE *memfile = fopen("memfile", "w");
        fseek(memfile, size, SEEK_SET);
        fputc(0, memfile);
        fclose(memfile);
    }

    bool read(uint32_t addr, void *data, size_t size);
    bool write(uint32_t addr, void *data, size_t size);
};

class Binary;
class Architecture {
public:    
    int32_t regfile[NUM_REGS];
    Memory mem;

    void init(Binary &binary);

    Architecture(Binary &binary) : mem(0xFFFFFFFF) {
        init(binary);
    }
};