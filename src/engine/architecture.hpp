#pragma once

#include "memory.hpp"
#include "binary.hpp"
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

class MemoryModel;
class Architecture {
public:    
    int32_t regfile[NUM_REGS];
    MemoryModel *mem;

    Architecture(){
        for(int i = 0; i < NUM_REGS; i++) {
            regfile[i] = 0;
        }
    }
};