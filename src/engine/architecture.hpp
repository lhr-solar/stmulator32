#pragma once

#include "../common.hpp"
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

// Regfile
extern int32_t regfile[];

// Update system flags based on input value.
void updateFlags(int32_t result, bool overflow = false);