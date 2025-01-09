#pragma once

#include "../common.hpp"
#include <capstone/capstone.h>

class Instruction {
public:
    cs_insn* insn;
    cs_detail* detail;

    Instruction(cs_insn* insn, cs_detail* detail) : insn(insn), detail(detail) {}
    ~Instruction() { cs_free(insn, 1); }
}

// Standard thumb instructions:
// http://bear.ces.cwru.edu/eecs_382/ARM7-TDMI-manual-pt3.pdf

// Special instructions:
// https://www.st.com/resource/en/programming_manual/pm0214-stm32-cortexm4-mcus-and-mpus-programming-manual-stmicroelectronics.pdf