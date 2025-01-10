#include "architecture.hpp"

#include "../loader/binary.hpp"

#include <stdint.h>

bool Memory::read(uint32_t addr, void *data, size_t size){
    FILE *memfile = fopen("memfile", "r");
    fseek(memfile, addr, SEEK_SET);
    fread(data, size, 1, memfile);
    return true;
}

bool Memory::write(uint32_t addr, void *data, size_t size){
    FILE *memfile = fopen("memfile", "w");
    fseek(memfile, addr, SEEK_SET);
    fwrite(data, size, 1, memfile);
    return true;
}

void Architecture::init(Binary& binary){
    // Loop through section_map and write to memfile
    binary.loadMemory(mem);

    // Initialize registers
    for(int i=0; i<NUM_REGS; i++){
        regfile[i] = 0;
    }
}

// void bootup(){

// }