#pragma once

#include "../engine/instructions.hpp"

#include <vector>
#include <cstdint>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>

class Binary {
private:
    FILE* file; // file ptr
    std::string name; // elf name
    uint32_t size; // filesize

    std::map<std::string, Elf32_Shdr*> section_map;
    char* shstrtab;

    void loadSections();
    bool loadInstructions();

public:
    uint8_t* mapped_ptr; // mmap location of entire file
    uint8_t* code_ptr;
    size_t code_size;
    uint32_t code_addr;
    Elf32_Ehdr* header;

    cs_insn* instructions;
    
    Binary(std::string path);
    ~Binary() { fclose(file); munmap(mapped_ptr, size); delete[] shstrtab;}

    void dumpSections();
    void dumpInstructions();
};