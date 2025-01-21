#pragma once

#include "instructions.hpp"
#include "architecture.hpp"

#include <vector>
#include <string>
#include <cstdint>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>

class MemoryModel;
class Binary {
private:
    FILE* file; // file ptr
    std::string name; // elf name
    uint32_t size; // filesize

    std::map<std::string, Elf32_Shdr*> section_map;
    char* shstrtab;

    void loadSections();
public:
    uint8_t* mapped_ptr; // mmap location of entire file
    Elf32_Ehdr* header;

    Binary(std::string path);
    ~Binary() { fclose(file); munmap(mapped_ptr, size); delete[] shstrtab; /*cs_free(instructions, instruction_count);*/}

    // iterator for sections
    std::map<std::string, Elf32_Shdr*>::iterator begin() { return section_map.begin(); }
    std::map<std::string, Elf32_Shdr*>::iterator end() { return section_map.end(); }

    void dumpSections();
};