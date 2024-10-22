#pragma once

#include "../common.hpp"
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

public:
    uint8_t* mapped_ptr; // mmap location of entire file
    uint8_t* code_ptr;
    uint32_t code_size;
    Elf32_Ehdr* header;
    
    Binary(std::string path);
    ~Binary() { fclose(file); munmap(mapped_ptr, size); delete[] shstrtab; }

    void dumpSections();
};