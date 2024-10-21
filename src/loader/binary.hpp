#pragma once

#include "../common.hpp"
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

class Binary {

private:
    FILE* file; // file ptr
    Elf32_Ehdr* header;
    std::string name; // elf name
    uint8_t* mapped_ptr; // mmap location of entire file
    uint8_t* code_ptr;
    uint32_t code_size;
    uint32_t size; // filesize

    std::vector<Elf32_Shdr*> shdrs;
    std::vector<Elf32_Phdr*> phdrs;
    std::vector<Elf32_Sym*> symtab;
    std::vector<std::string> strtab;

    void loadSections();

public:
    Binary(std::string path);
    ~Binary() { fclose(file); munmap(mapped_ptr, size); }
};