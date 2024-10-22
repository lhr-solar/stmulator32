#include "binary.hpp"
#include <cassert>

Binary::Binary(std::string path) {
    // Load file
    name = path;
    file = fopen(path.c_str(), "r");
    if (!file) {
        println("Couldn't open the file!");
        exit(-1);
    }
    int status;
    struct stat s;
    status = stat(path.c_str(), &s);
    size = s.st_size;

    // Memory map the file
    mapped_ptr = (uint8_t*)mmap(0, size, PROT_READ, MAP_SHARED, fileno(file), 0);
    if (!mapped_ptr) {
        println("Failed to mmap file");
        fclose(file);
        exit(-1);
    }

    // Load all the section headers
    loadSections();

    println("Section headers: %d", header->e_shnum);
    println("Program headers: %d", header->e_phnum);
    println("Mapped binary @ %p", mapped_ptr);
    println("Code pointer @ %p", code_ptr);
}

// Load all section and program headers from our ELF
void Binary::loadSections() {
    header = (Elf32_Ehdr*)mapped_ptr;
    code_ptr = nullptr;

    // Read program header ptrs
    Elf32_Phdr* start = (Elf32_Phdr*)(mapped_ptr + header->e_phoff);
    for (int i = 0; i < header->e_phnum; i++) {
        phdrs.push_back(&start[i]);
    }

    // Read section header ptrs
    Elf32_Shdr* start2 = (Elf32_Shdr*)(mapped_ptr + header->e_shoff);
    Elf32_Shdr *symtab_shdr = NULL;
    Elf32_Shdr *strtab_shdr = NULL;
    // Also identify symbol and string table locations
    for (int i = 0; i < header->e_shnum; i++) {
        shdrs.push_back(&start2[i]);
        if (start2[i].sh_type == SHT_SYMTAB)
            symtab_shdr = &start2[i];
        if (start2[i].sh_type == SHT_STRTAB)
            strtab_shdr = &start2[i];
    }

    // Populate string table
    if (strtab_shdr) {
        char* strtabb = (char*)(mapped_ptr + strtab_shdr->sh_offset);
        // Beautiful...
        for (int i = 0; i <= strtab_shdr->sh_size;) {
            strtab.push_back(std::string(strtabb));
            strtabb += strtab.back().size() + 1;
            i += strtab.back().size() + 1;
        }
        // Dump string table
        for (size_t i = 0; i < strtab.size(); i++) {
            println("strtab[%ld]: \'%s\'", i, strtab[i].c_str());
        }
    } else {
        println("No string table section found!");
    }

    // Grab index into strtab for ".text"
    uint32_t idx = 0;
    for (std::string& s : strtab) {
        if (s == ".text") break;
        else {
            idx += s.size() + 1;
        }
    }
    // Grab offset for .text
    for (Elf32_Shdr* p : shdrs) {
        if (p->sh_name == idx) {
            code_ptr = mapped_ptr + p->sh_offset;
            code_size = p->sh_size;
            break;
        }
    }

    // Populate symbol table
    if (symtab_shdr) {
        Elf32_Sym* ptr = (Elf32_Sym*)(mapped_ptr + symtab_shdr->sh_offset);
        size_t num_symbols = symtab_shdr->sh_size / sizeof(Elf32_Sym);
        for (size_t i = 0; i < num_symbols; i++) {
            symtab.push_back(&ptr[i]);
        }
    } else {
        println("No symbol table section found!");
    }

    assert(code_ptr);
}