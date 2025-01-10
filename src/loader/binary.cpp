#include "../utils.hpp"
#include "binary.hpp"
#include "../engine/instructions.hpp"

#include <vector>
#include <string>
#include <cassert>

// Constructor
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

    loadInstructions();
}

// Load all section and program headers from our ELF
void Binary::loadSections() {
    header = (Elf32_Ehdr*)mapped_ptr;
    this->code_ptr = nullptr;

    // We have our Elf header and index for where the shstrndx is.
    Elf32_Shdr section_string_table = ((Elf32_Shdr*)((mapped_ptr + header->e_shoff)))[header->e_shstrndx];
    // base + e_shoff is start of section header table
    // ^ at index e_shstrndx is the shstrtab SECTION (not data)
    shstrtab = new char[section_string_table.sh_size];
    memcpy(shstrtab, mapped_ptr + section_string_table.sh_offset, section_string_table.sh_size);
    
    // Populate our map
    Elf32_Shdr* ptr = (Elf32_Shdr*)(mapped_ptr + header->e_shoff);
    for (int i = 0; i < header->e_shnum; i++) {
        const char* s = shstrtab + ptr[i].sh_name;
        std::string name = std::string(s);
        section_map.emplace(name, &ptr[i]);
    }
    this->code_ptr = (mapped_ptr + section_map[".text"]->sh_offset);
    this->code_size = section_map[".text"]->sh_size;
    this->code_addr = section_map[".text"]->sh_addr;
}

bool Binary::loadInstructions(){
    csh handle;
    if (cs_open(CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB|CS_MODE_MCLASS), &handle) != CS_ERR_OK) return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    cs_insn* insn;
    size_t count = cs_disasm(handle, this->code_ptr, this->code_size, this->code_addr, 0, &insn);
    println("Disassembled %d instructions", count);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            println("0x%x: %s %s", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        println("Failed to disassemble");
    }
}

// Dump out brief section information
void Binary::dumpSections() {
    println("\n[NUM]\t[NAME]\t\t[SIZE]\t\t[OFFSET]\t\t[ADDRESS]");
    for (int i = 0; i < header->e_shnum; i++) {
        int nameIdx = ((Elf32_Shdr*)(mapped_ptr + header->e_shoff))[i].sh_name;
        std::string name = std::string((const char*)(shstrtab + nameIdx));
        Elf32_Shdr* ptr = section_map[name];
        println("[%d] - %-15s\tSIZE: 0x%-6x\tOFFSET: 0x%-6x\tADDR: 0x%x", i, name.c_str(), ptr->sh_size, ptr->sh_offset, ptr->sh_addr);
    }
}

void Binary::dumpInstructions() {
    // for () {
    //     println("0x%x: %s %s", i.insn->address, i.insn->mnemonic, i.insn->op_str);
    // }
}