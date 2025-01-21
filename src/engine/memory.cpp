#include "memory.hpp"

bool MemoryModel::read(uint32_t addr, void *data, size_t size) {
    FILE *memfile = fopen("memfile", "r");
    fseek(memfile, addr, SEEK_SET);
    fread(data, size, 1, memfile);
    fclose(memfile);
    return true;
}

bool MemoryModel::write(uint32_t addr, void *data, size_t size) {
    FILE *memfile = fopen("memfile", "r+");
    fseek(memfile, addr, SEEK_SET);
    fwrite(data, size, 1, memfile);
    fclose(memfile);
    return true;
}

bool MemoryModel::load(Binary &binary) {
    // For each section, create a file and write the data to it
    for (auto it = binary.begin(); it != binary.end(); it++) {
        Elf32_Shdr *section = it->second;
        if (section->sh_type != SHT_PROGBITS || (section->sh_flags & SHF_ALLOC) == 0) continue;
        
        std::string file_path = "mem/" + it->first;
        FILE *section_file = fopen(file_path.c_str(), "w");
        printf("Writing section %s to file\n", it->first.c_str());
        fwrite(binary.mapped_ptr + section->sh_offset, section->sh_size, 1, section_file);
        fclose(section_file);
    }
    return true;
}