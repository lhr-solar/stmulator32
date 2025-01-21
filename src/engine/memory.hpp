#pragma once

#include <sys/stat.h>
#include "binary.hpp"

class Binary;

class MemoryModel {
public:
    MemoryModel(){
        // Create empty memory directory
        mkdir("mem", 0777);
    }

    MemoryModel(Binary &binary) : MemoryModel() {
        load(binary);
    }

    bool read(uint32_t addr, void *data, size_t size);
    bool write(uint32_t addr, void *data, size_t size);
    bool load(Binary &binary);
};
