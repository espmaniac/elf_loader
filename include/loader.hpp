#pragma once
#include "elf.h"
#include "esp_heap_caps.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <map>
#include <utility>
#include <vector>



struct ELFLoaderSymbol_t {
    const char *name;
    void *ptr;
};

class ElfLoader {
public:
    ElfLoader();
    ElfLoader(void*);
    ElfLoader(void*, std::vector<ELFLoaderSymbol_t>);
    void setPayload(void*);
    void setExports(std::vector<ELFLoaderSymbol_t>);
    void parse();
    int16_t relocate();
    void elfLoaderFree();

    ~ElfLoader();
private:
    int16_t relocateSymbol(Elf32_Addr relAddr, int32_t type, Elf32_Addr symAddr);

    uint8_t unalignedGet8(void*);
    void unalignedSet8(void*, uint8_t);
    uint32_t unalignedGet32(void*);
    void unalignedSet32(void*, uint32_t);
    void unalignedCpy(void*, void*, size_t);

    Elf32_Ehdr *header;
    void *payload; // elf file data
    void *entry_point;
    std::vector<ELFLoaderSymbol_t> exports;
    std::map<int32_t, void*> sections_data;
};