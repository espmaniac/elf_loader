#pragma once
#include "elf.h"
#include "esp_heap_caps.h"
#include <stdint.h>
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
	ElfLoader(void*, const std::vector<ELFLoaderSymbol_t>&);
	void setPayload(void*);

	void *getEntryPoint(const char*);
	
	void setExports(const std::vector<ELFLoaderSymbol_t>&);
	int16_t parse();
	int16_t relocate();

	~ElfLoader();

	void* operator new(size_t, size_t);

	void operator delete(void*);

private:
	void elfLoaderFree();
	int16_t relocateSymbol(Elf32_Addr, int32_t, Elf32_Addr);

	uint8_t unalignedGet8(void*);
	void unalignedSet8(void*, uint8_t);
	uint32_t unalignedGet32(void*);
	void unalignedSet32(void*, uint32_t);
	void unalignedCpy(void*, void*, size_t);

	Elf32_Ehdr *header_m;
	Elf32_Shdr *symtab_m;

	// the code will not work without this alignment
	alignas(32) void *payload_m, *entry_point_m;

	std::vector<ELFLoaderSymbol_t> exports_m;
	
	std::map<int32_t, void*> sections_data_m;

};