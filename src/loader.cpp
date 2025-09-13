#include "loader.hpp"

ElfLoader::ElfLoader() : header_m(nullptr), symtab_m(nullptr), payload_m(nullptr),
	entry_point_m(nullptr), exports_m{0} {}

ElfLoader::ElfLoader(void* payloadFile) : ElfLoader() {
	payload_m = payloadFile;
}

ElfLoader::ElfLoader(void *payloadFile, const std::vector<ELFLoaderSymbol_t> &exportedThings) : ElfLoader() {
	payload_m = payloadFile;
	exports_m = exportedThings;
}

void ElfLoader::setPayload(void *payloadFile) {
	payload_m = payloadFile;
}

void *ElfLoader::getEntryPoint(const char* entryName) {
	// If the file doesn't have an associated entry point, then this holds zero.
	if (header_m->e_entry == 0) {
		Elf32_Shdr *strtab = ((Elf32_Shdr*) ((uint32_t)payload_m + header_m->e_shoff) + symtab_m->sh_link);
		for (int32_t i = 0; i < (symtab_m->sh_size / symtab_m->sh_entsize); ++i) {
			Elf32_Sym *sym = ((Elf32_Sym*)((uint32_t)payload_m + symtab_m->sh_offset) + i);
					
			if (sym->st_name) {
				if (strcmp(entryName, (const char*)((uint32_t)payload_m + strtab->sh_offset + sym->st_name)) == 0)
					entry_point_m = (void*)((uint32_t)sections_data_m.find(sym->st_shndx)->second + sym->st_value);
			}
		}
	}

	return entry_point_m;
}

void ElfLoader::setExports(const std::vector<ELFLoaderSymbol_t> &exportedThings) {
	exports_m = exportedThings;
}

int16_t ElfLoader::parse() {
	header_m = ((Elf32_Ehdr*) payload_m);
	if (memcmp(header_m->e_ident + 1, "ELF", 3) != 0) return -1;
	Elf32_Shdr *shstrtab = ((Elf32_Shdr*) ((uint32_t)payload_m + header_m->e_shoff) + header_m->e_shstrndx);

	for (int32_t i = 1; i < header_m->e_shnum; ++i) {
		Elf32_Shdr *sectHdr = ((Elf32_Shdr*)((uint32_t)payload_m + header_m->e_shoff) + i);
		const char* name = (const char*)((uint32_t)payload_m + sectHdr->sh_name + shstrtab->sh_offset);

		if (sectHdr->sh_flags & SHF_ALLOC) {
			if (sectHdr->sh_size) {
				void *data = nullptr;
				if (sectHdr->sh_flags & SHF_EXECINSTR) {
					data = heap_caps_aligned_alloc(sectHdr->sh_addralign, sectHdr->sh_size,
						MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
					if (entry_point_m == nullptr)
						entry_point_m = (void*)((uint32_t)data + header_m->e_entry); 
				}
				else 
					data = heap_caps_aligned_alloc(sectHdr->sh_addralign, sectHdr->sh_size,
						MALLOC_CAP_8BIT);

				if (data == nullptr) {
					elfLoaderFree();
					return -1;
				}
				
				if (sectHdr->sh_type == SHT_NOBITS)
					memset(data, 0, sectHdr->sh_size);
				else
					unalignedCpy(data, (void*)((uint32_t)payload_m + sectHdr->sh_offset), sectHdr->sh_size);
				
				sections_data_m.insert(std::make_pair(i, data));
			}
		}   
		if (strcmp(name, ".symtab") == 0)
			symtab_m = sectHdr;
	}
	return 0;
}

int16_t ElfLoader::relocate() {
	for (int32_t i = 1; i < header_m->e_shnum; ++i) {
		Elf32_Shdr *section = ((Elf32_Shdr*) ((uint32_t)payload_m + header_m->e_shoff) + i);
		Elf32_Shdr *symtab = ((Elf32_Shdr*) ((uint32_t)payload_m + header_m->e_shoff) + section->sh_link);
		Elf32_Shdr *strtab = ((Elf32_Shdr*) ((uint32_t)payload_m + header_m->e_shoff) + symtab->sh_link);
		
		auto info = sections_data_m.find(section->sh_info);
		void *data = (info != sections_data_m.end()) ? info->second : nullptr;
		
		if ((data==nullptr) || (section->sh_entsize == 0) || (section->sh_size == 0))
			continue;
			
		for (int32_t index = 0; index < ((int32_t)section->sh_size / (int32_t)section->sh_entsize); ++index) {
			
			Elf32_Rela *rel = ((Elf32_Rela*) ((uint32_t)payload_m + section->sh_offset) + index);
			Elf32_Sym *sym = ((Elf32_Sym*) ((uint32_t)payload_m + symtab->sh_offset) + ELF32_R_SYM(rel->r_info));
			const char* name = (const char*) ((uint32_t)payload_m + sym->st_name + strtab->sh_offset);
			
			Elf32_Addr relAddr = ((Elf32_Addr) data) + rel->r_offset;
			Elf32_Addr symAddr = rel->r_addend;

			auto shndx = sections_data_m.find(sym->st_shndx);
			void* relSectionData = (shndx != sections_data_m.end()) ? shndx->second : nullptr;
			
			if (relSectionData) {
				symAddr += ((Elf32_Addr)relSectionData) + sym->st_value;  
			}
			else 
				for (auto &elfLoaderSymbol : exports_m) {
					if (strcmp(elfLoaderSymbol.name, name) == 0) {
						symAddr += (Elf32_Addr)(elfLoaderSymbol.ptr);
						break;
					}
				}
			
			if (!(ELF32_R_TYPE(rel->r_info) == R_XTENSA_NONE || ELF32_R_TYPE(rel->r_info) == R_XTENSA_ASM_EXPAND)) {
				if (symAddr == rel->r_addend && sym->st_value != 0)
					symAddr = sym->st_value;
				
				else if (symAddr == rel->r_addend && sym->st_value == 0) {
					elfLoaderFree();
					return -1;
				}

				if (relocateSymbol(relAddr, ELF32_R_TYPE(rel->r_info), symAddr) != 0) {
					elfLoaderFree();
					return -1;
				}
			}
		}
	}
	
	return 0;
}

void* ElfLoader::operator new(size_t sz, size_t al) {
	return heap_caps_aligned_alloc(al, sz, MALLOC_CAP_8BIT);
}

void ElfLoader::operator delete(void *ptr) {
	//heap_caps_aligned_free(ptr); // This function is deprecated
	heap_caps_free(ptr);
}

void ElfLoader::elfLoaderFree() {
	for (auto it = sections_data_m.begin(); it != sections_data_m.end(); ++it)
		if (it->second) {
			heap_caps_free(it->second);
			it->second = nullptr;
		}
	
	sections_data_m.clear();
	exports_m.clear();
	entry_point_m = nullptr;
	payload_m = nullptr;
	header_m = nullptr;
	symtab_m = nullptr;
}

int16_t ElfLoader::relocateSymbol(Elf32_Addr relAddr, int32_t type, Elf32_Addr symAddr) {
	switch (type) {
		case R_XTENSA_32: {
			unalignedSet32((void*)relAddr, symAddr + unalignedGet32((void*)relAddr));
			break;
		}
		case R_XTENSA_SLOT0_OP: {
			uint32_t v = unalignedGet32((void*)relAddr);

			/* *** Format: L32R *** */
			if ((v & 0xF) == 1) {
				int32_t delta =  symAddr - ((relAddr + 3) & ~3);
				if (delta & 3) return -1;

				delta = delta >> 2;
				unalignedSet8((void*)(relAddr + 1), delta & 0xFF);
				unalignedSet8((void*)(relAddr + 2), (delta >> 8) & 0xFF);
				break;
			}

			/* *** Format: CALL *** */
			/* *** CALL0, CALL4, CALL8, CALL12, J *** */
			if ((v & 0xF) == 5) {
				int32_t delta =  symAddr - ((relAddr + 4) & ~3);
				if (delta & 3) return -1;

				delta = (delta >> 2) << 6;
				delta |= unalignedGet8((void*)(relAddr));
				unalignedSet8((void*)(relAddr), delta & 0xFF);
				unalignedSet8((void*)(relAddr + 1), (delta >> 8) & 0xFF);
				unalignedSet8((void*)(relAddr + 2), (delta >> 16) & 0xFF);
				break;
			}

			/* *** J *** */
			if ((v & 0x3F) == 6) {
				int32_t delta =  (symAddr - (relAddr + 4)) << 6;
				delta |= unalignedGet8((void*)(relAddr));
				unalignedSet8((void*)(relAddr), delta & 0xFF);
				unalignedSet8((void*)(relAddr + 1), (delta >> 8) & 0xFF);
				unalignedSet8((void*)(relAddr + 2), (delta >> 16) & 0xFF);
				break;
			}

			/* *** Format: BRI8  *** */
			/* *** BALL, BANY, BBC, BBCI, BBCI.L, BBS,  BBSI, BBSI.L, BEQ, BGE,  BGEU, BLT, BLTU, BNALL, BNE,  BNONE, LOOP,  *** */
			/* *** BEQI, BF, BGEI, BGEUI, BLTI, BLTUI, BNEI,  BT, LOOPGTZ, LOOPNEZ *** */
			if (((v & 0xF) == 7) || ((v & 0x3F) == 0x26) ||  ((v & 0x3F) == 0x36 && (v & 0xFF) != 0x36)) {
				int32_t delta =  symAddr - (relAddr + 4);
				unalignedSet8((void*)(relAddr + 2), delta & 0xFF);
				if ((delta < -(1 << 7)) || (delta >= (1 << 7))) { // Relocation: BRI8 out of range
					return -1;
				}
				break;
			}

			/* *** Format: BRI12 *** */
			/* *** BEQZ, BGEZ, BLTZ, BNEZ *** */
			if ((v & 0x3F) == 0x16) {
				int32_t delta =  (symAddr - (relAddr + 4)) << 4;
				delta |= unalignedGet32((void*)(relAddr + 1));
				unalignedSet8((void*)(relAddr + 1), delta & 0xFF);
				unalignedSet8((void*)(relAddr + 2), (delta >> 8) & 0xFF);
				delta =  symAddr - (relAddr + 4);
				if ((delta < - (1 << 11)) || (delta >= (1 << 11))) //Relocation: BRI12 out of range
					return -1;
				break;
			}

			/* *** Format: RI6  *** */
			/* *** BEQZ.N, BNEZ.N *** */
			if ((v & 0x8F) == 0x8C) {
				int32_t delta =  symAddr - (relAddr + 4);
				int32_t d2 = delta & 0x30;
				int32_t d1 = (delta << 4) & 0xf0;
				d2 |= unalignedGet32((void*)(relAddr));
				d1 |= unalignedGet32((void*)(relAddr + 1));
				unalignedSet8((void*)(relAddr), d2 & 0xFF);
				unalignedSet8((void*)(relAddr + 1), d1 & 0xFF);
				if ((delta < 0) || (delta > 0x111111)) //Relocation: RI6 out of range
					return -1;

				break;
			}

			return -1;
			//break;
		}

		default:
			return -1;
	}
	return 0;
}

uint8_t ElfLoader::unalignedGet8(void* src) {
    uint32_t w = *(uint32_t*)((uintptr_t)src & ~3);
    return (w >> (((uintptr_t)src & 3) * 8)) & 0xFF;
}

void ElfLoader::unalignedSet8(void* dest, uint8_t v) {
    uint32_t* wptr = (uint32_t*)((uintptr_t)dest & ~3);
    uint32_t shift = ((uintptr_t)dest & 3) * 8;
    *wptr = (*wptr & ~(0xFFu << shift)) | ((uint32_t)v << shift);
}

uint32_t ElfLoader::unalignedGet32(void* src) {
    uint32_t val;
    memcpy(&val, src, sizeof(val));
    return val;
}

void ElfLoader::unalignedSet32(void* dest, uint32_t value) {
	for(int8_t i = 0; i < 4; i++, value >>= 8, ((int8_t*&)dest)++)
		unalignedSet8(dest, value & 0xFF);
}

void ElfLoader::unalignedCpy(void* dest, void* src, size_t n) {
	for(; n > 0; n--, ((int8_t*&)dest)++, ((int8_t*&)src)++)
		unalignedSet8(dest, unalignedGet8(src));
}


ElfLoader::~ElfLoader() {
	elfLoaderFree();
}