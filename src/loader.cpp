#include "loader.hpp"

ElfLoader::ElfLoader() : header(nullptr), payload(nullptr), entry_point(nullptr), exports{0} {}

ElfLoader::ElfLoader(void* payloadFile) : ElfLoader() {
    payload = payloadFile;
}

ElfLoader::ElfLoader(void *payloadFile, const std::vector<ELFLoaderSymbol_t> &exportedThings) : ElfLoader() {
    payload = payloadFile;
    exports = exportedThings;
}

void ElfLoader::setPayload(void *payloadFile) {
    payload = payloadFile;
}

void* ElfLoader::getEntryPoint() const {
    return entry_point;
}

void ElfLoader::setExports(const std::vector<ELFLoaderSymbol_t> &exportedThings) {
    exports = exportedThings;
}

void ElfLoader::parse() {
    header = ((Elf32_Ehdr*) payload);
    if (memcmp(header->e_ident + 1, "ELF", 3) != 0) return;
    //Elf32_Shdr *shstrtab = ((Elf32_Shdr*) (payload + header->e_shoff) + header->e_shstrndx);
    for (uint32_t i = 1; i < header->e_shnum; ++i) {
        Elf32_Shdr *sectHdr = ((Elf32_Shdr*)(payload + header->e_shoff) + i);
        //const char* name = (const char*)(payload + sectHdr->sh_name + shstrtab->sh_offset);
        if (sectHdr->sh_flags & SHF_ALLOC) {
            if (sectHdr->sh_size) {
                void *data = nullptr;
                if (sectHdr->sh_flags & SHF_EXECINSTR) {
                    data = heap_caps_malloc(sectHdr->sh_size, MALLOC_CAP_EXEC | MALLOC_CAP_32BIT);
                    entry_point = (void*)(data + header->e_entry); 
                }
                else 
                    data = heap_caps_malloc(sectHdr->sh_size, MALLOC_CAP_8BIT);

                if (data == nullptr) {
                    elfLoaderFree();
                    return;
                }
                
                if (sectHdr->sh_type == SHT_NOBITS)
                    memset(data, 0, sectHdr->sh_size);
                else
                    unalignedCpy(data, payload + sectHdr->sh_offset, sectHdr->sh_size);
                
                sections_data.insert(std::pair<int32_t, void*>(i, data));
            }
        }   
    }
}

int16_t ElfLoader::relocate() {
    for (uint32_t i = 1; i < header->e_shnum; ++i) {
        Elf32_Shdr *section = ((Elf32_Shdr*) (payload + header->e_shoff) + i);
        Elf32_Shdr *symtab = ((Elf32_Shdr*) (payload + header->e_shoff) + section->sh_link);
        Elf32_Shdr *strtab = ((Elf32_Shdr*) (payload + header->e_shoff) + symtab->sh_link);

        void *data = sections_data.find(section->sh_info)->second;
        if (data == nullptr) continue;
        if (section->sh_entsize <= 0) continue;
        
        for (uint32_t index = 0; index < (section->sh_size / section->sh_entsize); index++) {
            Elf32_Rela *rel = ((Elf32_Rela*) (payload + section->sh_offset) + index);
            Elf32_Sym *sym = ((Elf32_Sym*) (payload + symtab->sh_offset) + ELF32_R_SYM(rel->r_info));
            const char* name = (const char*) (payload + sym->st_name + strtab->sh_offset);
            Elf32_Addr relAddr = ((Elf32_Addr) data) + rel->r_offset;
            Elf32_Addr symAddr = rel->r_addend;
            void* relSectionData = sections_data.find(sym->st_shndx)->second;

            if (relSectionData)
                symAddr += ((Elf32_Addr)relSectionData) + sym->st_value;
            else 
                for (auto &elfLoaderSymbol : exports) 
                    if (strcmp(elfLoaderSymbol.name, name) == 0) {
                        symAddr += (Elf32_Addr)(elfLoaderSymbol.ptr);
                        break;
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

void ElfLoader::elfLoaderFree() {
    for (auto it = sections_data.begin(); it != sections_data.end(); ++it)
        if (it->second)
            heap_caps_free(it->second);
    
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
            if (((v & 0xF) == 7) || ((v & 0x3F) == 26) ||  ((v & 0x3F) == 36 && (v & 0xFF) != 36)) {
                int32_t delta =  symAddr - (relAddr + 4);
                unalignedSet8((void*)(relAddr + 2), delta & 0xFF);
                if ((delta < -(1 << 7)) || (delta >= (1 << 7))) // Relocation: BRI8 out of range
                    return -1;

                break;
            }

            /* *** Format: BRI12 *** */
            /* *** BEQZ, BGEZ, BLTZ, BNEZ *** */
            if ((v & 0x3F) == 16) {
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

            break;
        }

        default:
            return -1;
    }
    return 0;
}


uint8_t ElfLoader::unalignedGet8(void* src) {
    /*
    asm volatile (
        "EXTUI a12, %[src], 0, 2" "\n"
        "XOR %[src], %[src], a12" "\n"
        "L32I.N %[src], %[src], 0" "\n"
        "SSA8L a12" "\n"
        "SRA a12, %[src]" "\n"
        "MOV %[src], a12" "\n"
        : [src] "=r"(src) ::
    );
    return (uint8_t) src;
    */
    return (*(uint32_t*)((uint32_t)src & 0xfffffffc) >> (((uint32_t)src & 0x3) * 8)) & 0xFF;
}

void ElfLoader::unalignedSet8(void* dest, uint8_t value) {
    *(uint32_t*)((uint32_t)dest & 0xfffffffc) = (*(uint32_t*)((uint32_t)dest & 0xfffffffc) & ~(0xFF << (((uint32_t)dest & 0x3) * 8))) | (value << (((uint32_t)dest & 0x3) * 8));
}

uint32_t ElfLoader::unalignedGet32(void* src) {
    uint32_t res = 0;
    asm volatile (
      "EXTUI %[res], %[src], 0, 2" "\n"
      "XOR %[src], %[src], %[res]" "\n"
      "L32I.N a12, %[src], 0" "\n" 
      "L32I.N %[src], %[src], 4" "\n"
      "SSA8L %[res]" "\n"
      "SRC %[res], %[src], a12" "\n" 
      : [res] "=r"(res), [src]"=r"(src) : "[src]" (src) :
    );
    return res;
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
    exports.clear();
    sections_data.clear();
    entry_point = nullptr;
    payload = nullptr;
    header = nullptr;
}
