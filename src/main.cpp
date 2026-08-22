#include <cstdint>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <android/log.h>
#include "patch.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "LimitlessGlint", __VA_ARGS__)

namespace Enchant {
    
    void (*old_Enchant)(void* self, uint8_t id, int rarity, void* src, size_t n, void* a6, size_t a7, int a8, void* srca, size_t na, int a11, int a12, int a13);
    
    void Enchant(void* self, uint8_t id, int rarity, void* src, size_t n, void* a6, size_t a7, int a8, void* srca, size_t na, int a11, int a12, int a13) {
        old_Enchant(self, id, rarity, src, n, a6, a7, a8, srca, na, a11, -1, -1);
    }

    bool isCompatibleWith(void* a1, uint8_t ID) {
        return true;
    }
}

namespace ItemEnchants {
    int64_t (*old_canEnchant)(int64_t a1, int a2, char a3);

    int64_t canEnchant(int64_t a1, int a2, char a3) {
        return 1;
    }
}

bool SetMemoryPermission(uintptr_t addr, size_t len, int prot) {
    if (!addr || !len) return false;
    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t aligned_addr = addr & ~(pagesize - 1);
    size_t aligned_len = ((addr + len + pagesize - 1) & ~(pagesize - 1)) - aligned_addr;
    return mprotect((void*)aligned_addr, aligned_len, prot) == 0;
}

inline bool Unprotect(uintptr_t addr, size_t len) {
    return SetMemoryPermission(addr, len, PROT_READ | PROT_WRITE);
}

inline bool Protect(uintptr_t addr, size_t len) {
    return SetMemoryPermission(addr, len, PROT_READ);
}

void** FindVtable(const char* typeStr) {
    static uintptr_t rodata{}, drr{}, libBase{};
    static size_t rodataSize{}, drrSize{};
    
    if (!rodata) {
        rodata = GetLibSection("libminecraftpe.so", ".rodata", &rodataSize);
        drr = GetLibSection("libminecraftpe.so", ".data.rel.ro", &drrSize);
        
        Dl_info info;
        if (dladdr((void*)rodata, &info)) {
            libBase = (uintptr_t)info.dli_fbase;
        }
    }
    
    char* ztsPtr= nullptr;
    size_t classLen = strlen(typeStr);
    size_t offset{};
    
    // Find String (_ZTS)
    while (offset < rodataSize) {
        char* match = (char*)memmem((void*)(rodata + offset), rodataSize - offset, typeStr, classLen + 1);
        if (!match) break;
        
        if (match == (char*)rodata || *(match - 1) == '\0') {
            ztsPtr = match;
            break;
        }
        offset = (uintptr_t)match - rodata + 1;
    }
    
    if (!ztsPtr) return nullptr;
    
    // Find TypeInfo (_ZTI)
    uintptr_t zts = (uintptr_t)ztsPtr;
    uintptr_t zti{};
    for (size_t i{}; i < drrSize; i += sizeof(uintptr_t)) {
        if (*(uintptr_t*)(drr + i) == zts) {
            zti = drr + i - sizeof(uintptr_t);
            break;
        }
    }
    
    if (!zti) return nullptr;
    
    // Find Vtable (_ZTV)
    uintptr_t vtable{};
    for (size_t i{}; i < drrSize; i += sizeof(uintptr_t)) {
        if (*(uintptr_t*)(drr + i) == zti) {
            uintptr_t potential_vtable = drr + i + sizeof(uintptr_t);
            
            if (i >= sizeof(uintptr_t) && *(uintptr_t*)(drr + i - sizeof(uintptr_t)) == 0) {
                vtable = potential_vtable;
                break; 
            }
            if (!vtable) {
                vtable = potential_vtable; 
            }
        }
    }
        
    if (!vtable) return nullptr;

    if (libBase)
        LOG("%s -> ZTS: 0x%lX | ZTI: 0x%lX | ZTV: 0x%lX", typeStr, zts - libBase, zti - libBase, vtable - libBase);
    else
        LOG("%s -> ZTS: .rodata+0x%zX | ZTI: .data.rel.ro+0x%zX | ZTV: .data.rel.ro+0x%zX", typeStr, (size_t)(zts - rodata), (size_t)(zti - drr), (size_t)(vtable - drr));
        
    return (void**)vtable;
}

namespace Function {
    uintptr_t FindReference(uintptr_t target) {
        size_t textSize{};
        uintptr_t text = GetLibSection("libminecraftpe.so", ".text", &textSize);
        for (uintptr_t p = text; p < text + textSize - 8; p += 4) {
            uint32_t adrp = *(uint32_t*)p;
            uint32_t add  = *(uint32_t*)(p + 4);
            if ((adrp & 0x9F000000) != 0x90000000) continue;
            if ((add & 0xFF000000) != 0x91000000) continue;
            int reg = adrp & 0x1F;
            if (((add >> 5) & 0x1F) != reg) continue;
            int64_t immhi = (adrp >> 5) & 0x7FFFF;
            int64_t immlo = (adrp >> 29) & 3;
            int64_t page  = ((immhi << 2) | immlo) << 12;
            uintptr_t pageAddr = (p & ~0xFFFULL) + page;
            int64_t off = (add >> 10) & 0xFFF;
            uintptr_t resolved = pageAddr + off;
            if (resolved == target) return p;
        }
        return 0;
    }

    uintptr_t FindSetterViaBackwalk(uintptr_t refAddr) {
        for (uintptr_t p = refAddr - 4; p > refAddr - 40; p -= 4) {
            uint32_t ins = *(uint32_t*)p;
            if ((ins & 0xFC000000) == 0x94000000) {
                return p;
            }
        }
        return 0;
    }
}

void* Redirect(void* target, void* hook, void** outOriginal) {
    LOG("Function entered. Target: %p, Hook: %p", target, hook);
    if (!target || !hook) return nullptr;

    uint32_t* target32 = (uint32_t*)target;
    auto IsPCRelative = [](uint32_t ins) -> bool {
        if ((ins & 0x9F000000) == 0x90000000) return true; // ADRP
        if ((ins & 0x9F000000) == 0x10000000) return true; // ADR
        if ((ins & 0x7C000000) == 0x14000000) return true; // B, BL
        if ((ins & 0xFF000000) == 0x54000000) return true; // B.cond
        if ((ins & 0x7E000000) == 0x34000000) return true; // CBZ, CBNZ
        if ((ins & 0x7E000000) == 0x36000000) return true; // TBZ, TBNZ
        if ((ins & 0x3B000000) == 0x18000000) return true; // LDR (literal)
        return false;
    };

    for (int i = 0; i < 4; i++) {
        if (IsPCRelative(target32[i])) {
            LOG("Function cannot be hooked: unsupported instruction.");
            return nullptr;
        }
    }

    void* trampoline = mmap(nullptr, 64, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (trampoline == MAP_FAILED) return nullptr;

    uint32_t* tramp32 = (uint32_t*)trampoline;

    tramp32[0] = target32[0];
    tramp32[1] = target32[1];
    tramp32[2] = target32[2];
    tramp32[3] = target32[3];

    tramp32[4] = 0x58000050; // ldr x16, #8
    tramp32[5] = 0xD61F0200; // br x16
    *(uint64_t*)(&tramp32[6]) = (uint64_t)target + 16;

    if (outOriginal) {
        *outOriginal = trampoline;
    }

    size_t pagesize = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)target & ~(pagesize - 1);
    mprotect((void*)page_start, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);

    target32[0] = 0x58000050; // ldr x16, #8
    target32[1] = 0xD61F0200; // br x16
    *(uint64_t*)(&target32[2]) = (uint64_t)hook;

    mprotect((void*)page_start, pagesize, PROT_READ | PROT_EXEC);

    __builtin___clear_cache((char*)trampoline, (char*)trampoline + 64);
    __builtin___clear_cache((char*)target, (char*)target + 16);

    LOG("Redirection Successful");
    return trampoline;
}

void HookCompatible() {
    size_t drrSize{};
    uintptr_t drr = GetLibSection("libminecraftpe.so", ".data.rel.ro", &drrSize);
    uintptr_t end = drr + drrSize;
    int replaced{};

    auto FindTarget = [](const char* typeStr, int idx, uintptr_t hook) -> uintptr_t {
        struct CacheNode {
            uintptr_t slotAddr;
            uintptr_t originalVal;
            CacheNode* next;
        };
        
        static CacheNode* cacheHead = nullptr;

        void** vt = FindVtable(typeStr);
        if (!vt) return 0;
        
        uintptr_t slotAddr = (uintptr_t)&vt[idx];
        uintptr_t currentVal = (uintptr_t)vt[idx];
        
        if (currentVal != hook) {
            CacheNode* newNode = (CacheNode*)malloc(sizeof(CacheNode));
            if (newNode) {
                newNode->slotAddr = slotAddr;
                newNode->originalVal = currentVal;
                newNode->next = cacheHead;
                cacheHead = newNode;
            }
            return currentVal;
        }
        
        CacheNode* curr = cacheHead;
        while (curr) {
            if (curr->slotAddr == slotAddr) {
                return curr->originalVal;
            }
            curr = curr->next;
        }
        
        return currentVal;
    };
    
    auto Redirect = [&](const char* typeStr, int idx, uintptr_t hook) {
        uintptr_t targetPtr = FindTarget(typeStr, idx, hook);
        
        if (!targetPtr || targetPtr == hook) {
            return;
        }
        if (!targetPtr) {
            LOG("%s not found", typeStr);
            return;
        }
        
        for (uintptr_t p = drr; p < end; p += sizeof(uintptr_t)) {
            uintptr_t* entry = (uintptr_t*)p;
            if (*entry == targetPtr) {
                Unprotect((uintptr_t)entry, sizeof(uintptr_t));
                *entry = hook;
                replaced++;
                Protect((uintptr_t)entry, sizeof(uintptr_t));
            }
        }
    };
    
    Redirect("14MendingEnchant", 2, (uintptr_t)Enchant::isCompatibleWith);
    Redirect("24TridentChannelingEnchant", 2, (uintptr_t)Enchant::isCompatibleWith);
    Redirect("21TridentRiptideEnchant", 2, (uintptr_t)Enchant::isCompatibleWith);
    Redirect("15CrossbowEnchant", 2, (uintptr_t)Enchant::isCompatibleWith);
    
    LOG("redirected %d vtable references", replaced);
}

__attribute__((constructor))
void init() {
    uintptr_t base = GetLibBase();
    void** vtable = FindVtable("17ProtectionEnchant"); // 1. Locate ProtectionEnchant vtable
    if (!vtable) return;
    
    uintptr_t ref = Function::FindReference((uintptr_t)vtable); // 2. Find where it is used in the text section
    if (!ref) return;
    
    uintptr_t setterAddr = Function::FindSetterViaBackwalk(ref); // 3. Walk back to find the nearest BL (the Enchant::Enchant function call)
    if (!setterAddr) return;
    
    LOG("BL found at offset: 0x%lx. Applying hook...", (long)(setterAddr - base));
    
    uint32_t blIns = *(uint32_t*)setterAddr;
    int32_t imm26 = (int32_t)(blIns << 6) >> 6;
    uintptr_t targetFunc = setterAddr + (imm26 * 4);
    
    Redirect((void*)targetFunc, (void*)Enchant::Enchant, (void**)&Enchant::old_Enchant);
    HookCompatible();
    
    Patch::Queue("3F 00 00 71 ?? ?? 9F 1A 08 01 02 2A ?? ?? 00 34 ?? ?? 00 37","20 00 80 52 C0 03 5F D6");
    Patch::Execute();
    
    LOG("Mod initialized successfully.");
}