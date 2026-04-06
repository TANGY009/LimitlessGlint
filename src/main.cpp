#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <android/log.h>
#include <dlfcn.h>
#include "Gloss.h"

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "LimitlessGlint", __VA_ARGS__)

uintptr_t GetLibBase() {
    size_t textSize{};
    uintptr_t text = GlossGetLibSection("libminecraftpe.so", ".text", &textSize);
    Dl_info info{};
    if (dladdr((void*)text, &info))
        return (uintptr_t)info.dli_fbase;
    return 0;
}

void (*old_Enchant_Setter)(void* self, unsigned char id, int rarity, void* src, size_t n, void* a6, size_t a7, int a8, void* srca, size_t na, int a11, int a12, int a13);

void hook_Enchant_Setter(void* self, unsigned char id, int rarity, void* src, size_t n, void* a6, size_t a7, int a8, void* srca, size_t na, int a11, int a12, int a13) {
    old_Enchant_Setter(self, id, rarity, src, n, a6, a7, a8, srca, na, a11, 0xFFFFFFFF, 0xFFFFFFFF);
}

bool Enchant_isCompatibleWith(void* a1, uint8_t ID) {
    return true;
}

void** FindVtable(const char* cls) {
    static uintptr_t rodata{}, drr{};
    static size_t rodataSize{}, drrSize{};
    if (!rodata) {
        rodata = GlossGetLibSection("libminecraftpe.so", ".rodata", &rodataSize);
        drr = GlossGetLibSection("libminecraftpe.so", ".data.rel.ro", &drrSize);
    }
    char* s = (char*)memmem((void*)rodata, rodataSize, cls, strlen(cls) + 1);
    if (!s) return nullptr;
    uintptr_t zts = (uintptr_t)s, zti{};
    for (size_t i = 0; i < drrSize; i += sizeof(uintptr_t))
        if (*(uintptr_t*)(drr + i) == zts) {
            zti = drr + i - sizeof(uintptr_t);
            break;
        }
    if (!zti) return nullptr;
    for (size_t i = 0; i < drrSize; i += sizeof(uintptr_t))
        if (*(uintptr_t*)(drr + i) == zti)
            return (void**)(drr + i + sizeof(uintptr_t));
    return nullptr;
}

uintptr_t FindReference(uintptr_t target) {
    size_t textSize{};
    uintptr_t text = GlossGetLibSection("libminecraftpe.so", ".text", &textSize);
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
            int32_t imm26 = (int32_t)(ins << 6) >> 6;
            return p + (imm26 * 4);
        }
    }
    return 0;
}

void HookCompatible() {
    size_t drrSize{};
    uintptr_t drr = GlossGetLibSection("libminecraftpe.so", ".data.rel.ro", &drrSize);
    uintptr_t end = drr + drrSize;
    int replaced{};
    auto Redirect = [&](const char* sym, std::initializer_list<int> idx, uintptr_t hook) {
        void** vt = FindVtable(sym);
        if (!vt) {
            LOG("%s not found", sym);
            return;
        }
        for (int i : idx) {
            uintptr_t func = (uintptr_t)vt[i];
            for (uintptr_t p = drr; p < end; p += sizeof(uintptr_t)) {
                uintptr_t* entry = (uintptr_t*)p;
                if (*entry == func) {
                    Unprotect((uintptr_t)entry, sizeof(uintptr_t));
                    *entry = hook;
                    replaced++;
                }
            }
        }
    };
    Redirect("14MendingEnchant", {2}, (uintptr_t)Enchant_isCompatibleWith);
    Redirect("24TridentChannelingEnchant", {2}, (uintptr_t)Enchant_isCompatibleWith);
    Redirect("21TridentRiptideEnchant", {2}, (uintptr_t)Enchant_isCompatibleWith);
    Redirect("15CrossbowEnchant", {2}, (uintptr_t)Enchant_isCompatibleWith);
    LOG("redirected %d vtable references", replaced);
}

__attribute__((constructor))
void init() {
    LOG("Starting dynamic search...");
    uintptr_t base = GetLibBase();
    void** vtable = FindVtable("17ProtectionEnchant"); // 1. Locate ProtectionEnchant vtable
    if (!vtable) {
        LOG("ProtectionEnchant vtable not found!");
        return;
    }
    uintptr_t ref = FindReference((uintptr_t)vtable); // 2. Find where it is used in the text section
    if (!ref) {
        LOG("Reference to ProtectionEnchant not found!");
        return;
    }
    uintptr_t setterAddr = FindSetterViaBackwalk(ref); // 3. Walk back to find the nearest BL (the setter function call)
    if (!setterAddr) {
        LOG("Could not find Setter call via backwalk.");
        return;
    }
    LOG("Setter found at offset: 0x%lx. Applying hook...", (long)(setterAddr - base));
    GlossHook((void*)setterAddr, (void*)hook_Enchant_Setter, (void**)&old_Enchant_Setter);
    HookCompatible();
    LOG("Mod initialized successfully.");
}