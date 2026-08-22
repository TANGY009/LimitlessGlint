#include "patch.h"

uintptr_t GetLibBase(const char* libname) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libname)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(fp);
    return base;
}

uintptr_t GetLibSection(const char* libname, const char* section_name, size_t* out_size) {
    if (!libname) return 0;
    if (!section_name) section_name = ".text";

    uintptr_t base_addr = 0;
    char lib_path[512] = {0};

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, libname)) {
            char path[512] = {0};
            if (sscanf(line, "%llx-%*x %*s %*x %*s %*d %511s", (unsigned long long*)&base_addr, path) >= 1) {
                if (path[0] == '/') {
                    strncpy(lib_path, path, sizeof(lib_path) - 1);
                    break;
                }
            }
        }
    }
    fclose(maps);

    if (lib_path[0] == '\0' || base_addr == 0) return 0;

    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 0;
    }

    void* map_base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map_base == MAP_FAILED) return 0;

    uintptr_t section_runtime_addr = 0;
    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)map_base;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && ehdr->e_shstrndx != SHN_UNDEF) {
        ElfW(Shdr)* shdr = (ElfW(Shdr)*)((uintptr_t)map_base + ehdr->e_shoff);
        
        if (ehdr->e_shstrndx < ehdr->e_shnum) {
            const char* shstrtab = (const char*)((uintptr_t)map_base + shdr[ehdr->e_shstrndx].sh_offset);

            for (int i = 0; i < ehdr->e_shnum; i++) {
                const char* current_section_name = shstrtab + shdr[i].sh_name;
                if (strcasecmp(current_section_name, section_name) == 0) {
                    section_runtime_addr = base_addr + shdr[i].sh_addr;
                    if (out_size) *out_size = shdr[i].sh_size;
                    break;
                }
            }
        }
    }

    munmap(map_base, st.st_size);
    return section_runtime_addr;
}

namespace Pattern {
    static int Hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        c |= 0x20;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    Signature Parse(const char* pattern) {
        Signature out{};
        out.size = 0;
        out.anchor_offset = 0;
        bool found_anchor = false;
        
        while (*pattern && out.size < MAX_PATTERN_BYTES) {
            // Skip leading spaces
            while (*pattern == ' ' || *pattern == '\t') pattern++;
            if (!*pattern) break;
            
            Byte p{};
            
            if (pattern[0] == '?' && pattern[1] == '?') {
                p.mask = 0x00;
                p.value = 0x00;
                pattern += 2;
            } 
            else if (pattern[0] == '?') {
                p.mask = 0x0F;
                int low = Hex(pattern[1]);
                p.value = (low != -1) ? (uint8_t)low : 0x00;
                pattern += 2;
            } 
            else if (pattern[1] == '?') {
                p.mask = 0xF0;
                int high = Hex(pattern[0]);
                p.value = (high != -1) ? (uint8_t)(high << 4) : 0x00;
                pattern += 2;
            } 
            else {
                int high = Hex(pattern[0]);
                int low = Hex(pattern[1]);
                
                if (high != -1 && low != -1) {
                    p.mask = 0xFF;
                    p.value = (uint8_t)((high << 4) | low);
                    pattern += 2;
                } else if (high != -1) { 
                    p.mask = 0xF0;
                    p.value = (uint8_t)(high << 4);
                    pattern += 1;
                } else {
                    pattern++;
                    continue;
                }
            }
            
            if (p.mask == 0xFF && !found_anchor) {
                out.anchor_offset = out.size;
                found_anchor = true;
            }

            out.bytes[out.size++] = p;
        }
        
        return out;
    }

    uintptr_t Find(const Signature& sig) {
        static thread_local uintptr_t text = 0;
        static thread_local size_t size = 0;
        static thread_local uintptr_t cursor = 0;

        if (!text) text = GetLibSection("libminecraftpe.so", ".text", &size);
        if (!text || !size || sig.size == 0) return 0;

        uintptr_t end = text + size;

        if (cursor < text || cursor >= end) {
            cursor = text;
        }

        const uint8_t* scan_start = (const uint8_t*)text;
        const size_t anchor = sig.anchor_offset;
        const uint8_t anchor_val = sig.bytes[anchor].value;

        auto MatchesAt = [&](const uint8_t* p) -> bool {
            for (size_t j = 0; j < sig.size; j++) {
                if ((p[j] & sig.bytes[j].mask) != (sig.bytes[j].value & sig.bytes[j].mask)) {
                    return false;
                }
            }
            return true;
        };

        auto ScanRangeNEON = [&](size_t start_offset, size_t end_offset) -> uintptr_t {
            if (start_offset >= end_offset || end_offset < sig.size) return 0;

            size_t scan_limit = end_offset - sig.size;
            size_t i = start_offset;

            i = (i + 3) & ~3;

            uint8x16_t target_vec = vdupq_n_u8(anchor_val);

            for (; i + 16 <= scan_limit; i += 16) {
                uint8x16_t data = vld1q_u8(&scan_start[i + anchor]);
                uint8x16_t cmp = vceqq_u8(data, target_vec);

                uint64x2_t mask64 = vreinterpretq_u64_u8(cmp);
                uint64_t low = vgetq_lane_u64(mask64, 0);
                uint64_t high = vgetq_lane_u64(mask64, 1);

                if (low || high) {
                    for (size_t lane = 0; lane < 16; lane += 4) {
                        size_t candidate = i + lane;
                        if (candidate <= scan_limit && scan_start[candidate + anchor] == anchor_val) {
                            if (MatchesAt(&scan_start[candidate])) {
                                cursor = (uintptr_t)&scan_start[candidate] + sig.size;
                                return (uintptr_t)&scan_start[candidate];
                            }
                        }
                    }
                }
            }

            for (; i <= scan_limit; i += 4) {
                if (scan_start[i + anchor] == anchor_val) {
                    if (MatchesAt(&scan_start[i])) {
                        cursor = (uintptr_t)&scan_start[i] + sig.size;
                        return (uintptr_t)&scan_start[i];
                    }
                }
            }

            return 0;
        };

        size_t cursor_offset = cursor - text;
        uintptr_t result = ScanRangeNEON(cursor_offset, size);
        if (result) return result;

        if (cursor_offset > 0) {
            result = ScanRangeNEON(0, cursor_offset);
            if (result) return result;
        }

        return 0;
    }
}

namespace Patch {
    struct Entry {
        const char* search;
        const char* replace;
    };

    static Entry queue[MAX_QUEUE_ENTRIES];
    static size_t count = 0;

    void Queue(const char* search, const char* replace) {
        if (count < MAX_QUEUE_ENTRIES) {
            queue[count++] = { search, replace };
        } else {
            LOG("Queue overflow: skipped patch %s", search);
        }
    }

    void Execute() {
        uintptr_t base = GetLibBase("libminecraftpe.so");
        size_t pagesize = sysconf(_SC_PAGESIZE);
        
        for (size_t i = 0; i < count; i++) {
            Pattern::Signature search = Pattern::Parse(queue[i].search);
            Pattern::Signature replace = Pattern::Parse(queue[i].replace);
    
            uintptr_t addr = Pattern::Find(search);
            if (!addr) continue;
    
            LOG("Found %s at 0x%lX", queue[i].search, (unsigned long)(addr - base));
    
            size_t max_bytes = (search.size > replace.size) ? search.size : replace.size;
            uintptr_t page = addr & ~(pagesize - 1);
            size_t len = ((addr + max_bytes + pagesize - 1) & ~(pagesize - 1)) - page;
    
            if (mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                LOG("Failed mprotect at 0x%lX", (unsigned long)(addr - base));
                continue;
            }
    
            for (size_t j = 0; j < replace.size; j++) {
                if (replace.bytes[j].mask != 0x00) {
                    if (replace.bytes[j].mask == 0xFF) {
                        ((uint8_t*)addr)[j] = replace.bytes[j].value;
                    } else {
                        uint8_t orig = ((uint8_t*)addr)[j];
                        uint8_t mask = replace.bytes[j].mask;
                        uint8_t val  = replace.bytes[j].value;
                        ((uint8_t*)addr)[j] = (orig & ~mask) | (val & mask);
                    }
                }
            }
    
            mprotect((void*)page, len, PROT_READ | PROT_EXEC);
            
            __builtin___clear_cache((char*)addr, (char*)(addr + max_bytes));
        }
    
        count = 0;
    }
}