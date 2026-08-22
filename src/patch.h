#pragma once

#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>
#include <strings.h>
#include <android/log.h>
#include <arm_neon.h>

#define MOD_NAME "AnvilUncapped"
#define MAX_PATTERN_BYTES 256
#define MAX_QUEUE_ENTRIES 64

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, MOD_NAME, __VA_ARGS__)

uintptr_t GetLibBase(const char* libname = "libminecraftpe.so");
uintptr_t GetLibSection(const char* libname, const char* section_name, size_t* out_size);

namespace Pattern {
    struct Byte {
        uint8_t value;
        uint8_t mask;
    };
    struct Signature {
        Byte bytes[MAX_PATTERN_BYTES];
        size_t size;
        size_t anchor_offset;
    };

    Signature Parse(const char* sig);
    uintptr_t Find(const Signature& sig);
}

namespace Patch {
    void Queue(const char* search, const char* replace);
    void Execute();
}