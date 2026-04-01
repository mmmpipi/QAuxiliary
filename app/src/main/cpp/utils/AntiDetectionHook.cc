// QAuxiliary - An Xposed module for QQ/TIM
// Copyright (C) 2019-2023 QAuxiliary developers
// https://github.com/cinit/QAuxiliary
//
// This software is non-free but opensource software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License
// as published by the Free Software Foundation; either
// version 3 of the License, or any later version and our eula as published
// by QAuxiliary contributors.
//
// This software is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// and eula along with this software.  If not, see
// <https://www.gnu.org/licenses/>
// <https://github.com/cinit/QAuxiliary/blob/master/LICENSE.md>.

//
// Anti-detection inline hook implementation
//

#include "AntiDetectionHook.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

#include "utils/Log.h"

namespace qauxv::antidetect {

// ============================================================
// Global state
// ============================================================

static void* sModuleBase = nullptr;
static size_t sModuleSize = 0;
static void* sTextPaddingAddr = nullptr;
static size_t sTextPaddingSize = 0;

// ============================================================
// Syscall-based mprotect (bypasses libc hook)
// ============================================================

int SyscallMprotect(void* addr, size_t len, int prot) {
    // Use syscall directly to bypass any libc-level mprotect hooks
    // that QQ's security module may have installed
    long ret = syscall(SYS_mprotect, addr, len, prot);
    if (ret != 0) {
        LOGE("SyscallMprotect failed: addr={:p}, len={}, prot={}, errno={}",
             addr, len, prot, errno);
        return -1;
    }
    return 0;
}

// ============================================================
// NOP region detection
// ============================================================

bool IsNopRegion(const void* addr, size_t len) {
    if (addr == nullptr || len == 0 || (len % 4) != 0) {
        return false;
    }
    const uint32_t* p = static_cast<const uint32_t*>(addr);
    size_t count = len / 4;
    for (size_t i = 0; i < count; i++) {
        if (p[i] != 0xD503201Fu) { // ARM64 NOP
            return false;
        }
    }
    return true;
}

long FindNopSequence(const void* base, size_t size, size_t minLen) {
    if (base == nullptr || size == 0 || minLen == 0 || (minLen % 4) != 0) {
        return -1;
    }

    const uint8_t* p = static_cast<const uint8_t*>(base);
    size_t consecutiveNops = 0;

    for (size_t i = 0; i < size - 3; i += 4) {
        uint32_t inst = *reinterpret_cast<const uint32_t*>(p + i);
        if (inst == 0xD503201Fu) { // ARM64 NOP
            consecutiveNops += 4;
            if (consecutiveNops >= minLen) {
                // Found sufficient NOP padding
                return static_cast<long>(i - consecutiveNops + 4);
            }
        } else {
            consecutiveNops = 0;
        }
    }
    return -1;
}

// ============================================================
// .text padding finder
// ============================================================

void* FindTextPadding(void* moduleBase, size_t moduleSize, size_t minSize) {
    if (moduleBase == nullptr || moduleSize == 0) {
        return nullptr;
    }

    // Scan .text segment for NOP padding
    // The .text segment typically starts at module base
    // We look for 0xD503201F (ARM64 NOP) sequences

    // Strategy: scan in 4KB pages, skip known executable regions
    // Focus on alignment padding areas (typically at end of functions)

    const uint8_t* base = static_cast<const uint8_t*>(moduleBase);
    size_t scanned = 0;
    size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));

    while (scanned < moduleSize) {
        // Scan one page at a time
        size_t pageScanSize = std::min(pageSize, moduleSize - scanned);
        long offset = FindNopSequence(base + scanned, pageScanSize, minSize);
        if (offset >= 0) {
            void* result = const_cast<uint8_t*>(base + scanned + static_cast<size_t>(offset));
            LOGD("FindTextPadding: found {} bytes at offset 0x{:x}", minSize, scanned + offset);
            return result;
        }
        scanned += pageScanSize;
    }

    LOGW("FindTextPadding: no suitable NOP padding found in module");
    return nullptr;
}

// ============================================================
// Instruction substitution hook
// ============================================================

int InstructionSubstitutionHook(
        void* targetAddr,
        size_t offsetToPatch,
        const uint8_t* patchBytes,
        size_t patchLen
) {
    if (targetAddr == nullptr || patchBytes == nullptr || patchLen == 0 || (patchLen % 4) != 0) {
        LOGE("InstructionSubstitutionHook: invalid parameters");
        return -1;
    }

    uint8_t* patchAddr = static_cast<uint8_t*>(targetAddr) + offsetToPatch;

    // Save original bytes for potential unhook
    uint8_t originalBytes[32];
    if (patchLen > sizeof(originalBytes)) {
        LOGE("InstructionSubstitutionHook: patch too large");
        return -1;
    }
    std::memcpy(originalBytes, patchAddr, patchLen);

    // Use syscall mprotect to bypass libc hooks
    size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t pageStart = reinterpret_cast<uintptr_t>(patchAddr) & ~(pageSize - 1);
    size_t pageLen = pageSize;

    // Change to rwx
    if (SyscallMprotect(reinterpret_cast<void*>(pageStart), pageLen,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("InstructionSubstitutionHook: mprotect(rwx) failed");
        return -1;
    }

    // Write patch instructions
    std::memcpy(patchAddr, patchBytes, patchLen);

    // __builtin___clear_cache for ARM64 instruction cache
    __builtin___clear_cache(
            reinterpret_cast<char*>(patchAddr),
            reinterpret_cast<char*>(patchAddr + patchLen)
    );

    // Restore to r-x
    if (SyscallMprotect(reinterpret_cast<void*>(pageStart), pageLen,
                        PROT_READ | PROT_EXEC) != 0) {
        LOGW("InstructionSubstitutionHook: mprotect(r-x) failed, but patch was applied");
    }

    LOGD("InstructionSubstitutionHook: patched {} bytes at {:p}", patchLen, static_cast<void*>(patchAddr));
    return 0;
}

// ============================================================
// .text padding trampoline hook
// ============================================================

int TextPaddingTrampolineHook(AntiDetectHookContext* ctx) {
    if (ctx == nullptr || ctx->targetAddr == nullptr || ctx->hookAddr == nullptr) {
        LOGE("TextPaddingTrampolineHook: invalid context");
        return -1;
    }

    // Step 1: Find or reuse NOP padding area
    if (sTextPaddingAddr == nullptr || sTextPaddingSize < 64) {
        sTextPaddingAddr = FindTextPadding(sModuleBase, sModuleSize, 128);
        if (sTextPaddingAddr == nullptr) {
            LOGE("TextPaddingTrampolineHook: no text padding available");
            return -1;
        }
        sTextPaddingSize = 128;
    }

    // Step 2: Build trampoline in padding area
    // Trampoline structure:
    //   [original instructions that were overwritten] (12-16 bytes)
    //   [branch back to original function + offset]   (4 bytes)
    //
    // For ARM64, we need to handle the branch carefully.
    // The trampoline will:
    //   1. Execute the original instructions that we're about to overwrite
    //   2. Branch to the remaining part of the original function

    uint8_t* trampoline = static_cast<uint8_t*>(sTextPaddingAddr);
    size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uintptr_t pageStart = reinterpret_cast<uintptr_t>(trampoline) & ~(pageSize - 1);

    // Make padding area writable
    if (SyscallMprotect(reinterpret_cast<void*>(pageStart), pageSize,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("TextPaddingTrampolineHook: mprotect for trampoline failed");
        return -1;
    }

    // Step 3: Save original instructions (first 16 bytes = 4 instructions)
    constexpr size_t kOverwriteSize = 16; // 4 ARM64 instructions
    std::memcpy(ctx->originalBytes, ctx->targetAddr, kOverwriteSize);
    ctx->originalBytesLen = kOverwriteSize;

    // Copy original instructions to trampoline
    std::memcpy(trampoline, ctx->targetAddr, kOverwriteSize);

    // Add branch back to original function + kOverwriteSize
    uintptr_t targetAfterOverwrite = reinterpret_cast<uintptr_t>(ctx->targetAddr) + kOverwriteSize;
    uintptr_t branchFromAddr = reinterpret_cast<uintptr_t>(trampoline) + kOverwriteSize;
    int32_t branchOffset = static_cast<int32_t>(targetAfterOverwrite - branchFromAddr);

    // Check branch range (+/-128MB)
    if (branchOffset < -0x08000000 || branchOffset > 0x07FFFFFF) {
        LOGE("TextPaddingTrampolineHook: branch offset out of range: 0x{:x}", branchOffset);
        return -1;
    }

    uint32_t branchInst = EncodeBranch(branchOffset);
    *reinterpret_cast<uint32_t*>(trampoline + kOverwriteSize) = branchInst;

    ctx->trampolineAddr = trampoline;

    // Step 4: Write branch to hook function at target
    uintptr_t targetAddr = reinterpret_cast<uintptr_t>(ctx->targetAddr);
    uintptr_t hookAddr = reinterpret_cast<uintptr_t>(ctx->hookAddr);
    int32_t hookOffset = static_cast<int32_t>(hookAddr - targetAddr);

    if (hookOffset < -0x08000000 || hookOffset > 0x07FFFFFF) {
        LOGE("TextPaddingTrampolineHook: hook branch offset out of range: 0x{:x}", hookOffset);
        return -1;
    }

    uintptr_t targetPageStart = targetAddr & ~(pageSize - 1);
    if (SyscallMprotect(reinterpret_cast<void*>(targetPageStart), pageSize,
                        PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("TextPaddingTrampolineHook: mprotect for target failed");
        return -1;
    }

    uint32_t hookBranch = EncodeBranch(hookOffset);
    *reinterpret_cast<uint32_t*>(ctx->targetAddr) = hookBranch;

    // Clear instruction cache
    __builtin___clear_cache(
            reinterpret_cast<char*>(ctx->targetAddr),
            reinterpret_cast<char*>(ctx->targetAddr) + kOverwriteSize
    );
    __builtin___clear_cache(
            reinterpret_cast<char*>(trampoline),
            reinterpret_cast<char*>(trampoline) + kOverwriteSize + 4
    );

    // Restore target page to r-x
    SyscallMprotect(reinterpret_cast<void*>(targetPageStart), pageSize,
                    PROT_READ | PROT_EXEC);

    // Advance padding pointer for next hook
    sTextPaddingAddr = static_cast<uint8_t*>(sTextPaddingAddr) + kOverwriteSize + 4;
    sTextPaddingSize -= (kOverwriteSize + 4);

    ctx->strategy = 1; // .text padding trampoline

    LOGD("TextPaddingTrampolineHook: success, trampoline at {:p}", ctx->trampolineAddr);
    return 0;
}

// ============================================================
// Initialization
// ============================================================

int InitAntiDetectHook(void* moduleBase, size_t moduleSize) {
    if (moduleBase == nullptr || moduleSize == 0) {
        LOGE("InitAntiDetectHook: invalid module");
        return -1;
    }

    sModuleBase = moduleBase;
    sModuleSize = moduleSize;

    // Pre-scan for NOP padding
    sTextPaddingAddr = FindTextPadding(moduleBase, moduleSize, 256);
    if (sTextPaddingAddr != nullptr) {
        sTextPaddingSize = 256;
        LOGD("InitAntiDetectHook: found text padding at {:p}, size={}",
             sTextPaddingAddr, sTextPaddingSize);
    } else {
        LOGW("InitAntiDetectHook: no text padding found, falling back to other strategies");
    }

    return 0;
}

} // namespace qauxv::antidetect

