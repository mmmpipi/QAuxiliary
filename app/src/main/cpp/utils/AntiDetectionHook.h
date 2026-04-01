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
// Anti-detection inline hook infrastructure
// Provides stealth alternatives to Dobby inline hooks
//

#ifndef QAUXV_ANTI_DETECTION_HOOK_H
#define QAUXV_ANTI_DETECTION_HOOK_H

#include <cstdint>
#include <cstddef>
#include <sys/types.h>


namespace qauxv::antidetect {

// ============================================================
// Anti-detection hook strategies
// ============================================================

// Strategy 1: Instruction substitution
// Instead of writing a branch instruction at function entry,
// modify critical instructions inside the function body to
// change behavior without introducing external jumps.
//
// Example: Replace `cbz x0, #skip` with `mov x0, #0` to force
// a code path, or replace a key instruction with `nop`.
//
// Pros: No branch instructions, no trampoline needed
// Cons: Requires precise analysis of target function

// Strategy 2: .text padding trampoline
// Instead of mmap'ing anonymous executable memory for trampolines,
// find NOP padding areas in the target .text segment and write
// trampoline code there.
//
// Pros: No new executable mappings in /proc/self/maps
// Cons: Requires sufficient NOP padding in .text segment

// Strategy 3: Syscall-based mprotect
// Use syscall(SYS_mprotect, ...) directly to bypass libc-level
// mprotect hooks that QQ may install.
//
// Pros: Bypasses user-space mprotect monitoring
// Cons: Still modifies .text permissions (detectable via other means)

// ============================================================
// Data structures
// ============================================================

struct AntiDetectHookContext {
    // Original function address
    void* targetAddr;
    // Hook function address
    void* hookAddr;
    // Backup of original instructions (for trampoline)
    uint8_t originalBytes[32];
    size_t originalBytesLen;
    // Trampoline address (if used)
    void* trampolineAddr;
    // Strategy used
    int strategy; // 0 = instruction substitution, 1 = .text padding, 2 = syscall mprotect + Dobby
    // Module base address (for .text padding search)
    void* moduleBase;
    size_t moduleSize;
};

// ============================================================
// Core API
// ============================================================

// Initialize anti-detection hook system for a given module
// moduleBase: base address of the target .so (e.g., libkernel.so)
// moduleSize: size of the module in memory
// Returns 0 on success, negative error code on failure
int InitAntiDetectHook(void* moduleBase, size_t moduleSize);

// Find NOP padding area in .text segment
// Returns address of first suitable NOP sequence, or nullptr if not found
// minSize: minimum consecutive NOP bytes required (typically 16-32)
void* FindTextPadding(void* moduleBase, size_t moduleSize, size_t minSize);

// Perform instruction substitution hook
// Instead of branching to hookFunc, modify critical instructions
// at targetAddr to change behavior.
//
// This is the MOST stealthy approach but requires knowing exactly
// which instructions to modify. The caller must provide:
// - offsetToPatch: byte offset from targetAddr to the instruction to patch
// - patchBytes: the replacement instruction bytes
// - patchLen: length of patchBytes
//
// Returns 0 on success, negative error code on failure
int InstructionSubstitutionHook(
        void* targetAddr,
        size_t offsetToPatch,
        const uint8_t* patchBytes,
        size_t patchLen
);

// Perform .text padding trampoline hook
// Writes trampoline code into NOP padding area instead of anonymous memory
//
// Returns 0 on success, negative error code on failure
int TextPaddingTrampolineHook(AntiDetectHookContext* ctx);

// Syscall-based mprotect (bypasses libc hook)
// Returns 0 on success, -1 on failure (errno preserved)
int SyscallMprotect(void* addr, size_t len, int prot);

// ============================================================
// Utility functions
// ============================================================

// Check if a memory region contains only NOP instructions
// ARM64 NOP = 0xD503201F
bool IsNopRegion(const void* addr, size_t len);

// Find consecutive NOP sequence in memory
// Returns offset from base, or -1 if not found
long FindNopSequence(const void* base, size_t size, size_t minLen);

// Encode ARM64 NOP instruction
inline uint32_t EncodeNop() { return 0xD503201F; }

// Encode ARM64 B (branch) instruction
// offset: byte offset from current PC (must be multiple of 4, range +/-128MB)
inline uint32_t EncodeBranch(int32_t offset) {
    return 0x14000000u | ((offset >> 2) & 0x03FFFFFFu);
}

// Encode ARM64 BL (branch with link) instruction
inline uint32_t EncodeBranchLink(int32_t offset) {
    return 0x94000000u | ((offset >> 2) & 0x03FFFFFFu);
}

// Encode ARM64 RET instruction
inline uint32_t EncodeRet() { return 0xD65F03C0; }

// Encode ARM64 MOV x0, #0 instruction
inline uint32_t EncodeMovX0Zero() { return 0xD2800000; }

// Encode ARM64 NOP instruction
inline uint32_t EncodeNop32() { return 0xD503201F; }

} // namespace qauxv::antidetect


#endif // QAUXV_ANTI_DETECTION_HOOK_H
