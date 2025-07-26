// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDB_REGISTERS_H
#define GDB_REGISTERS_H

#include <sys/user.h>

#include "common/types.h"

// we need this to map user_regs_struct to GDB
// exact order **must** follow GDBs order
// either in gdb/features/i386/64bit-core OR
// see what's the order in `info reg` OR
// `maint print register-groups` with option `set architecture i386:x86-64`
// note: registers with width '0' in GDB are skipped
//

// register sizes in bytes
// Currently 207 registers for i386:x86_64, out of which 112 are
// not 0-length. One 0 is used for padding.

#define X84_64_REG_TOTAL 113
const u8 user_reg_size[X84_64_REG_TOTAL] = {
    // user_regs_struct (0-23)
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4,
    // user_fpregs_struct st_space (24-31)
    10, 10, 10, 10, 10, 10, 10, 10,
    // user_fpregs_struct control registers (32-39)
    4, 4, 4, 4, 4, 4, 4, 4,
    // user_fpregs_struct xmm0-xmm15, mxcsr (40-56)
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 4,
    // [padding] 57-151 are skipped, replaced by a single '0' width register at 57
    0,
    // user_regs_struct (58-61)
    8, 8, 8,
    // [unimplemented]
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};

#define X86_64_REG_BASE 0
#define X86_64_REG_COUNT 24
const u16 user_reg_offsets[X86_64_REG_COUNT] = {
    offsetof(struct user_regs_struct, rax), offsetof(struct user_regs_struct, rbx),
    offsetof(struct user_regs_struct, rcx), offsetof(struct user_regs_struct, rdx),
    offsetof(struct user_regs_struct, rsi), offsetof(struct user_regs_struct, rdi),
    offsetof(struct user_regs_struct, rbp), offsetof(struct user_regs_struct, rsp),
    offsetof(struct user_regs_struct, r8),  offsetof(struct user_regs_struct, r9),
    offsetof(struct user_regs_struct, r10), offsetof(struct user_regs_struct, r11),
    offsetof(struct user_regs_struct, r12), offsetof(struct user_regs_struct, r13),
    offsetof(struct user_regs_struct, r14), offsetof(struct user_regs_struct, r15),
    offsetof(struct user_regs_struct, rip), offsetof(struct user_regs_struct, eflags),
    offsetof(struct user_regs_struct, cs),  offsetof(struct user_regs_struct, ss),
    offsetof(struct user_regs_struct, ds),  offsetof(struct user_regs_struct, es),
    offsetof(struct user_regs_struct, fs),  offsetof(struct user_regs_struct, gs)};

#define X86_64_FPREG_BASE 24
#define X86_64_FPREG_COUNT 33
const u16 user_fpreg_offsets[X86_64_FPREG_COUNT] = {
    offsetof(struct user_fpregs_struct, st_space[0]),
    offsetof(struct user_fpregs_struct, st_space[4]),
    offsetof(struct user_fpregs_struct, st_space[8]),
    offsetof(struct user_fpregs_struct, st_space[12]),
    offsetof(struct user_fpregs_struct, st_space[16]),
    offsetof(struct user_fpregs_struct, st_space[20]),
    offsetof(struct user_fpregs_struct, st_space[24]),
    offsetof(struct user_fpregs_struct, st_space[28]),
    ///< stub
    offsetof(struct user_fpregs_struct, cwd), ///< fctrl (FCW)  not sure, makes sense
    offsetof(struct user_fpregs_struct, swd), ///< fstat (FSW)  not sure, makes sense
    offsetof(struct user_fpregs_struct, ftw), ///< ftag (FTW)   not sure, makes sense
    0,                                        ///< fiseg        ??? stub
    0,                                        ///< fioff        ??? stub
    0,                                        ///< foseg        ??? stub
    0,                                        ///< foff         ??? stub
    offsetof(struct user_fpregs_struct, fop), ///< fop          OK
    // ???? - i'm not sure if it's the right member, the size is correct though

    offsetof(struct user_fpregs_struct, xmm_space[0]),
    offsetof(struct user_fpregs_struct, xmm_space[4]),
    offsetof(struct user_fpregs_struct, xmm_space[8]),
    offsetof(struct user_fpregs_struct, xmm_space[12]),
    offsetof(struct user_fpregs_struct, xmm_space[16]),
    offsetof(struct user_fpregs_struct, xmm_space[20]),
    offsetof(struct user_fpregs_struct, xmm_space[24]),
    offsetof(struct user_fpregs_struct, xmm_space[28]),
    offsetof(struct user_fpregs_struct, xmm_space[32]),
    offsetof(struct user_fpregs_struct, xmm_space[36]),
    offsetof(struct user_fpregs_struct, xmm_space[40]),
    offsetof(struct user_fpregs_struct, xmm_space[44]),
    offsetof(struct user_fpregs_struct, xmm_space[48]),
    offsetof(struct user_fpregs_struct, xmm_space[52]),
    offsetof(struct user_fpregs_struct, xmm_space[56]),
    offsetof(struct user_fpregs_struct, xmm_space[60]),
    offsetof(struct user_fpregs_struct, mxcsr),
};

#define X86_64_REG_2_BASE 58
#define X86_64_REG_2_COUNT 3
const u16 user_reg_2_offsets[X86_64_REG_COUNT] = {offsetof(struct user_regs_struct, fs_base),
                                                  offsetof(struct user_regs_struct, gs_base),
                                                  offsetof(struct user_regs_struct, orig_rax)};

bool RegisterRead(u16 target_reg, u64* value, u16* size, const struct user_regs_struct* user_regs,
                  const struct user_fpregs_struct* user_fpregs) {

    if (target_reg > X84_64_REG_TOTAL) {
        *value = 0;
        *size = 0;
        return false;
    }

    u16 target_reg_size = user_reg_size[target_reg];
    const void* base{};
    u16 idx{};
    u16 offset{};

    *size = target_reg_size;

    if (target_reg >= X86_64_REG_BASE && target_reg < (X86_64_REG_BASE + X86_64_REG_COUNT)) {
        base = static_cast<const void*>(user_regs);
        idx = target_reg - X86_64_REG_BASE;
        offset = user_reg_offsets[idx];
    }

    if (target_reg >= X86_64_REG_2_BASE && target_reg < (X86_64_REG_2_BASE + X86_64_REG_2_COUNT)) {
        base = static_cast<const void*>(user_regs);
        idx = target_reg - X86_64_REG_2_BASE;
        offset = user_reg_2_offsets[idx];
    }

    if (target_reg >= X86_64_FPREG_BASE && target_reg < (X86_64_FPREG_BASE + X86_64_FPREG_COUNT)) {
        if (target_reg >= 35 && target_reg < 39) {
            // these are unavailable until I can find them in memory
            return false;
        }
        base = static_cast<const void*>(user_fpregs);
        idx = target_reg - X86_64_FPREG_BASE;
        offset = user_fpreg_offsets[idx];
    }

    if (base == nullptr) {
        // unlikely
        return false;
    }

    memcpy(value, static_cast<const u8*>(base) + offset, target_reg_size);
    return true;
}

#endif // GDB_REGISTERS_H