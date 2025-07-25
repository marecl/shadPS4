// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <iostream>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "gdb_command.h"
#include "stubtools.h"

typedef struct _breakpoint_sw_t {
    u16 kind{};
    u64 address{};
    std::vector<u8> original_data{};
} breakpoint_sw_t;

void BreakpointSetMainThread(ThreadID);
breakpoint_sw_t* BreakpointFind_SW(u64 addr);
breakpoint_sw_t* BreakpointAdd_SW(u16 kind, u64 addr, u16 length);
void BreakpointRemove_SW(u64 addr);
bool BreakpointEnable_SW(u64 addr);
bool BreakpointDisable_SW(u64 addr);

#endif // BREAKPOINT_H