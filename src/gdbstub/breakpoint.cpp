// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>

#include "common/logging/log.h"
#include "common/types.h"

#include "breakpoint.h"
#include "threadinfo.h"

static std::unordered_map<u64, breakpoint_sw_t> breakpoint_sw_list{};
static ThreadID main_thread{};

void BreakpointSetMainThread(ThreadID thread) {
    main_thread = thread;
}

breakpoint_sw_t* BreakpointFind_SW(u64 addr) {
    auto target_found = breakpoint_sw_list.find(addr);
    return target_found == breakpoint_sw_list.end() ? nullptr : &target_found->second;
}

breakpoint_sw_t* BreakpointAdd_SW(u16 kind, u64 addr, u16 length) {
    if (breakpoint_sw_t* found = BreakpointFind_SW(addr); found != nullptr)
        return found;

    std::vector<u8> original_data{};
    if (!ReadMemory(main_thread, addr, length, original_data))
        return nullptr;

    breakpoint_sw_t new_breakpoint{.kind = kind, .address = addr, .original_data = original_data};

    breakpoint_sw_list[addr] = new_breakpoint;
    return &breakpoint_sw_list[addr];
}

void BreakpointRemove_SW(u64 addr) {
    breakpoint_sw_list.erase(addr);
}

u8 compareData(u64 address, std::vector<u8> what_was_written) {
    std::vector<u8> what_was_read{};
    if (!ReadMemory(main_thread, address, what_was_written.size(), what_was_read))
        return -1;
    const std::string written = BytesToString(what_was_written);
    const std::string readback = BytesToString(what_was_read);

    return written == readback;
}

bool BreakpointEnable_SW(u64 addr) {
    breakpoint_sw_t* target = BreakpointFind_SW(addr);
    if (target == nullptr)
        return false;

    std::vector<u8> to_write{};
    for (auto _ : target->original_data)
        to_write.push_back(0xCC);

    if (!WriteMemory(main_thread, target->address, to_write.size(), to_write))
        return false;

    u8 ret = compareData(addr, to_write);

    return ret == 1;
}

bool BreakpointDisable_SW(u64 addr) {
    breakpoint_sw_t* target = BreakpointFind_SW(addr);
    if (target == nullptr)
        return false;

    if (!WriteMemory(main_thread, target->address, target->original_data.size(),
                     target->original_data)) {

        return false;
    }

    u8 ret = compareData(addr, target->original_data);

    return ret == 1;
}
