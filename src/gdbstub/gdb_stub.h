// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDB_STUB_H
#define GDB_STUB_H

#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/user.h>

#include "common/types.h"
#include "threadinfo.h"

namespace Core::Devtools {

namespace GdbStub {

extern const char* const OK;
extern const char* const E01;
extern const char* const touch_grass;

// move this to a separate class, so stub and main can have access to it
// also, childtools
struct system_state_t {
    std::unordered_map<pid_t, std::string> threads{}; ///< TID + name
    std::unordered_map<pid_t, u8> threads_running{};  ///< TID + latest signal sent/received (TODO)
    ThreadID thread_main = -1;                        ///< make this const at program startup??
    // in case if gdb can select multiple threads, be prepared to turn these into vectors
    ThreadID thread_sel_reg_dump = -1;       ///< selected for g-action
    ThreadID thread_sel_flow = -1;           ///< selected for s/c/t action
    bool user_regs_dirty = true;             ///< thread changed, true if regs weren't updated
    struct user_regs_struct user_regs{};     ///< latest thread regs dump
    struct user_fpregs_struct user_fpregs{}; ///< latest thread floating point regs dump
};

extern struct system_state_t g_system_state;

enum class ControlCode : char {
    Ack = '+',
    Nack = '-',
    PacketStart = '$',
    PacketEnd = '#',
    Interrupt = '\03',
};

enum LoopAction {
    ERROR,          ///< Error, what to do - idk, just notify the user
    EXIT,           ///< GDB signaled to detach. RN it kills the whole app
    BACK_TO_SENDER, ///< Send back whatever GDB sent
    REPEAT,         ///< Repeat last response (no change)
    SEND,           ///< Send response
    NOSEND          ///< Don't send anything (now)
};

struct GdbCommand {
    std::string raw{};
    std::string cmd{};
    std::string arg{};
};

LoopAction Loop(std::string message, std::string& response);
s8 HandleContinuous(GdbCommand cmd);
std::string HandlePacket(GdbCommand cmd);

// these 3 to the same class as childtools
void ThreadRegister(ThreadID id);
void ThreadUnregister(ThreadID id);
void ThreadRefresh(void);

// printing for gdb
std::string ThreadList(void);
std::string PrintRegisters(const struct user_regs_struct* regs,
                           const struct user_fpregs_struct* fpregs);
bool ReadMemory(const u64 address, const u64 length, std::string* out);

// pretty generic if you asked me
// just get rid of those control characters, jeez
s8 Preprocess(std::string& data);
GdbCommand ParsePacket(const std::string data);
std::string MakeResponse(const std::string msg);

} // namespace GdbStub

} // namespace Core::Devtools

#endif // GDB_STUB_H