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

#define MAX_REGISTERED_THREADS 2137

extern const char* const OK;
extern const char* const E01;
extern const char* const touch_grass;

struct system_state_t {
    std::unordered_map<pid_t, std::string> threads; // TID + name
    std::unordered_map<pid_t, u8> threads_running;  // TID + latest signal sent/received
    // make this const at program startup??
    ThreadID thread_main;
    // in case if gdb can select multiple threads, be prepared to turn these into vectors
    ThreadID thread_sel_reg_dump; // selected for g-action
    ThreadID thread_sel_flow;     // selected for s/c/t action
    // latest thread dump
    bool user_regs_dirty; // thread changed, true if regs weren't updated
    struct user_regs_struct user_regs;
    struct user_fpregs_struct user_fpregs;
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
    ERROR,          // Error, what to do - idk, just notify the user
    EXIT,           // GDB signaled to detach. RN it kills the whole app
    BACK_TO_SENDER, // Send back whatever GDB sent
    REPEAT,         // Repeat last response (no change)
    SEND,           // Send response
    NOSEND          // Don't send anything (now)
};

struct GdbCommand {
    std::string raw{};
    std::string cmd{};
    std::string arg{};
};

LoopAction Loop(std::string message, std::string& response);

s8 HandleContinuous(GdbCommand cmd);
std::string HandlePacket(GdbCommand cmd);
void ThreadRegister(ThreadID id);
void ThreadUnregister(ThreadID id);
void ThreadRefresh(void);
std::string ThreadList(void);

// dump for gdb ONLY IF WERE READ FIRST!!!

// struct user_regs_struct*
// struct user_fpregs_struct*
std::string PrintRegisters(const struct user_regs_struct* regs,
                           const struct user_fpregs_struct* fpregs);

// pretty generic if you asked me
s8 Preprocess(std::string& data);
GdbCommand ParsePacket(const std::string data);
std::string MakeResponse(const std::string msg);
bool ReadMemory(const u64 address, const u64 length, std::string* out);

} // namespace GdbStub

} // namespace Core::Devtools

#endif // GDB_STUB_H