// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDB_STUB_H
#define GDB_STUB_H

#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/user.h>

#include "childtools.h"
#include "common/types.h"
#include "threadinfo.h"

namespace Core::Devtools {

namespace GdbStub {

extern const char* const OK;
extern const char* const E01;
extern const char* const touch_grass;

extern Predator* predator;

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