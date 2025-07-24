// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDB_STUB_H
#define GDB_STUB_H

#include <iostream>
#include <thread>

#include <sys/user.h>

#include "childtools.h"
#include "common/types.h"
#include "gdb_server.h"
#include "ptrace_listener.h"
#include "threadinfo.h"

#include "gdb_command.h"

class GdbStub {
public:
    GdbStub(Predator* predator, PtraceListener* listener, StubServer* stub_server)
        : predator(predator), listener(listener), stub_server(stub_server) {};
    ~GdbStub() {};
    void End(u8 code);

    s8 LoopCommand(void);
    bool LoopTrace(void);
    s8 HandleContinuous(GdbCommand cmd);
    std::string HandlePacket(GdbCommand cmd);

    // printing for gdb
    std::string ThreadList(void);
    std::string PrintRegisters(const struct user_regs_struct* regs,
                               const struct user_fpregs_struct* fpregs);
    bool ReadMemory(const u64 address, const u64 length, std::string* out);

    // pretty generic if you asked me
    // just get rid of those control characters, jeez

private:
    bool SendMessage(std::string message, bool raw = false);


    Predator* predator;
    PtraceListener* listener;
    StubServer* stub_server;
};

#endif // GDB_STUB_H