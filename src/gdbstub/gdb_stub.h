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

// Show received/sent data. It's a lot and may obfuscate the rest of the program
#define DEBUG_COMM

class GdbStub {
public:
    GdbStub(Predator* predator, PtraceListener* listener, StubServer* stub_server)
        : predator(predator), listener(listener), stub_server(stub_server),
          client_connected(false) {};
    ~GdbStub() {};

    s8 LoopCommand(void);
    bool LoopTrace(void);
    s8 HandleContinuous(GdbCommand cmd);
    std::string HandlePacket(GdbCommand cmd);

    // printing for gdb
    std::string ThreadList(void);
    std::string PrintRegisters(const struct user_regs_struct* regs,
                               const struct user_fpregs_struct* fpregs);
    bool ReadMemory(const u64 address, const u64 length, std::string* out);
    bool WriteMemory(const u64 address, const u64 length,std::vector<u8> data);

    // ...
    void End(int code);

private:
    bool SendMessage(std::string message, bool raw_and_mute = false);
    void handle_packet_vCont(std::string arg);

    bool client_connected{};
    Predator* predator{};
    PtraceListener* listener{};
    StubServer* stub_server{};
};

#endif // GDB_STUB_H