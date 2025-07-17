// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <iostream>
#include <thread>
#include <ucontext.h>
#include "gdb_data.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>
using ThreadID = DWORD;
#else
#include <pthread.h>
#include <signal.h>
using ThreadID = pthread_t;
#endif

namespace Core::Devtools {

class GdbStub {
public:
    explicit GdbStub(u16 port, pid_t parent, GdbDataType::SharedVector* shared);
    ~GdbStub();
    bool Run();

    std::string BuildThreadList();

private:
    GdbDataType::SharedVector* shd;

    // Taken from xenia
    enum class ControlCode : char {
        Ack = '+',
        Nack = '-',
        PacketStart = '$',
        PacketEnd = '#',
        Interrupt = '\03',
    };

    GdbDataType::ThreadInfo* selectedThread;

    pid_t pid_target;
    pid_t pid_self;
    u16 m_port;
    int m_socket{};

    // Taken from xenia
    struct GdbCommand {
        std::string raw{};
        std::string cmd{};
        std::string arg{};
    };

    void CreateSocket();
    static bool IsValidAddress(u64 address, u64 length);
    static bool ReadMemory(u64 address, u64 length, std::string* out);
    static GdbCommand ParsePacket(const std::string& data);
    bool HandleIncomingData(const int client);
    static GdbStub::GdbCommand HandleCommand(const GdbCommand& command);
    GdbDataType::ThreadInfo* getThreadHandleFromString(const std::string& data);
    std::string GdbStub::dumpRegistersFromThread(struct user_regs_struct regs,
                                                 struct user_fpregs_struct fpregs);
    std::string MakeResponse(const std::string& response);
    std::string handler(const GdbCommand& command);
    std::string handle_v_packet(const GdbCommand& command);
    std::string handle_H_packet(const GdbCommand& command);
    std::string handle_q_packet(const GdbCommand& command);
    std::string handle_Q_packet(const GdbCommand& command) {
        return "E.Stub";
    }
};

} // namespace Core::Devtools
