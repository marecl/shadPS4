// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <thread>
#include <ucontext.h>

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
    explicit GdbStub(u16 port);

    ~GdbStub();

private:
    // Taken from xenia
    enum class ControlCode : char {
        Ack = '+',
        Nack = '-',
        PacketStart = '$',
        PacketEnd = '#',
        Interrupt = '\03',
    };

    ThreadID selectedThread;

    u16 m_port;
    int m_socket{};
    std::jthread m_thread;

    // Taken from xenia
    struct GdbCommand {
        std::string raw{};
        std::string cmd{};
        std::string arg{};
    };

    void CreateSocket();
    void ReInit();
    static bool IsValidAddress(u64 address, u64 length);
    static bool ReadMemory(u64 address, u64 length, std::string* out);
    static GdbCommand ParsePacket(const std::string& data);
    bool HandleIncomingData(const int client);
    static GdbStub::GdbCommand HandleCommand(const GdbCommand& command);

    static std::string dumpRegistersFromThread(ThreadID threadID);
    std::string MakeResponse(const std::string& response);
    std::string handler(const GdbCommand& command);
    std::string handle_v_packet(const GdbCommand& command);
    std::string handle_H_packet(const GdbCommand& command);
    std::string handle_q_packet(const GdbCommand& command);
    std::string handle_Q_packet(const GdbCommand& command) {
        return "E.Stub";
    }

    void Run(const std::stop_token& stop);
};

} // namespace Core::Devtools
