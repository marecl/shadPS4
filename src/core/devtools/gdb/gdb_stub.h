// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <thread>
#include <ucontext.h>

namespace Core::Devtools {

class GdbStub {
    enum class Register : int {
        RAX = REG_RAX,
        RBX = REG_RBX,
        RCX = REG_RCX,
        RDX = REG_RDX,
        RSI = REG_RSI,
        RDI = REG_RDI,
        RBP = REG_RBP,
        RSP = REG_RSP,
        R8 = REG_R8,
        R9 = REG_R9,
        R10 = REG_R10,
        R11 = REG_R11,
        R12 = REG_R12,
        R13 = REG_R13,
        R14 = REG_R14,
        R15 = REG_R15,
        RIP = REG_RIP,
    };

public:
    explicit GdbStub(u16 port);

    ~GdbStub();

private:
    u16 m_port;
    int m_socket{};
    std::jthread m_thread;

    // Taken from xenia
    enum class ControlCode : char {
        Ack = '+',
        Nack = '-',
        PacketStart = '$',
        PacketEnd = '#',
        Interrupt = '\03',
    };

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

    static std::string ReadRegisterAsString(Register reg);
    std::string MakeResponse(const std::string& response);
    std::string handler(const GdbCommand& command);
    std::string handle_v_packet(const GdbCommand& command);
    std::string handle_q_packet(const GdbCommand& command);
    std::string handle_Q_packet(const GdbCommand& command) {
        return "E.Stub";
    }

    void Run(const std::stop_token& stop);
};

} // namespace Core::Devtools
