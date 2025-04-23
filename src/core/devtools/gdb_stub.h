// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <thread>

namespace Core::Devtools {

class GdbStub {
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
        std::string cmd{};
        std::string raw_data{};
        u8 checksum{};
    };

    enum class Register : int {
        RAX = 0,
        RBX,
        RCX,
        RDX,
        RSI,
        RDI,
        RBP,
        RSP,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        RIP,
        EFLAGS,
        CS,
        SS,
        DS,
        ES,
        FS,
        GS,
    };

    void CreateSocket();
    void ReInit();
    static bool IsValidAddress(u64 address, u64 length);
    static bool ReadMemory(u64 address, u64 length, std::string* out);
    static GdbCommand ParsePacket(const std::string& data);
    static bool HandleIncomingData(int client);
    static std::string HandleCommand(const GdbCommand& command);

    static std::string ReadRegisterAsString(Register reg);

    void Run(const std::stop_token& stop) const;
};

} // namespace Core::Devtools
