// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <functional>
#include <optional>
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
    std::string m_recv_buffer;

    // Taken from xenia
    enum ControlCode : char {
        Ack = '+',
        Nack = '-',
        PacketStart = '$',
        PacketEnd = '#',
        Interrupt = '\03',
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
        ST0,
        ST1,
        ST2,
        ST3,
        ST4,
        ST5,
        ST6,
        ST7,
        FCTRL,
        FSTAT,
        FTAG,
        FISEG,
        FIOFF,
        FOSEG,
        FOOFF,
        FOP
    };

    void CreateSocket();

    std::string ProcessIncomingData(int client);
    static std::string HandleCommand(const std::string& command);

    static std::string ReadRegisterAsString(Register reg);

    void Run(const std::stop_token& stop_token);
};

} // namespace Core::Devtools
