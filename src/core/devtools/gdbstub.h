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

    // Taken from xenia
    struct GDBCommand {
        std::string cmd{};  // Command
        std::string data{}; // Full packet
        // u8 checksum{}; // Checksum
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

    struct Breakpoint {
        u64 address;
        u8 original_byte;

        explicit Breakpoint(const u64 address) : address(address) {
            original_byte = *reinterpret_cast<u8*>(address);
            Enable();
        }

        ~Breakpoint() {
            Disable();
        }

        void Enable() const {
            *reinterpret_cast<u8*>(address) = 0xCC;
        }

        void Disable() const {
            *reinterpret_cast<u8*>(address) = original_byte;
        }
    };

    std::vector<Breakpoint> m_breakpoints;

    void CreateSocket();

    std::string ProcessIncomingData(int client);
    std::string HandleCommand(const GDBCommand& command);

    static std::string ReadRegisterAsString(Register reg);

    void Run(const std::stop_token& stop_token);
};

} // namespace Core::Devtools
