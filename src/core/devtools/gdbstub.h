// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <optional>
#include <thread>

namespace Core::Devtools {

class GdbStub {
public:
    GdbStub();
    ~GdbStub();

private:
    int m_socket;
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

    // Return a reply for GDB on success
    std::optional<std::string> ProcessIncomingData(int client);
    static std::optional<std::string> ProcessCommand(const std::string& command);

    void Run(const std::stop_token& stop_token);
};

} // namespace Core::Devtools
