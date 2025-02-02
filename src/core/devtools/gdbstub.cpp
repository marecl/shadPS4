// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "common/assert.h"
#include "gdbstub.h"

namespace Core::Devtools {

GdbStub::GdbStub() : m_socket(socket(AF_INET, SOCK_STREAM, 0)), m_thread(&GdbStub::Run, this) {
    ASSERT(m_socket != -1);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(42069);
    addr.sin_addr.s_addr = INADDR_ANY;

    const int ret = bind(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ASSERT_MSG(ret != -1, "{}", strerror(errno));

    m_thread.detach();
}

GdbStub::~GdbStub() {
    close(m_socket);
}

std::optional<std::string> GdbStub::ProcessIncomingData(const int client) {
    /*char packet_buf[1024];
    const ssize_t read = recv(client, packet_buf, sizeof(packet_buf), 0);
    if (read <= 0) {
        LOG_ERROR(Debug, "Failed to read from client ({})", strerror(errno));
        return std::nullopt;
    }

    auto buf_str = std::string(packet_buf, read);

    LOG_INFO(Debug, "buf_str = {}", buf_str);

    //
    https://sourceware.org/gdb/current/onlinedocs/gdb.html/Packet-Acknowledgment.html#index-acknowledgment_002c-for-GDB-remote
    if (buf_str[0] == Ack) {
        LOG_INFO(Debug, "The package was received correctly");
    } else if (buf_str[0] == Nack) {
        LOG_ERROR(Debug, "Requesting retransmission");
    }

    for (const char c : buf_str) {
        if (c == PacketStart) {
            m_recv_buffer.clear();
        } else if (c == PacketEnd) {
            return ProcessCommand(m_recv_buffer);
        } else {
            m_recv_buffer.push_back(c);
        }
    }

    return std::nullopt;*/

    std::string buf_str;
    while (true) {
        char buf[1024];
        const ssize_t bytes = recv(client, buf, sizeof(buf), 0);
        if (bytes <= 0) {
            LOG_ERROR(Debug, "Failed to read from client ({})", strerror(errno));
            return std::nullopt;
        }

        buf_str.append(buf, bytes);

        if (buf_str.find(PacketStart) != std::string::npos &&
            buf_str.find(PacketEnd) != std::string::npos) {
            break;
        }
    }

    for (const char c : buf_str) {
        if (c == PacketStart) {
            m_recv_buffer.clear();
        } else if (c == PacketEnd) {
            return ProcessCommand(m_recv_buffer);
        } else {
            m_recv_buffer.push_back(c);
        }
    }

    return std::nullopt;
}

/*std::optional<std::string> GdbStub::ProcessIncomingData(const int client) {
    //
https://github.com/emoose/xenia/blob/591755432430ddf7751dc02f50deadde0c3ee011/src/xenia/debug/gdb/gdbstub.cc#L325
    char buf[1024];
    const ssize_t bytes = recv(client, buf, sizeof(buf), 0);
    if (bytes <= 0) {
        return std::nullopt;
    }

    /*
     * Packet format:
     *
     * - $      : Start
     * - ...    : Command
     * - #...   : Start of checksum (end)
     #1#

    const std::string buf_str(buf, bytes);
    if (buf_str.find(PacketStart) == std::string::npos ||
        buf_str.find(PacketEnd) == std::string::npos) {
        LOG_INFO(Debug, "Invalid packet '{}'?", buf_str);
        return std::nullopt;
    }

    return ProcessCommand(buf_str);
}*/

static std::string ToHex(const uint8_t value) {
    char buffer[3];
    snprintf(buffer, sizeof(buffer), "%02X", value);
    return std::string(buffer);
}

static std::string CreateResponseWithChecksum(const std::string& response) {
    uint8_t checksum = 0;
    for (const char c : response) {
        checksum ^= static_cast<uint8_t>(c);
    }
    return "$" + response + "#" + ToHex(checksum);
}

std::optional<std::string> GdbStub::ProcessCommand(const std::string& command) {
    LOG_INFO(Debug, "command = {}", command);

    // Prepare for a mess!

    if (command == "!") {
        return std::string("OK");
    }

    if (command == "Hg0") {
        // What is this?
        return std::string("OK");
    }

    if (command == "?") {
        return CreateResponseWithChecksum("R02");
    }

    if (const auto substr = command.substr(0, 10); substr == "qSupported") {
        return CreateResponseWithChecksum("PacketSize=1024");
    }

    if (const auto substr = command.substr(0, 9); substr == "qAttached") {
        return CreateResponseWithChecksum("1");
    }

    LOG_ERROR(Debug, "Unhandled command '{}'", command);
    return std::nullopt;
}

void GdbStub::Run(const std::stop_token& stop_token) {
    LOG_INFO(Debug, "GDB server listening on port 13378");

    listen(m_socket, 5);

    while (!stop_token.stop_requested()) {
        sockaddr_in addr{};
        socklen_t addr_len = sizeof(addr);
        const int client = accept(m_socket, reinterpret_cast<sockaddr*>(&addr), &addr_len);
        if (client == -1) {
            if (stop_token.stop_requested()) {
                break;
            }
            LOG_ERROR(Debug, "Accept failed: {}", strerror(errno));
            continue;
        }

        timeval timeout = {10, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        while (!stop_token.stop_requested()) {
            const auto reply = ProcessIncomingData(client);
            if (!reply) {
                // No data available, can do other work or sleep
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                break;
            }

            const std::string& reply_str = *reply;
            LOG_INFO(Debug, "Replying with '{}'", reply_str);
            const ssize_t bytes = send(client, reply_str.c_str(), reply_str.size(), 0);
            if (bytes <= 0) {
                break;
            }
        }

        // close(client);
    }
}

} // namespace Core::Devtools
