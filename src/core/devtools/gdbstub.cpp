// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <unordered_map>

#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <sys/socket.h>

#include "common/assert.h"
#include "core/thread.h"
#include "gdbstub.h"

#if defined(__GNUC__)
u64 SwapEndian64(const u64 value) {
    return __builtin_bswap64(value);
}
#elif defined(_MSC_VER)
u64 SwapEndian64(const u64 value) {
    return _byteswap_uint64(value);
}
#endif

namespace Core::Devtools {

constexpr char target_description[] = R"(l<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>)";

GdbStub::GdbStub(const u16 port) : m_port(port), m_thread(&GdbStub::Run, this) {
    CreateSocket();
    m_thread.detach();
}

GdbStub::~GdbStub() {
    close(m_socket);
}

void GdbStub::CreateSocket() {
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_MSG(m_socket != -1, "Failed to create socket ({})", strerror(errno));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    ASSERT_MSG(bind(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != -1,
               "Failed to bind socket ({})", strerror(errno));
}

std::string GdbStub::ProcessIncomingData(const int client) {
    std::string buf_str;
    while (true) {
        char buf[1024];
        const ssize_t bytes = recv(client, buf, sizeof(buf), 0);
        if (bytes <= 0) {
            LOG_ERROR(Debug, "Failed to read from client ({})", strerror(errno));
            return "";
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
            return HandleCommand(m_recv_buffer);
        } else {
            m_recv_buffer.push_back(c);
        }
    }

    return "";
}

static std::string MakeResponse(const std::string& response) {
    uint8_t checksum = 0;
    for (const char c : response) {
        checksum += static_cast<uint8_t>(c);
    }
    return "+$" + response + "#" + fmt::format("{:02X}", checksum & 0xFF);
}

std::string GdbStub::HandleCommand(const std::string& command) {
    LOG_INFO(Debug, "command = {}", command);

    static const std::unordered_map<std::string, std::function<std::string()>> command_table{
        {"?", [] { return "S05"; }},
        {"Hg0", [] { return "OK"; }},
        {"vCont?", [] { return "vCont;c;t"; }},
        {"qAttached", [] { return "1"; }},
        {"!", [] { return "OK"; }},
        {"qfThreadInfo",
         [] {
             fmt::memory_buffer buf;
             fmt::format_to(std::back_inserter(buf), "m");

             for (size_t i = 0; i < thread_ids.size(); ++i) {
                 if (i > 0) {
                     fmt::format_to(std::back_inserter(buf), ",");
                 }
                 fmt::format_to(std::back_inserter(buf), "{:x}", thread_ids[i]);
             }

             fmt::format_to(std::back_inserter(buf), "l");

             return to_string(buf);
         }},
        {"qC", [] { return fmt::format("QC {:x}", gettid()); }},
        {"g",
         [] {
             int i = 1;
             std::string regs;

             // TODO: Is there a way to do this with a custom match function?
             magic_enum::enum_for_each<Register>([&i, &regs](auto val) {
                 ++i;

                 if (i <= static_cast<int>(Register::RIP)) {
                     constexpr Register reg = val;
                     regs += ReadRegisterAsString(reg);
                 }
             });

             return regs;
         }},
        {"vMustReplyEmpty", [] { return ""; }},
        {"qTStatus", [] { return "Trunning;tnotrun:0"; }},
    };

    if (const auto it = command_table.find(command); it != command_table.end()) {
        return MakeResponse(it->second());
    }

    // Substring commands...

    if (command.substr(0, 10) == "qSupported") {
        return MakeResponse("PacketSize=1024;qXfer:features:read+;");
    }

    if (command.substr(0, 5) == "qXfer") {
        if (command.substr(6, 8) == "features") {
            return MakeResponse(target_description);
        }
    }

    if (command.size() == 3 && command.at(0) == 'p') {
        const auto reg = static_cast<Register>(std::stoi(command.substr(1), nullptr, 16));
        return MakeResponse(ReadRegisterAsString(reg));
    }

    if (command.size() > 1 && command[0] == 'm') {
        const auto comma_pos = command.find(',');
        if (comma_pos != std::string::npos) {
            const uintptr_t addr = std::stoull(command.substr(1, comma_pos - 1), nullptr, 16);
            const size_t length = std::stoul(command.substr(comma_pos + 1), nullptr, 16);

            std::vector<uint8_t> buffer(length);
            if (memcpy(buffer.data(), reinterpret_cast<void*>(addr), length) == nullptr) {
                LOG_ERROR(Debug, "Memory read failed at address {:x}", addr);
                return "E03"; // Memory access error
            }

            std::ostringstream response;
            response << std::hex << std::setfill('0');
            for (const uint8_t byte : buffer)
                response << std::setw(2) << static_cast<int>(byte);
            return response.str();
        }
    }

    LOG_ERROR(Debug, "Unhandled command '{}'", command);
    return MakeResponse("");
}

std::string GdbStub::ReadRegisterAsString(const Register reg) {
    u64 value = 0;

    switch (reg) {
    case Register::RAX:
        asm volatile("mov %%rax, %0" : "=r"(value));
        break;
    case Register::RBX:
        asm volatile("mov %%rbx, %0" : "=r"(value));
        break;
    case Register::RCX:
        asm volatile("mov %%rcx, %0" : "=r"(value));
        break;
    case Register::RDX:
        asm volatile("mov %%rdx, %0" : "=r"(value));
        break;
    case Register::RSI:
        asm volatile("mov %%rsi, %0" : "=r"(value));
        break;
    case Register::RDI:
        asm volatile("mov %%rdi, %0" : "=r"(value));
        break;
    case Register::RBP:
        asm volatile("mov %%rbp, %0" : "=r"(value));
        break;
    case Register::RSP:
        asm volatile("mov %%rsp, %0" : "=r"(value));
        break;
    case Register::R8:
        asm volatile("mov %%r8, %0" : "=r"(value));
        break;
    case Register::R9:
        asm volatile("mov %%r9, %0" : "=r"(value));
        break;
    case Register::R10:
        asm volatile("mov %%r10, %0" : "=r"(value));
        break;
    case Register::R11:
        asm volatile("mov %%r11, %0" : "=r"(value));
        break;
    case Register::R12:
        asm volatile("mov %%r12, %0" : "=r"(value));
        break;
    case Register::R13:
        asm volatile("mov %%r13, %0" : "=r"(value));
        break;
    case Register::R14:
        asm volatile("mov %%r14, %0" : "=r"(value));
        break;
    case Register::R15: // For some reason, IDA requests this register, even though it gets it from
                        // 'g' as well
        asm volatile("mov %%r15, %0" : "=r"(value));
        break;
    case Register::RIP:
        asm volatile("lea (%%rip), %0" : "=r"(value));
        break;
    case Register::EFLAGS:
        asm volatile("pushfq; pop %0" : "=r"(value));
        break;
    case Register::CS:
        asm volatile("mov %%cs, %0" : "=r"(value));
        break;
    case Register::SS:
        asm volatile("mov %%ss, %0" : "=r"(value));
        break;
    case Register::DS:
        asm volatile("mov %%ds, %0" : "=r"(value));
        break;
    case Register::ES:
        asm volatile("mov %%es, %0" : "=r"(value));
        break;
    case Register::FS:
        asm volatile("mov %%fs, %0" : "=r"(value));
        break;
    case Register::GS:
        asm volatile("mov %%gs, %0" : "=r"(value));
        break;
    default:
        LOG_ERROR(Debug, "Saying {} is unavailable", magic_enum::enum_name(reg));
        return "xxxxxxxxxxxxxxxx";
    }

    auto formatted = fmt::format("{:016x}", SwapEndian64(value));
    LOG_INFO(Debug, "Endian swapped value of {} is '{}'", magic_enum::enum_name(reg), formatted);
    return formatted;
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
            std::string reply = ProcessIncomingData(client);
            if (reply.empty()) {
                // No data available, can do other work or sleep
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                break;
            }

            LOG_INFO(Debug, "Replying with '{}'", reply);
            const ssize_t bytes = send(client, reply.c_str(), reply.size(), 0);
            if (bytes <= 0) {
                break;
            }
        }

        // close(client);
    }
}

} // namespace Core::Devtools
