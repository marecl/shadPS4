// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>

#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "common/assert.h"
#include "common/debug.h"
#include "core/libraries/kernel/kernel.h"
#include "core/memory.h"
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
    static auto Receive = [&] -> std::string {
        char buf[1024];
        const ssize_t bytes = recv(client, buf, sizeof(buf), 0);
        if (bytes <= 0) {
            return "";
        }

        return std::string(buf, bytes);
    };

    static auto Trim = [&](const std::string& packet) -> std::string {
        if (packet.front() != PacketStart && packet.front() != Ack ||
            packet.find(PacketEnd) == std::string::npos) {
            UNREACHABLE_MSG("Malformed packet '{}'", packet);
        }

        std::string trimmed_packet = packet.substr(1, packet.find(PacketEnd) - 1);
        if (const size_t colon_pos = trimmed_packet.find(':'); colon_pos != std::string::npos) {
            trimmed_packet = trimmed_packet.substr(0, colon_pos);
        }
        if (const size_t dash_pos = trimmed_packet.find('-'); dash_pos != std::string::npos) {
            trimmed_packet = trimmed_packet.substr(0, dash_pos);
        }
        if (const size_t semicolon_pos = trimmed_packet.find(';');
            semicolon_pos != std::string::npos) {
            trimmed_packet = trimmed_packet.substr(0, semicolon_pos);
        }
        if (std::isdigit(trimmed_packet[1])) {
            return std::string(1, trimmed_packet[0]);
        }
        return trimmed_packet;
    };

    auto packet = Receive();

    if (packet.empty()) {
        return "";
    }

    if (packet == "+") {
        // Initial acknowledgement
        return "+";
    }

    if (packet.front() == Interrupt) {
        BREAKPOINT();
    }

    if (packet.front() == '+') {
        packet = packet.substr(1);
    }

    const std::string command = Trim(packet);

    LOG_INFO(Debug, "Raw packet '{}'", packet);
    LOG_INFO(Debug, "Trimmed packet (command) = {}", command);

    return HandleCommand({command, packet});
}

u8 CalculateChecksum(const std::string& command) {
    u8 sum = 0;
    for (const char c : command) {
        sum += static_cast<uint8_t>(c);
    }
    return sum & 0xFF;
}

static std::string MakeResponse(const std::string& response) {
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
}

static void EnableStepping() {
    // Taken from
    // https://stackoverflow.com/questions/77123145/how-to-create-an-int-1-interrupt-handler-when-the-trap-flag-is-enabled
    asm volatile("pushf\n\t"            // Push FLAGS onto the stack
                 "pop %%ax\n\t"         // Pop FLAGS into AX register
                 "or $0x0100, %%ax\n\t" // Set the Trap Flag (bit 8)
                 "push %%ax\n\t"        // Push the modified value onto the stack
                 "popf\n\t"             // Pop it back into FLAGS
                 :
                 :
                 : "ax", "flags" // Clobbers AX and FLAGS
    );
}

std::string GdbStub::HandleCommand(const GDBCommand& command) {
    LOG_INFO(Debug, "command.cmd = {}", command.cmd);

    static const std::unordered_map<std::string, std::function<std::string()>> command_table{
        {"!", [&] { return "OK"; }},
        {"?", [&] { return "S05"; }},
        {"Hg0", [&] { return "OK"; }},
        {"Z",
         [&] {
             const u64 address = std::stoull(command.data.substr(4, 9), nullptr, 16);
             m_breakpoints.emplace_back(address);
             return "OK";
         }},
        {"g",
         [&] {
             int i = 0;
             std::string regs;

             // TODO: Is there a way to do this with a custom match function?
             magic_enum::enum_for_each<Register>([&i, &regs](auto val) {
                 ++i;

                 if (i <= 17) {
                     constexpr Register reg = val;
                     regs += ReadRegisterAsString(reg);
                 }
             });

             return regs;
         }},
        {"Hc",
         [&] {
             const auto tid = std::stoi(command.data.substr(4, 1), nullptr, 16);
             LOG_INFO(Debug, "tid = {}", tid);

             return "OK";
         }},
        {"m",
         [&] {
             // TODO: Clean this garbage up :(

             if (const size_t comma_pos = command.data.find(','); comma_pos != std::string::npos) {
                 const u64 address =
                     std::stoull(command.data.substr(2, comma_pos - 1), nullptr, 16);
                 const u64 length = std::stoull(command.data.substr(comma_pos + 1), nullptr, 16);

                 static auto mem = Memory::Instance();
                 std::scoped_lock lck{mem->mutex};

                 bool is_valid_address = false;

                 for (auto [d_addr, d_mem_area] : mem->dmem_map) {
                     if (address >= d_addr && address + length <= d_addr + d_mem_area.size) {
                         is_valid_address = true;
                         break;
                     }
                 }

                 for (auto [v_addr, v_mem_area] : mem->vma_map) {
                     if (address >= v_addr && address + length <= v_addr + v_mem_area.size) {
                         is_valid_address = true;
                         break;
                     }
                 }

                 if (!is_valid_address) {
                     LOG_ERROR(Debug, "Invalid address: 0x{:x}", address);
                     return std::string("E01");
                 }

                 std::string memory;
                 for (u64 i = 0; i < length; ++i) {
                     mprotect(reinterpret_cast<u8*>(address + i), 1, PROT_READ);
                     memory += fmt::format("{:02x}", *reinterpret_cast<u8*>(address + i));
                 }

                 return memory;
             }

             return std::string("E01");
         }},
        {"p",
         [&] {
             const auto reg = static_cast<Register>(std::stoi(command.data.substr(2), nullptr, 16));
             return ReadRegisterAsString(reg);
         }},
        {"qAttached", [&] { return "1"; }},
        {"qC", [&] { return fmt::format("QC {:x}", gettid()); }},
        {"qSupported", [&] { return "PacketSize=1024;qXfer:features:read+;binary-upload+;"; }},
        {"qTStatus", [&] { return "Trunning;tnotrun:0"; }},
        {"qXfer",
         [&] {
             auto param = command.data;
             if (param.length() > 0 && param[0] == ':') {
                 param = param.substr(1);
             }

             const auto sub_cmd = param.substr(0, param.find(':'));
             if (sub_cmd == "features") {
                 return target_description;
             }

             return "E01";
         }},
        {"qfThreadInfo",
         [&] {
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
        {"vCont?", [&] { return "vCont;c;t"; }},
        {"vCont", [] { return "OK"; }},
        {"vMustReplyEmpty", [&] { return ""; }},
        {"x",
         [&] {
             if (const size_t comma_pos = command.data.find(','); comma_pos != std::string::npos) {
                 const u64 address =
                     std::stoull(command.data.substr(2, comma_pos - 1), nullptr, 16);
                 const u64 length = std::stoull(command.data.substr(comma_pos + 1), nullptr, 16);

                 static auto mem = Memory::Instance();
                 std::scoped_lock lck{mem->mutex};

                 bool is_valid_address = false;

                 for (auto [d_addr, d_mem_area] : mem->dmem_map) {
                     if (address >= d_addr && address + length <= d_addr + d_mem_area.size) {
                         is_valid_address = true;
                         break;
                     }
                 }

                 for (auto [v_addr, v_mem_area] : mem->vma_map) {
                     if (address >= v_addr && address + length <= v_addr + v_mem_area.size) {
                         is_valid_address = true;
                         break;
                     }
                 }

                 if (!is_valid_address) {
                     LOG_ERROR(Debug, "Invalid address: 0x{:x}", address);
                     return std::string("E01");
                 }

                 std::string memory;
                 for (u64 i = 0; i < length; ++i) {
                     mprotect(reinterpret_cast<u8*>(address + i), 1, PROT_READ);
                     memory += fmt::format("{:02x}", *reinterpret_cast<u8*>(address + i));
                 }

                 return memory;
             }

             return std::string("E01");
         }},
        /*{"z",
         [&] {
             const u64 address = std::stoull(command.data.substr(4, 9), nullptr, 16);
             for (auto it = m_breakpoints.begin(); it != m_breakpoints.end(); ++it) {
                 if (it->address == address) {
                     m_breakpoints.erase(it);
                     return "OK";
                 }
             }

             return "E01";
         }},
        {"vRun", [&] {
            EnableStepping();
            return "OK";
        }},
        {"vCont;c",
         [&] {
             EnableStepping();
             return "OK";
         }},
        {"c",
         [&] {
             EnableStepping();
             return "S05"; // Stopped
         }},
        {"s",
         [&] {
             EnableStepping();
             return "S05"; // Stopped
         }},
        {"D",
         [&] {
             // Detach

            return "";
        }}*/
    };

    if (const auto it = command_table.find(command.cmd); it != command_table.end()) {
        return MakeResponse(it->second());
    }

    LOG_ERROR(Debug, "Unhandled command '{}'", command.cmd);
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
        LOG_ERROR(Debug, "Saying {} is unavailable", static_cast<int>(reg));
        return "xxxxxxxxxxxxxxxx";
    }

    auto formatted = fmt::format("{:016x}", SwapEndian64(value));
    LOG_INFO(Debug, "Endian swapped value of {} is '{}'", magic_enum::enum_name(reg), formatted);
    return formatted;
}

void GdbStub::Run(const std::stop_token& stop_token) {
    LOG_INFO(Debug, "GDB server listening on port {}", m_port);

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

        while (!stop_token.stop_requested()) {
            std::string reply = ProcessIncomingData(client);
            if (reply.empty()) {
                // No data available, can do other work or sleep
                // std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
