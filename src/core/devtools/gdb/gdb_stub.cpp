// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>
#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "common/assert.h"
#include "common/debug.h"
#include "core/debug_state.h"
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"
#include "gdb_stub.h"

using namespace DebugStateType;
using namespace ::Libraries::Kernel;

namespace Core::Devtools {

DebugStateImpl& DebugState = *Common::Singleton<DebugStateImpl>::Instance();

constexpr auto OK = "OK";
constexpr auto E01 = "E01";

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

GdbStub::GdbCommand GdbStub::ParsePacket(const std::string& data) {
    const auto end_pos = data.find(char(ControlCode::PacketEnd));

    if (data[0] != char(ControlCode::PacketStart) || end_pos == std::string::npos) {
        UNREACHABLE_MSG("Malformed packet: {}", data);
    }

    const std::string_view cmd_view = std::string_view(data).substr(1, end_pos - 1);

    GdbCommand command;
    command.raw = data;
    command.cmd = std::string(cmd_view);

    if (std::isdigit(cmd_view[1])) {
        command.cmd = cmd_view.substr(0, 1);
    }

    if (std::isdigit(cmd_view[2])) { // e.g. "Hg12345"
        command.cmd = cmd_view.substr(0, 2);
    }

    auto septoken = cmd_view.find_first_of(":;");
    auto maybeNumber = cmd_view.find_first_of("-0123456789");
    if (const size_t pos = std::min(septoken, maybeNumber); pos != std::string::npos) {
        command.cmd = cmd_view.substr(0, pos);
        command.arg = cmd_view.substr(pos + (pos == septoken ? 1 : 0));
    }

    return command;
}

static u8 CalculateChecksum(const std::string& command) {
    u8 sum = 0;
    for (const char c : command) {
        sum += static_cast<uint8_t>(c);
    }
    return sum & 0xFF;
}

std::string GdbStub::MakeResponse(const std::string& response) {
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
}

bool GdbStub::HandleIncomingData(const int client) {
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    const ssize_t bytes = recv(client, buf, sizeof(buf), 0);
    if (bytes == -1 || bytes == 0) {
        return false;
    }

    std::string data(buf, bytes);

    if (data.empty()) {
        return false;
    }

    if (data == "+") {
        // Initial connection acknowledgement
        send(client, "+", 1, 0);
        return true;
    }

    if (data.front() == char(ControlCode::Interrupt)) {
        BREAKPOINT();
    }

    if (data.front() == char(ControlCode::Ack)) {
        data = data.substr(1);
    }

    const std::string reply = MakeResponse(handler(ParsePacket(data)));
    if (reply.empty()) {
        return false;
    }

    LOG_INFO(Debug, "Reply: {}", reply);
    if (send(client, reply.c_str(), reply.size(), 0) == -1) {
        return false;
    }

    return true;
}

bool GdbStub::ReadMemory(const u64 address, const u64 length, std::string* out) {
    const auto mem = Memory::Instance();

    if (!mem->IsValidAddress(reinterpret_cast<void*>(address))) {
        return false;
    }

    for (u64 i = 0; i < length; ++i) {
        *out += fmt::format("{:02x}", *reinterpret_cast<u8*>(address + i));
    }

    return true;
}

// To (supposedly) get thread ID from a pthread_t
pid_t GetTid(const pthread_t ptid) {
    pid_t tid = 0;
    memcpy(&tid, &ptid, std::min(sizeof(tid), sizeof(ptid)));
    return tid;
}

// Modified from xenia a little bit
std::string BuildThreadList() {
    std::string buffer;
    buffer += "l<?xml version=\"1.0\"?>\n<threads>\n";
    for (auto& [name, id, id_enc] : Core::Devtools::GdbData::thread_list()) {
        buffer += fmt::format(R"*(    <thread id="{:x}" name="{}" handle="{:x}"></thread>\n)*",
                              id_enc, name, id_enc);
    }
    buffer += "</threads>";
    return buffer;
}

#include <pthread.h>

auto wwe = DebugState.cctx;
static ThreadID selectedThread = 0;
static ucontext_t selectedCtx = wwe[selectedThread];
static bool vMustReplyEmpty = false; // Empty string on unknown command

std::string NIMPL(std::string c) {
    LOG_WARNING(Debug, "Not implemented: {}", c);
    return std::format("E.Not implemented: {}", c);
}

std::string GdbStub::handler(const GdbCommand& command) {
    LOG_INFO(Debug, "Received data:\n\tRAW: {}\n\tCMD: {}\n\tARG: {}", command.raw, command.cmd,
             command.arg);

    char category = command.cmd[0];

    switch (category) {
    default:
        break;
    case '!':
        return OK;
    case '?': // redo
        return "S05";

    case 'H': // handle threads, -1 all, 0 any
        break;
        // these apply to threads too
        // the problem is, that gdb expects the main thread to be active
        // so i need to figure out how to address GAME_MainThread
    case 'g':
        break; // read general registers
    case 'G':
        break; // write general registers
    case 'm':  // m addr,length read
        break;
    case 'M': // M addr,length:XX write
        break;
    case 'p': // p m reg read
        break;
    case 'P': // P n=x reg write
        break;
    case 'x': // same as m but binary
        break;
    case 'X': // same as M but binary
        break;

        // advanced
    case 'v': // Special, multiletter, until first ; OR until first ? OR until EOS
        return handle_v_packet(command);

    case 'q':
        return handle_q_packet(command);
    case 'Q':
        return handle_Q_packet(command);

    case 'r':
    case 'R':
        return "E.Target reset not allowed";

    case 'z': // insert breakpoint (0-SW, 1-HW, 2-write, 3-read, 4-access)
        break;
    case 'Z': // remove breakpoint
        break;
    }
    return NIMPL(command.cmd);
}

std::string GdbStub::handle_v_packet(const GdbCommand& command) {
    if (command.cmd == "vCont?") {
        LOG_WARNING(Debug, "vCont? probably stubbed");
        return "vCont;s;c;t";
        // supported commands for vCont
        // vCont[;action;...]
    }
    if (command.cmd == "vCont") {
        LOG_WARNING(Debug, "qAttach probably stubbed");
        return OK;
        // vCont[;action[:thread-id]]
        //  c C [sig] s S [sig] t r
    }
    if (command.cmd == "vMustReplyEmpty")
        return "";

    return NIMPL(command.cmd);
}

std::string GdbStub::handle_q_packet(const GdbCommand& command) {
    if (command.cmd == "qAttached") {
        LOG_WARNING(Debug, "qAttach probably stubbed");
        return "1";
    }
    if (command.cmd == "qXfer:features")
        return target_description;
    if (command.cmd == "qXfer:threads")
        return BuildThreadList();
    if (command.cmd == "qfThreadInfo") {
        // send MAIN THREAD!!! m thread-id
    }
    if (command.cmd == "qsThreadInfo") {
        // send remaining threads! m tid,tid.. l (male l - koniec listy)
    }
    if (command.cmd == "qSupported") {
        LOG_WARNING(Debug, "qSupported probably stubbed");
        // save what's supported by the remote
        return "PacketSize=1024;qXfer:features:read+;qXfer:threads:read+;binary-upload+";
    }

    return NIMPL(command.cmd);
}

/*
std::string GdbStub::HandleCommand(const GdbCommand& command) {
    LOG_INFO(Debug, "command.cmd = {} | command.arg = {}", command.cmd, command.raw_data);

    ucontext_t* ctx = &selectedCtx;
    if (selectedThread != 0) {
        selectedCtx = wwe[selectedThread];

        std::string out = "";
        u8 bfr[32];
        memcpy(bfr, ctx->uc_stack.ss_sp - 32, 32);

        for (u8 i = 0; i < 32; i++)
            out += std::format("{:02x} ", bfr[i]);
        LOG_INFO(Debug, "{:x} -> RIP: {:x} -> RDI: {:x} -> RSI: {:x} -> RBP: {:x} -> RBX: {:x}",
                 reinterpret_cast<u64>(selectedThread), ctx->uc_mcontext.gregs[REG_RIP],
                 ctx->uc_mcontext.gregs[REG_RDI], ctx->uc_mcontext.gregs[REG_RSI],
                 ctx->uc_mcontext.gregs[REG_RBP], ctx->uc_mcontext.gregs[REG_RBX]);
        LOG_INFO(Debug, "\t->Stack Dump: {}", out);
    }

    if (const auto it = command_table.find(command.cmd); it != command_table.end()) {
        return it->second();
    }

    LOG_ERROR(Debug, "Unhandled command '{}'", command.cmd);
    return vMustReplyEmpty ? "" : E01;
}*/

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
        /*   case Register::EFLAGS:
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
               break;*/
    default:
        return "00000000000000";
    }

    std::string formatted;
#if defined(__GNUC__)
    formatted = fmt::format("{:016x}", __builtin_bswap64(value));
#elif defined(_MSC_VER)
    formatted = fmt::format("{:016x}", _byteswap_uint64(value));
#else
#error "What the fuck is this compiler"
#endif
    LOG_INFO(Debug, "Endian swapped value of {} is '{}'", magic_enum::enum_name(reg), formatted);
    return formatted;
}

void GdbStub::Run(const std::stop_token& stop) {
    LOG_INFO(Debug, "GDB stub listening on port {}", m_port);

    if (listen(m_socket, 1) == -1) {
        LOG_ERROR(Debug, "Failed to listen on socket ({})", strerror(errno));
        return;
    }

    while (!stop.stop_requested()) {
        sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        const int client =
            accept(m_socket, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
        if (client == -1) {
            LOG_ERROR(Debug, "Failed to accept client ({})", strerror(errno));
            continue;
        }

        LOG_INFO(Debug, "Client {} connected", client);

        while (!stop.stop_requested()) {
            if (!HandleIncomingData(client)) {
                // LOG_ERROR(Debug, "Failed to handle incoming data");
            }
        }
    }
}

} // namespace Core::Devtools
