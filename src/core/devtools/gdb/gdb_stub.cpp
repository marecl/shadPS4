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
    command.cmd = std::string(cmd_view);
    command.raw_data = data;

    if (std::isdigit(cmd_view[1])) {
        command.cmd = cmd_view.substr(0, 1);
        return command;
    }

    if (std::isdigit(cmd_view[2])) { // e.g. "Hg12345"
        command.cmd = cmd_view.substr(0, 2);
        return command;
    }

    if (const size_t pos = cmd_view.find_first_of(":;-"); pos != std::string::npos) {
        command.cmd = cmd_view.substr(0, pos);
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

static std::string MakeResponse(const std::string& response) {
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
}

bool GdbStub::HandleIncomingData(const int client) {
    char buf[1024];
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

    const std::string reply = MakeResponse(HandleCommand(ParsePacket(data)));
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
    buffer += "l<?xml version=\"1.0\"?>\n";
    buffer += "<threads>\n";

    for (auto& [name, id, id_enc] : Core::Devtools::GdbData::thread_list()) {
        buffer += fmt::format(R"*(    <thread id="{:x}" name="{}" handle="{:x}"></thread>)*",
                              id_enc, name, id_enc);
        buffer += '\n';
    }

    buffer += "</threads>";
    return buffer;
}

#include <pthread.h>

auto wwe = DebugState.cctx;
static ThreadID selectedThread = 0;
static ucontext_t selectedCtx = wwe[selectedThread];
static bool vMustReplyEmpty = false; // Empty string on unknown command

std::string GdbStub::HandleCommand(const GdbCommand& command) {
    LOG_INFO(Debug, "command.cmd = {} | command.arg = {}", command.cmd, command.raw_data);

    DebugState.PauseGuestThreads();

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

    static const std::unordered_map<std::string, std::function<std::string()>> command_table{
        {"!", [&] { return OK; }},
        {"?", [&] { return "S05"; }},
        {"Hg0", [&] { return OK; }},
        {"Z",
         [&] {
             // const u64 address = std::stoull(command.raw_data.substr(4, 9), nullptr, 16);
             return OK;
         }},
        {"g",
         [&] {
             std::string regs = "";

             // TODO: Is there a way to do this with a custom match function?
             magic_enum::enum_for_each<Register>([&regs, ctx](auto val) {
                 constexpr Register reg = val;
                 u64 regval = ctx->uc_mcontext.gregs[static_cast<u8>(reg)];

                 LOG_INFO(Debug, "Reading reg: {} - {} - {:x}", magic_enum::enum_name(reg),
                          static_cast<u8>(reg), regval);

                 std::string formatted;
#if defined(__GNUC__)
                 formatted = fmt::format("{:016x}", __builtin_bswap64(regval));
#elif defined(_MSC_VER)
                 formatted = fmt::format("{:016x}", _byteswap_uint64(regval));
#else
#error "What the fuck is this compiler"
#endif
                 LOG_INFO(Debug, "Endian swapped value of {} is '{}'", magic_enum::enum_name(reg),
                          formatted);
                 regs += formatted;
             });

             return regs;
         }},
        {"Hc",
         [&] {
             const auto tid_enc = std::stoull(
                 command.raw_data.substr(3, command.raw_data.find('#') - 3), nullptr, 16);
             // const Pthread* pthr = Core::Devtools::GdbData::thread_decode_id(tid_enc);
             LOG_INFO(Debug, "tid (Hc) = {:x} decoded to ", tid_enc);

             for (auto& [uu1, id, uuu1] : Core::Devtools::GdbData::thread_list()) {
                 if (tid_enc == id)
                     return OK;
             }
             return E01;
         }},
        {"Hg",
         // Select this particular thread
         [&, qq = &selectedThread] {
             const auto tid_enc = std::stoul(
                 command.raw_data.substr(3, command.raw_data.find('#') - 3), nullptr, 16);

             u64 pthr = Core::Devtools::GdbData::thread_decode_id(tid_enc);

             LOG_INFO(Debug, "tid (Hc) = {:x} decoded to {:x}", tid_enc, pthr);

             if (pthr == 0 || pthr == -1)
                 return E01;

             char XD[128];
             pthread_getname_np(pthr, XD, 256);
             std::string thrname = std::string(XD);
             LOG_INFO(Debug, "XDXDXD {} XDXDXD", thrname);

             u64 thread_id = pthr;
             *qq = pthr;

             return OK;
         }},
        {"m",
         [&] -> std::string {
             if (const size_t comma_pos = command.raw_data.find(',');
                 comma_pos != std::string::npos) {
                 const u64 address =
                     std::stoull(command.raw_data.substr(2, comma_pos - 1), nullptr, 16);
                 const u64 length =
                     std::stoull(command.raw_data.substr(comma_pos + 1), nullptr, 16);
                 std::string memory{};

                 if (!ReadMemory(address, length, &memory)) {
                     return E01;
                 }

                 return memory;
             }

             return E01;
         }},
        {"p",
         [&, ctx = &selectedCtx] {
             auto targetReg =
                 std::stoi(command.raw_data.substr(2, command.raw_data.find('#') - 2), nullptr, 16);

             ucontext_t selCtx = *ctx;
             auto regVal = selCtx.uc_mcontext.gregs[targetReg];

             LOG_INFO(Debug, "Reading reg no {} -> {:x}", targetReg, regVal);

             if (targetReg <= 17)
                 return std::format("{:016x}", regVal);

             // if( targetReg<=)

             return std::string("0000000000000000");
         }},
        {"qAttached", [&] { return "1"; }},
        {"qC", [&] { return fmt::format("QC {:x}", gettid()); }},
        {"qSupported",
         [&] { return "PacketSize=1024;qXfer:features:read+;qXfer:threads:read+;binary-upload+"; }},
        {"qTStatus", [&] { return "T1;tnotrun:0"; }},
        // List of
        // ‘QTDV:n:value:builtin:name’
        // Ending with empty string
        {"qTfV", [&] -> std::string { return ""; }},
        {"qTsV", [&] -> std::string { return ""; }},
        {"qTfP", [&] -> std::string { return ""; }},
        {"qTsP", [&] -> std::string { return ""; }},

        {"qXfer",
         [&] -> std::string {
             auto param = command.raw_data;
             if (!param.empty() && param[0] == '$') {
                 param = param.substr(7);
             }

             const auto sub_cmd = param.substr(0, param.find(':'));
             if (sub_cmd == "features") {
                 LOG_INFO(Debug, "qXfer:features");
                 return target_description;
             }
             if (sub_cmd == "threads") {
                 LOG_INFO(Debug, "qXfer:threads");
                 return BuildThreadList();
             }

             LOG_INFO(Debug, "Raw data: '{}'", command.raw_data);
             LOG_INFO(Debug, "Unhandled qXfer subcommand '{}'", sub_cmd);

             return E01;
         }},
        {"qfThreadInfo", // IDA uses this but then decides to use qXfer:threads:read instead
         [&] {
             std::string buffer = "m";

             for (auto& [name, id, id_enc] : GdbData::thread_list()) {
                 LOG_INFO(Debug, "thread_id = {:#16x} encoded to {:#8x})", id, id_enc);
                 buffer += fmt::format("{:#8x},", id_enc);
             }

             // Remove trailing comma
             buffer.pop_back();

             // Specify end of list
             buffer += "l";

             return buffer;
         }},
        {"vCont?", [&] { return "vCont;s;c;t"; }},
        {"vCont", [] { return OK; }},
        {"vMustReplyEmpty",
         [&, tmp = &vMustReplyEmpty] {
             *tmp = true;
             return "";
         }},
        {"x",
         [&] -> std::string {
             if (const size_t comma_pos = command.raw_data.find(',');
                 comma_pos != std::string::npos) {
                 const u64 address =
                     std::stoull(command.raw_data.substr(2, comma_pos - 1), nullptr, 16);
                 const u64 length =
                     std::stoull(command.raw_data.substr(comma_pos + 1, 3), nullptr, 16);
                 std::string memory;

                 LOG_INFO(Debug, "Read addr: {:x} len: {:x}", address, length);

                 if (!ReadMemory(address, length, &memory)) {
                     return E01;
                 }

                 return memory;
             }

             return E01;
         }},
    };

    DebugState.ResumeGuestThreads();

    if (const auto it = command_table.find(command.cmd); it != command_table.end()) {
        return it->second();
    }

    LOG_ERROR(Debug, "Unhandled command '{}'", command.cmd);
    return vMustReplyEmpty ? "" : E01;
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

void GdbStub::Run(const std::stop_token& stop) const {
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
