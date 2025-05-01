// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <pthread.h>
#include "common/assert.h"
#include "common/debug.h"
#include "core/debug_state.h"
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"
#include "gdb_stub.h"

using namespace ::Libraries::Kernel;

namespace Core::Devtools {

constexpr auto OK = "OK";
constexpr auto E01 = "E01";

static const std::vector<std::tuple<u8, std::string>> GPRegister = {
    {REG_RAX, "RAX"}, {REG_RBX, "RBX"}, {REG_RCX, "RCX"},    {REG_RDX, "RDX"}, {REG_RSI, "RSI"},
    {REG_RDI, "RDI"}, {REG_RBP, "RBP"}, {REG_RSP, "RSP"},    {REG_R8, "R8"},   {REG_R9, "R9"},
    {REG_R10, "R10"}, {REG_R11, "R11"}, {REG_R12, "R12"},    {REG_R13, "R13"}, {REG_R14, "R14"},
    {REG_R15, "R15"}, {REG_RIP, "RIP"}, {REG_EFL, "EFLAGS"},
};

constexpr char target_description[] = R"(l<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>)";

GdbStub::GdbStub(const u16 port) : m_port(port), m_thread(&GdbStub::Run, this) {
    CreateSocket();
    m_thread.detach();

    selectedThread = 0;
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
    const GdbDataType::thread_list_t threads = GdbData.thread_get_list();
    std::string buffer;
    buffer += "l<?xml version=\"1.0\"?>\n<threads>\n";
    for (auto& [name, id, id_enc] : threads) {
        buffer += fmt::format("    <thread id=\"{:x}\" name=\"{}\" handle=\"{:x}\"></thread>\n",
                              id_enc, name, id);
    }
    buffer += "</threads>";
    return buffer;
}

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
        // No point of supporting that (change my mind)
        return "E.Extended mode not supported";
        // return OK;
    case '?':
        /*
         * This is the very first packet to enable gdb stub (allegedly).
         * Reply is the stop reason, so we force a known state,
         * honestly quite characteristic for gdb - pause target.
         * 1) we are 100% sure we're in a known state
         * 2) paused threads dumped their contexts
         * */
        DebugState.PauseGuestThreads();
        return "S0A";

    case 'c':
        if (DebugState.IsGuestThreadsPaused())
            DebugState.ResumeGuestThreads();
        return OK;

    case 'H': // handle threads, -1 all, 0 any
        return handle_H_packet(command);
    // these apply to threads too
    // the problem is, that gdb expects the main thread to be active
    // so i need to figure out how to address GAME_MainThread
    case 'g':
        return dumpRegistersFromThread(selectedThread);
        break; // read general registers
    case 'G':
        break; // write general registers
    case 'm':  // m addr,length read
        break;
    case 'M': // M addr,length:XX write
        break;
    case 'p': // p m reg read
        if (std::stoi(command.arg, NULL, 16) >= 18)
            return "0000000000000000";
        return "0000000000000000";
        // 3A - fs_base
        // 3B - gs_base
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

ThreadID getThreadByName(std::string name) {
    for (GdbDataType::thread_list_item_t& thr : GdbData.thread_get_list()) {
        if (std::get<0>(thr) == name)
            return std::get<1>(thr);
    }
    return 0;
}

ThreadID getThreadHandleFromString(const std::string& data) {
    ThreadID out = std::strtoull(data.c_str(), NULL, 16);

    return out;
}

std::string GdbStub::handle_H_packet(const GdbCommand& command) {
    if (command.cmd.length() < 2)
        return "E.CMDTooShort";

    const char action = command.cmd[1];

    switch (action) {
    case 'c':
        // could be as encoded
        if (command.arg == "-1" || command.arg == "0") {
            selectedThread = getThreadByName(GAME_MAIN_THREAD_NAME);
            LOG_ERROR(Debug, "Main thread selected: {:x}", selectedThread);
            return OK;
        }
        selectedThread = getThreadHandleFromString(command.arg);
        LOG_ERROR(Debug, "Selected thread: {:x}", selectedThread);
        return OK;
    case 'g':
        ThreadID target = 0;
        if (command.arg == "0")
            target = getThreadByName(GAME_MAIN_THREAD_NAME);
        else if (command.arg == "-1")
            target = selectedThread;
        else
            target = GdbData.thread_decode_id(std::stoi(command.arg, NULL, 16));
        if (target == 0) {
            LOG_ERROR(Debug, "Attempting to dump nonexistent thread: {:x}", target);
            return "E.Thread doesn't exist";
        }

        if (DebugState.IsGuestThreadsPaused()) {
            GdbData.thread_resume(target);
            GdbData.thread_pause(target);
        } else {
            GdbData.thread_pause(target);
        }
        GdbData.thread_resume(target);
        LOG_ERROR(Debug, "Dumping thread registers: {} ({:x})",GdbData.getThreadName(target), target);
        return dumpRegistersFromThread(target);
    }

    return NIMPL(command.cmd);
}

// Because they would fall if they raised two

std::string GdbStub::handle_v_packet(const GdbCommand& command) {
    if (command.cmd == "vCont?") {
        // Currently supporting continue, step and stop
        // Additional actions (sig, run to addr) must wait
        return "vCont;s;c;t";
    }
    if (command.cmd == "vCont") {
        char action = command.arg[0];
        switch (action) {
        case 's':
        default:
            LOG_WARNING(Debug, "vCont action {} not implemented ", action);
            break;
        case 'c':
            DebugState.ResumeGuestThreads();
            break;
        case 't':
            DebugState.PauseGuestThreads();
            break;
        }
        return OK;
        // vCont[;action[:thread-id]]
        //  c C [sig] s S [sig] t r
    }
    if (command.cmd == "vMustReplyEmpty")
        return "";

    return NIMPL(command.cmd);
}

// <3
// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
std::vector<std::string> split(const std::string& din, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(din);
    std::string item;

    while (getline(ss, item, delim)) {
        out.push_back(item);
    }

    return out;
}

std::string GdbStub::handle_q_packet(const GdbCommand& command) {

    const std::vector<std::string> argTokens = split(command.arg, ':');

    if (command.cmd == "qAttached") {
        return "1"; // we're always attached
    }
    if (command.cmd == "qTStatus") {
        LOG_WARNING(Debug, "qTStatus probably stubbed");
        // return "T1;tstop:0";
        //  we're not tracing execution. yet.
        //  skip this because it throws an error for some reason
        // return "T0;tnotrun:0";
    }
    if (command.cmd == "qC") {
        return std::format("{:x}", selectedThread);
    }
    if (command.cmd == "qXfer") {

        if (argTokens[1] == "read") {
            if (argTokens[0] == "features") {
                if (argTokens[2] == "target.xml") {
                    return target_description;
                }
            }
            if (argTokens[0] == "threads") {
                return BuildThreadList();
            }
        }
    }
    if (command.cmd == "qfThreadInfo") {
        ThreadID mainThread = getThreadByName(GAME_MAIN_THREAD_NAME);
        u32 mainThreadEncoded = GdbData.thread_encode_id(mainThread);
        return std::format("m {:x}", mainThreadEncoded);
        // send MAIN THREAD!!! m thread-id
    }
    if (command.cmd == "qsThreadInfo") {
        std::string out = "m";
        ThreadID mainThread = getThreadByName(GAME_MAIN_THREAD_NAME); // skip this one
        GdbDataType::thread_list_t list = GdbData.thread_get_list();
        for (const auto& [name, tid, encid] : list) {
            if (tid == mainThread)
                continue;
            out += std::format("{:x},", tid);
        }
        out[out.length() - 1] = 'l';
        return out;
        // send remaining threads! m tid,tid.. l (male l - koniec listy)
    }
    if (command.cmd == "qTfV") {
    }
    if (command.cmd == "qTsV") {
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
#include <format>
#include <string>

std::string byteSwapString(std::string data, u8 width) {
    std::string out = "";
    for (u8 i = 0; i < width; i += 2) {
        out += data[width - i - 2];
        out += data[width - i - 1];
    }
    return out;
}

std::string byteSwap(u64 regval, u8 width = 16) {
    // format string to format string specifying output amount of bytes
    std::string fstr = std::format("{{:0{}x}}", width);
    std::string regValStr = std::vformat(fstr, std::make_format_args((regval)));
    return byteSwapString(regValStr, width);
}

std::string GdbStub::dumpRegistersFromThread(ThreadID threadID) {
    u64 value = 0;

    std::string regs = "";

    ucontext_t ctx = GdbData.thread_get_ctx(threadID);

    // TODO: Is there a way to do this with a custom match function?
    // 64-bit registers
    for (const auto& [regIdx, regName] : GPRegister) {

        u64 regval = ctx.uc_mcontext.gregs[regIdx];

        LOG_INFO(Debug, "Reading reg: {:>10} - {:>2} - {:>20x}", regName, regIdx, regval);

        // LOG_INFO(Debug, "Endian swapped value of {} is '{}'", magic_enum::enum_name(reg),
        //          formatted);
        regs += byteSwap(regval);
    }
    {
        // I think 64-bit registers
        u64 csgsfs = ctx.uc_mcontext.gregs[REG_CSGSFS];
        LOG_INFO(Debug, "Reading reg: REG_CSGSFS - 18 - {:>20x}", csgsfs & 0xFFFFFFFFFFFF0000);
        regs += byteSwap((csgsfs >> 48) & 0xFFFF); // CS
        regs += byteSwap(0);                       // SS
        regs += byteSwap(0);                       // DS
        regs += byteSwap(0);                       // ES
        regs += byteSwap((csgsfs >> 16) & 0xFFFF); // FS
        regs += byteSwap((csgsfs >> 32) & 0xFFFF); // GS
        // regs += byteSwap((spec >>48) &0xFFFF);
    }
    {
        fpregset_t fpregs = ctx.uc_mcontext.fpregs;
        // 80-bit fp registers
        for (u8 i = 0; i < 8; i++) {
            struct _libc_fpxreg fpreg = fpregs->_st[i];
            std::string fpval = "";
            fpval += std::format("{:04x}", fpreg.significand[3]);
            fpval += std::format("{:04x}", fpreg.significand[2]);
            fpval += std::format("{:04x}", fpreg.significand[1]);
            fpval += std::format("{:04x}", fpreg.significand[0]);
            fpval += std::format("{:04x}", fpreg.exponent);
            LOG_INFO(Debug, "Reading reg: {:>10} - {:>2} - {}", "_st", i, fpval);
            regs += byteSwapString(fpval, 20);
        }
    }
    return regs;
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
