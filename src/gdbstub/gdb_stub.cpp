// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <format>
#include <iostream>
#include <string>
#include <fmt/xchar.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "common/logging/backend.h"
#include "common/logging/log.h"

#include <pthread.h>
#include <sys/user.h>
#include "common/assert.h"
#include "common/debug.h"
#include "core/debug_state.h"
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_stub.h"
#include "processtools.h"
#include "stubtools.h"
#include "threadinfo.h"

using namespace ::Libraries::Kernel;

namespace Core::Devtools {

constexpr auto OK = "OK";
constexpr auto E01 = "E01";

constexpr char target_description[] = R"(l<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>)";

GdbStub::GdbStub(const u16 port, pid_t target, SharedVector* shared)
    : m_port(port), pid_target(target), pid_self(getpid()) {
    CreateSocket();

    selectedThread = nullptr;
    shd = shared;
}

GdbStub::~GdbStub() {}

void GdbStub::CreateSocket() {
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_MSG(m_socket != -1, "Failed to create socket ({})", strerror(errno));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ASSERT_MSG(bind(m_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != -1,
               "Failed to bind socket ({})", strerror(errno));
    std::cout << "GDB stub listening on port " << m_port << std::endl;
}

GdbStub::GdbCommand GdbStub::ParsePacket(const std::string& data) {
    GdbCommand out;
    out.raw = "";
    out.cmd = "";
    out.arg = "";

    if (data.front() == char(ControlCode::Interrupt)) {
        out.cmd = "\03";
        return out;
    }

    const auto end_pos = data.find(char(ControlCode::PacketEnd));

    if (data[0] != char(ControlCode::PacketStart) || end_pos == std::string::npos) {
        // UNREACHABLE_MSG("Malformed packet: {}", data);
        LOG_ERROR(Debug, "Malformed packet: {}", data);
        return out;
    }

    const std::string_view cmd_view = std::string_view(data).substr(1, end_pos - 1);

    out.raw = data;
    out.cmd = std::string(cmd_view);
    out.arg = "";

    if (cmd_view.length() == 1)
        return out;

    auto septoken = cmd_view.find_first_of(":;");
    auto maybeNumber = cmd_view.find_first_of("-0123456789");
    if (const size_t pos = std::min(septoken, maybeNumber); pos != std::string::npos) {
        out.cmd = cmd_view.substr(0, pos);
        out.arg = cmd_view.substr(pos + (pos == septoken ? 1 : 0));
    }

    return out;
}

static std::string prevMsg;

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
        // Connection acknowledgement
        send(client, "+", 1, 0);
        return true;
    }
    if (data == "-") {
        send(client, prevMsg.c_str(), prevMsg.size(), 0);
        return true;
    }

    if (data.front() == char(ControlCode::Ack)) {
        data = data.substr(1);
    }

    GdbCommand command = ParsePacket(data);
    std::string response = handler(command);
    std::string msg = MakeResponse(response);
    prevMsg = msg;

    LOG_INFO(Debug, "Received data:\n\tRAW: {}\n\tCMD: {}\n\tARG: {}\n\tRESP: {}", command.raw,
             command.cmd, command.arg, response);

    if (msg.empty()) {
        return false;
    }

    if (send(client, msg.c_str(), msg.size(), 0) == -1) {
        return false;
    }

    return true;
}

bool GdbStub::Run() {
    if (GdbData.thread_shared() == nullptr) {
        LOG_ERROR(Debug, "Invalid thread buffer");
        return false;
    }

    if (listen(m_socket, 1) == -1) {
        std::cout << "Failed to listen on socket (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        const int client =
            accept(m_socket, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
        if (client == -1) {
            LOG_ERROR(Debug, "Failed to accept client ({})", strerror(errno));
            continue;
        }

        LOG_INFO(Debug, "Client {} connected", client);
        // BuildThreadList();

        while (true) {
            if (!HandleIncomingData(client)) {
                // LOG_ERROR(Debug, "Failed to handle incoming data");
            }
        }
    }

    close(m_socket);

    LOG_DEBUG(Debug, "Stub exited");
    return true;
}

std::string GdbStub::handler(const GdbCommand& command) {

    if (command.cmd == "qAttached")
        return "1";

    char category = command.cmd[0];

    switch (category) {
    default:
        break;
    case '\03': // pause target
        break;
    case '!':
        // No point of supporting that (change my mind)
        return "";
    case '?':
        /*        for (u16 idx = 0; idx < shd->size; idx++) {
                    struct ThreadInfo* thd = &shd->threads[idx];
                    ptrace(PTRACE_SEIZE, thd->tid, nullptr, nullptr);
                    ptrace(PTRACE_INTERRUPT, thd->tid, nullptr, nullptr);
                    waitpid(thd->tid, nullptr, 0);
                }
                process_stop(shd, pid_target);*/

        return "S05";

    case 'c':
        kill(pid_target, SIGCONT);
        waitpid(pid_target, nullptr, 0);
        return "S09";
        /*for (u16 idx = 0; idx < shd->size; idx++) {
            struct ThreadInfo* thd = &shd->threads[idx];
            ptrace(PTRACE_CONT, thd->tid, nullptr, nullptr);
            waitpid(thd->tid, nullptr, 0);
        }*/

        // if (DebugState.IsGuestThreadsPaused())
        //     DebugState.ResumeGuestThreads();
        // return OK;

    case 'H': // handle threads, -1 all, 0 any
        // return handle_H_packet(command);
        break;
    case 'g':
        return "00000000000000000000000000000000";
        /*{
            struct ThreadInfo* target = getThreadByName(shd, GAME_MAIN_THREAD_NAME);
            struct user_regs_struct regs;
            struct user_fpregs_struct fpregs;
            ptrace(PTRACE_GETREGS, target->tid, nullptr, &regs);
            ptrace(PTRACE_GETFPREGS, target->tid, nullptr, &fpregs);

            LOG_ERROR(Debug, "Dumping thread registers: {} ({:x})", target->name, target->tid);
            return dumpRegistersFromThread(&regs, &fpregs);
        } */
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
              //    return handle_v_packet(command);
        break;

    case 'q':
        //      return handle_q_packet(command);
        break;
    case 'Q':
        //        return handle_Q_packet(command);
        break;

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

// Modified from xenia a little bit
std::string GdbStub::BuildThreadList() {

    std::string buffer;
    buffer += "l<?xml version=\"1.0\"?>\n<threads>\n";
    LOG_WARNING(Debug, "Thread count: {}", shd->size);

    for (u8 i = 0; i < shd->size; i++) {
        struct ThreadInfo* thrd = &shd->threads[i];

        LOG_WARNING(Debug, "\tID: {:x}\tEncID: {:x}\tName: {}", thrd->tid, thrd->tid_enc,
                    std::string(thrd->name));

        buffer += fmt::format("    <thread id=\"{:x}\" name=\"{}\" handle=\"{:x}\"></thread>\n",
                              thrd->tid_enc, std::string(thrd->name), thrd->tid);
    }

    buffer += "</threads>";
    return buffer;
}
std::string GdbStub::dumpRegistersFromThread(struct user_regs_struct* regs,
                                             struct user_fpregs_struct* fpregs) {
    std::string out = "";

    out = out + byteSwap(regs->rax, sizeof(unsigned long long));
    out = out + byteSwap(regs->rcx, sizeof(unsigned long long));
    out = out + byteSwap(regs->rdx, sizeof(unsigned long long));
    out = out + byteSwap(regs->rbx, sizeof(unsigned long long));

    out = out + byteSwap(regs->rsp, sizeof(unsigned long long));
    out = out + byteSwap(regs->rbp, sizeof(unsigned long long));
    out = out + byteSwap(regs->rsi, sizeof(unsigned long long));
    out = out + byteSwap(regs->rdi, sizeof(unsigned long long));
    out = out + byteSwap(regs->rip, sizeof(unsigned long long));

    out = out + byteSwap(regs->eflags, sizeof(unsigned long long));
    out = out + byteSwap(regs->cs, sizeof(unsigned long long));
    out = out + byteSwap(regs->ss, sizeof(unsigned long long));
    out = out + byteSwap(regs->ds, sizeof(unsigned long long));
    out = out + byteSwap(regs->es, sizeof(unsigned long long));
    out = out + byteSwap(regs->fs, sizeof(unsigned long long));
    out = out + byteSwap(regs->gs, sizeof(unsigned long long));

    return out;
}
} // namespace Core::Devtools