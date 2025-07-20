// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <format>
#include <iostream>
#include <string>
#include <fmt/xchar.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "common/assert.h"
#include "common/debug.h"
#include "common/logging/backend.h"
#include "common/logging/log.h"
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

namespace GdbStub {

struct system_state_t g_system_state = {.running = false,
                                        .thread_main = static_cast<ThreadID>(-1),
                                        .thread_selected = static_cast<ThreadID>(-1)};

constexpr auto OK = "OK";
constexpr auto E01 = "E01";

std::string HandlePacket(GdbCommand cmd) {
    if (cmd.cmd[0] == '?') {
        return "S05";
    }

    if (cmd.cmd[0] == 'H') {
        if (cmd.cmd == "Hg") {
            // for (auto [tid, name] : g_system_state.threads) {
            //     LOG_WARNING(Debug, "{}\t{}", tid, name);
            // }

            ThreadID ttid = std::stoul(cmd.arg, nullptr, 16);
            // could be different but may work for now (I think)
            if (ttid == 0) {
                g_system_state.thread_selected = g_system_state.thread_main;
            } else if (g_system_state.threads.find(ttid) != g_system_state.threads.end()) {
                g_system_state.thread_selected = ttid;
            } else {
                LOG_ERROR(Debug, "GDB requested nonexistent PID:{}", ttid);
                return E01;
            }
            LOG_INFO(Debug, "Selected thread: {}", g_system_state.thread_selected);

            return OK;
        }
    }

    if (cmd.cmd[0] == 'v') {
        if (cmd.cmd == "vMustReplyEmpty") {
            // all unknown v packets must return the same thing (this)
            return "";
        }
        if (cmd.cmd == "vCont?") {
            return "vCont;s;c;t";
        }
        return "";
    }

    if (cmd.cmd[0] == 'q') {
        const std::vector<std::string> argTokens = split(cmd.arg, ':');
        if (cmd.cmd == "qC") {
            return std::format("QC{:x}", g_system_state.thread_selected);
        }
        if (cmd.cmd == "qAttached") {
            return "1";
        }
        if (cmd.cmd == "qSupported") {
            std::string resp = "PacketSize=1024;multiprocess-;qXfer:features:read+;qXfer:threads:"
                               "read+;binary-upload+";
            if (resp.find("swbreak+"))
                resp += "swbreak+";
            return resp;
        }

        if (cmd.cmd == "qXfer") {
            if (argTokens[1] == "read") {
                if (argTokens[0] == "features") {
                    if (argTokens[2] == "target.xml") {
                        return R"(l<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>)";
                    }
                }
                if (argTokens[0] == "threads") {
                    return ThreadList();
                    LOG_WARNING(Debug, "Stub");
                }
            }
        }
    }
    return E01;
}

/*
Arg: input from GDB
Ret:
-1 error
0 return input directly to sender
1 pass on for processing
2 repeat last response
*/
s8 Preprocess(std::string& data) {

    if (data.empty())
        return -1;

    if (data == "+") {
        return 0;
    }

    if (data == "\03") {
        return 1;
    }
    if (data == "-") {
        return 2;
    }

    if (data.front() == char(ControlCode::Ack)) {
        data = data.substr(1);
    }

    return 1;
}

GdbCommand ParsePacket(const std::string data) {
    GdbCommand out;
    out.raw = "";
    out.cmd = "";
    out.arg = "";

    if (data.front() == char(ControlCode::Interrupt)) {
        out.cmd = "\03";
        out.raw = "\03";
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
std::string MakeResponse(const std::string response) {
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
}

std::string ThreadGetName(ThreadID tid) {
    // pthread can't pull out name if it belongs to other process
    // just... really?
    // pthread_getname_np(tid, buf, 16);

    std::ifstream commFile(std::format("/proc/{}/comm", tid));
    if (!commFile.is_open()) {
        return {};
    }
    std::string name;
    std::getline(commFile, name);
    return name;
}

void ThreadRegister(ThreadID tid) {
    // Give it a temporary name
    g_system_state.threads[tid] = std::format("Thr{}", tid);
}
void ThreadUnregister(ThreadID tid) {
    if (g_system_state.thread_main == tid) {
        LOG_WARNING(Debug, "Main thread unregistered: {}", tid);
        g_system_state.thread_main = -1;
    }
    g_system_state.threads.erase(tid);
}

void ThreadRefresh(void) {
    bool thrfnd = false;
    for (auto& [tid, name] : g_system_state.threads) {
        std::string thrName = ThreadGetName(tid);
        name = thrName;
        if (tid == g_system_state.thread_selected)
            thrfnd = true;
    }
    if (!thrfnd)
        g_system_state.thread_selected = g_system_state.thread_main;
}

std::string ThreadList() {
    ThreadRefresh();
    std::string buffer = "";
    buffer += R"*(l<?xml version="1.0"?><threads>)*";

    for (auto& [tid, name] : g_system_state.threads) {
        buffer += fmt::format(R"*(<thread id="{:x}" name="{}" handle="{:x}"/>)*", tid, name, tid);
    }

    buffer += "</threads>";
    return buffer;
}

} // namespace GdbStub

} // namespace Core::Devtools

/*
constexpr auto OK = "OK";
constexpr auto E01 = "E01";

constexpr char target_description[] = R"(l<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
</target>)";

static std::string prevMsg;

bool GdbStub2::HandleIncomingData(const int client) {

    //  if (data.empty()) {
    //       return false;
    //  }
    std::string data;
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

    GdbCommand command = GdbCommand(); // ParsePacket(data);
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

bool GdbStub2::Run() {

    // HandleIncomingData(client);
    return false;
}

std::string GdbStub2::handler(const GdbCommand& command) {

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
               for (u16 idx = 0; idx < shd->size; idx++) {
                    struct ThreadInfo* thd = &shd->threads[idx];
                    ptrace(PTRACE_SEIZE, thd->tid, nullptr, nullptr);
                    ptrace(PTRACE_INTERRUPT, thd->tid, nullptr, nullptr);
                    waitpid(thd->tid, nullptr, 0);
                }
                process_stop(shd, pid_target);

        return "S05";

    case 'c':
        // kill(target_pid, SIGCONT);
        // waitpid(target_pid, nullptr, 0);
        return "S09";
        for (u16 idx = 0; idx < shd->size; idx++) {
            struct ThreadInfo* thd = &shd->threads[idx];
            ptrace(PTRACE_CONT, thd->tid, nullptr, nullptr);
            waitpid(thd->tid, nullptr, 0);
        }

        // if (DebugState.IsGuestThreadsPaused())
        //     DebugState.ResumeGuestThreads();
        // return OK;

    case 'H': // handle threads, -1 all, 0 any
        // return handle_H_packet(command);
        break;
    case 'g':
        return "00000000000000000000000000000000";
        {
            struct ThreadInfo* target = getThreadByName(shd, GAME_MAIN_THREAD_NAME);
            struct user_regs_struct regs;
            struct user_fpregs_struct fpregs;
            ptrace(PTRACE_GETREGS, target->tid, nullptr, &regs);
            ptrace(PTRACE_GETFPREGS, target->tid, nullptr, &fpregs);

            LOG_ERROR(Debug, "Dumping thread registers: {} ({:x})", target->name, target->tid);
            return dumpRegistersFromThread(&regs, &fpregs);
        }
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
std::string GdbStub2::ThreadList() {

    std::string buffer;
    buffer += "l<?xml version=\"1.0\"?>\n<threads>\n";
    LOG_WARNING(Debug, "Stub");

    buffer += "</threads>";
    return buffer;
}
std::string GdbStub2::dumpRegistersFromThread(struct user_regs_struct* regs,
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
*/