// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <format>
#include <iomanip>
#include <iostream>
#include <regex>
#include <string>
#include <fmt/xchar.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "childtools.h"
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
#include "stubtools.h"
#include "threadinfo.h"

using namespace ::Libraries::Kernel;

namespace Core::Devtools {

namespace GdbStub {

struct system_state_t g_system_state = {.threads{},
                                        .threads_running{},
                                        .thread_main = static_cast<ThreadID>(-1),
                                        .thread_sel_reg_dump = static_cast<ThreadID>(-1),
                                        .thread_sel_flow = static_cast<ThreadID>(-1),
                                        .user_regs_dirty = true};

constexpr const char* OK = "OK";
constexpr const char* E01 = "E01";
constexpr const char* touch_grass = "UwU";

// -1 fail, 0 N/A, 1 Action done
// doesn't return anything to client
s8 HandleContinuous(GdbCommand cmd) {
    char maincmd = cmd.cmd[0];
    if (maincmd == 'c') {
        LOG_WARNING(Debug, "stub, add SIG argument, check if target(s) is running already, maybe "
                           "add continue address??");
        ThreadID target = g_system_state.thread_sel_flow;
        u8 sig = 0; // take from the argument

        if (target != -1) {
            LOG_ERROR(Debug, "GDB Continuing thread ", target);
            if (!child_continue(target, sig)) {
                LOG_ERROR(Debug, "GDB Can't continue thread {}", target);
            }
            return -1;
        }

        LOG_ERROR(Debug, "Continuing all threads");

        bool wasError = false;
        for (auto [tid, _] : g_system_state.threads) {
            if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
                wasError = true;
                LOG_ERROR(Debug, "GDB Cannot continue thread {}", tid);
            }
        }

        return wasError ? -1 : 1;
    }

    return 0;
}

std::string HandlePacket(GdbCommand cmd) {
    char maincmd = cmd.cmd[0];

    if (maincmd == 'D') {
        LOG_WARNING(Debug, "Detach -- stub");
        return touch_grass;
    }

    if (maincmd == '\03') {
        LOG_WARNING(Debug, "stub");

        int status;
        pid_t waitpid_responder;

        ThreadID target = g_system_state.thread_sel_flow;
        if (target != -1) {
            LOG_ERROR(Debug, "Interrupting thread {}", target);
            if (ptrace(PTRACE_INTERRUPT, target, nullptr, nullptr) == -1) {
                LOG_ERROR(Debug, "GDB Can't stop thread {}", target);
                return E01;
            }
            waitpid_responder = waitpid(target, &status, 0);
            if (waitpid_responder == -1) {
                LOG_ERROR(Debug, "GDB Child can't get interrupted {}", target);
                return E01;
            }
            return "T02";
        }

        // else is omitted, if not selected we want all threads
        LOG_ERROR(Debug, "Interrupting all threads");
        bool wasError = false;
        for (auto [tid, _] : g_system_state.threads) {
            if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) == -1) {
                wasError = true;
                LOG_ERROR(Debug, "GDB Cannot continue thread {}", tid);
            }
        }

        // Detection by elimination lol
        std::vector<ThreadID> stopped_threads_NOT(std::views::keys(g_system_state.threads).begin(),
                                                  std::views::keys(g_system_state.threads).end());
        bool all_stopped = false;
        while (!all_stopped) {
            waitpid_responder = waitpid(-1, &status, __WALL);
            if (waitpid_responder == -1) {
                LOG_ERROR(Debug, "Co do huja nawet nie wiem co to oznacza, nie da sie zaczekac na "
                                 "zjebany proces ktory mial sie przerwac");
                continue;
            }

            if (!child_thread_stopped(status))
                continue;

            if (child_thread_stopped(status)) {
                if (child_thread_stop_reason(status) == (SIGTRAP | 0x80)) {
                    LOG_ERROR(Debug, "[*] Thread {} got SYSCALL SIGTRAP", waitpid_responder);
                } else if (child_thread_stop_reason(status) == SIGTRAP) {
                    LOG_ERROR(Debug, "[*] Thread {} got SIGTRAP", waitpid_responder);
                } else {
                    LOG_ERROR(Debug, "[*] Thread {} stopped with code",
                              child_thread_stop_reason(status));
                    continue;
                }
            }

            if (std::erase(stopped_threads_NOT, waitpid_responder) == 0) {
                LOG_ERROR(Debug, "An untraced child thread did something funky wunky");
            }
            all_stopped = stopped_threads_NOT.empty();
        }

        // normal stop reply packet, same as stops for '?'
        LOG_ERROR(Debug, "All threads stopped");
        return "T02";
        // however...
        // T AA format allows for passing information like
        // breakpoints (sigtrap/user), forks and other events
        // so... basically a wrapper for ptrace.
    }

    if (maincmd == '?') {
        LOG_WARNING(Debug, "stub, update stop reason signal,change to T ???and list threads??");
        return "running"; // g_system_state.running ? "OK" : "T05";
    }

    if (maincmd == 'm') {
        u8 sepidx = cmd.arg.find(',');
        u64 addr = std::stoull(cmd.arg.substr(0, sepidx), nullptr, 16);
        u64 len = std::stoull(cmd.arg.substr(sepidx + 1), nullptr, 16);
        LOG_INFO(Debug, "GDB m packet read from address 0x{:x} length {}", addr, len);
        std::string mem{};
        if (!ReadMemory(addr, len, &mem)) {
            return E01;
        }
        return mem;
    }

    if (maincmd == 'g') {
        ThreadID target = g_system_state.thread_sel_reg_dump;

        struct user_regs_struct* regs = &g_system_state.user_regs;
        struct user_fpregs_struct* fpregs = &g_system_state.user_fpregs;
        if (!child_thread_dump_regs(target, regs, fpregs)) {
            LOG_ERROR(Debug, "GDB Can't read registers of thread {}", target);
            return E01;
        }
        g_system_state.user_regs_dirty = false;
        return PrintRegisters(regs, fpregs);
    }

    if (maincmd == 'p') {
        if (g_system_state.user_regs_dirty) {
            // didn't send Hg packet to switch threads
            // or (idk) ran the target (TODO)
            LOG_ERROR(Debug, "GDB didn't refresh registers after changing target/running thread");
            return "xxxxxxxxxxxxxxxx";
        }
        u16 targetReg = std::stol(cmd.arg, nullptr, 16);

        switch (targetReg) {
        default:
            break;
        case 0x3A:
            return byteSwap(g_system_state.user_regs.fs_base, 16);
        case 0x3B:
            return byteSwap(g_system_state.user_regs.gs_base, 16);
        }
        return "xxxxxxxxxxxxxxxx";
    }

    if (maincmd == 'H') {
        ThreadID ttid = std::stoul(cmd.arg, nullptr, 16);
        ThreadID* threadActionTarget = nullptr;

        char subcmd = cmd.cmd[1];

        if (subcmd == 'g') {
            threadActionTarget = &g_system_state.thread_sel_reg_dump;
        }
        if (subcmd == 'c') {
            threadActionTarget = &g_system_state.thread_sel_flow;
        }

        if (threadActionTarget != nullptr) {
            if (ttid == 0) {
                *threadActionTarget = g_system_state.thread_main;
                LOG_WARNING(Debug, "GDB H[{}] packet -> selected main thread ({})", subcmd,
                            *threadActionTarget);
            } else if (ttid == -1) {
                LOG_WARNING(Debug, "GDB H[{}] packet -> all threads", subcmd);
                *threadActionTarget = -1;
            } else if (g_system_state.threads.find(ttid) != g_system_state.threads.end()) {
                LOG_WARNING(Debug, "GDB H[{}] packet -> selected thread {}", subcmd, ttid);
                *threadActionTarget = ttid;
            } else {
                LOG_ERROR(Debug, "GDB H[{}] requested nonexistent PID:{}", subcmd, ttid);
                return E01;
            }
            g_system_state.user_regs_dirty = true;
            return OK;
        }
        LOG_ERROR(Debug, "Cannot parse argument for H packet");
        return E01;
    }

    if (maincmd == 'v') {
        if (cmd.cmd == "vMustReplyEmpty") {
            // all unknown v packets must return the same thing (this)
            return "";
        }
        if (cmd.cmd == "vCont?") {
            // return "vCont;s;c;t";
            return "vCont;c;t"; // step currently not implemented
        }
        return "";
    }

    if (maincmd == 'q') {
        const std::vector<std::string> argTokens = split(cmd.arg, ':');

        if (cmd.cmd[1] == 'T') {
            // I think qT packets can be safely ignored
            // Could pose problems if user wants to see the variables though :')
            // Let's make it work first
            // Yes, empty is valid
            return "";
        }
        if (cmd.cmd == "qC") {
            // target disputable, works for now
            return std::format("QC{:x}", g_system_state.thread_sel_reg_dump);
        }
        if (cmd.cmd == "qAttached") {
            return "1";
        }
        if (cmd.cmd == "qSupported") {
            // QThreadEvents+ces
            std::string resp = "PacketSize=1024;multiprocess-;qXfer:threads:read+;binary-upload+";
            if (resp.find("swbreak+"))
                resp += ";swbreak+";
            return resp;
        }

        if (cmd.cmd == "qXfer") {
            if (argTokens[1] == "read") {
                // keep this commented
                // for now we use builtin i386:x86-64 definition, unless specified by PS4 arch
                // (user must specify this in local config to take effect, otherwise gdb assumes
                // it's i386)
                /*
                if (argTokens[0] == "features") {
                    if (argTokens[2] == "target.xml") {
                        ;
                    }
                }*/
                if (argTokens[0] == "threads") {
                    return ThreadList();
                }
            }
        }
    }
    LOG_ERROR(Debug, "Not implemented: {}", cmd.cmd);
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
    // compressed response
    // std::string cpr{};
    // cpr = std::regex_replace(response, std::regex("0000"), "0* ");
    // return "+$" + cpr + "#" + fmt::format("{:02X}", CalculateChecksum(cpr));

    // regular response
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
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
        std::string thrName = child_thread_name(tid);
        name = thrName;
        if (tid == g_system_state.thread_sel_reg_dump)
            thrfnd = true;
    }
    if (!thrfnd)
        g_system_state.thread_sel_reg_dump = g_system_state.thread_main;
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

bool ReadMemory(const u64 address, const u64 length, std::string* out) {
    // const auto mem = Memory::Instance();

    // if (!mem->IsValidAddress(reinterpret_cast<void*>(address))) {
    //     return false;
    // }

    for (u64 i = 0; i < length; ++i) {
        *out += fmt::format("{:02x}", *reinterpret_cast<u8*>(address + i));
    }

    return true;
}

// we need this to map user_regs_struct to GDB
#define X86_64_REG_COUNT 24
const u16 user_reg_size[X86_64_REG_COUNT] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
                                             8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4};
const u16 user_reg_offsets[X86_64_REG_COUNT] = {offsetof(struct user_regs_struct, rax),
                                                offsetof(struct user_regs_struct, rbx),
                                                offsetof(struct user_regs_struct, rcx),
                                                offsetof(struct user_regs_struct, rdx),
                                                offsetof(struct user_regs_struct, rsi),
                                                offsetof(struct user_regs_struct, rdi),
                                                offsetof(struct user_regs_struct, rbp),
                                                offsetof(struct user_regs_struct, rsp),
                                                offsetof(struct user_regs_struct, r8),
                                                offsetof(struct user_regs_struct, r9),
                                                offsetof(struct user_regs_struct, r10),
                                                offsetof(struct user_regs_struct, r11),
                                                offsetof(struct user_regs_struct, r12),
                                                offsetof(struct user_regs_struct, r13),
                                                offsetof(struct user_regs_struct, r14),
                                                offsetof(struct user_regs_struct, r15),
                                                offsetof(struct user_regs_struct, rip),
                                                offsetof(struct user_regs_struct, eflags),
                                                offsetof(struct user_regs_struct, cs),
                                                offsetof(struct user_regs_struct, ss),
                                                offsetof(struct user_regs_struct, ds),
                                                offsetof(struct user_regs_struct, es),
                                                offsetof(struct user_regs_struct, fs),
                                                offsetof(struct user_regs_struct, gs)

};

std::string PrintRegisters(const struct user_regs_struct* regs,
                                    const struct user_fpregs_struct* fpregs) {

    std::string out = "";

    const void* base = static_cast<const void*>(regs);
    for (u8 idx = 0; idx < X86_64_REG_COUNT; idx++) {
        u8 reg_size = user_reg_size[idx]; // bytes
        size_t offset = user_reg_offsets[idx];
        u64 buf = 0;
        memcpy(&buf, static_cast<const u8*>(base) + offset, reg_size);
        out = out + byteSwap(buf, reg_size * 2);
    }

    // Uncomment for some insider knowledge
    /*
    LOG_INFO(Debug, "RAX\t{:016x}", regs->rax);
    LOG_INFO(Debug, "RBX\t{:016x}", regs->rbx);
    LOG_INFO(Debug, "RCX\t{:016x}", regs->rcx);
    LOG_INFO(Debug, "RDX\t{:016x}", regs->rdx);
    LOG_INFO(Debug, "RSI\t{:016x}", regs->rsi);
    LOG_INFO(Debug, "RDI\t{:016x}", regs->rdi);
    LOG_INFO(Debug, "RBP\t{:016x}", regs->rbp); // pointer
    LOG_INFO(Debug, "RSP\t{:016x}", regs->rsp); // pointer
    LOG_INFO(Debug, "R8\t{:016x}", regs->r8);
    LOG_INFO(Debug, "R9\t{:016x}", regs->r9);
    LOG_INFO(Debug, "R10\t{:016x}", regs->r10);
    LOG_INFO(Debug, "R11\t{:016x}", regs->r11);
    LOG_INFO(Debug, "R12\t{:016x}", regs->r12);
    LOG_INFO(Debug, "R13\t{:016x}", regs->r13);
    LOG_INFO(Debug, "R14\t{:016x}", regs->r14);
    LOG_INFO(Debug, "R15\t{:016x}", regs->r15);
    LOG_INFO(Debug, "RIP\t{:016x}", regs->rip); // pointer
    LOG_INFO(Debug, "EFLAGS\t{:08x}", regs->eflags);
    LOG_INFO(Debug, "CS\t{:08x}", regs->cs);
    LOG_INFO(Debug, "SS\t{:08x}", regs->ss);
    LOG_INFO(Debug, "DS\t{:08x}", regs->ds);
    LOG_INFO(Debug, "ES\t{:08x}", regs->es);
    LOG_INFO(Debug, "FS\t{:08x}", regs->fs);
    LOG_INFO(Debug, "FSBASE\t{:016x}", regs->fs_base);
    LOG_INFO(Debug, "GS\t{:08x}", regs->gs);
    LOG_INFO(Debug, "GSBASE\t{:016x}", regs->gs_base);
    */

    return out;
}

} // namespace GdbStub

} // namespace Core::Devtools
