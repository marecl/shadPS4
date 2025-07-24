// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <format>
#include <iomanip>
#include <iostream>
#include <regex>
#include <unordered_map>
#include <vector>

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "childtools.h"
#include "common/debug.h"
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "gdb_stub.h"
#include "src/core/memory.h"
#include "stubtools.h"
#include "threadinfo.h"

constexpr const char* OK = "OK";
constexpr const char* E01 = "E01";
constexpr const char* TOUCH_GRASS = "UwU";
constexpr const char* DETACH = "OwO";

// -2 error (yeet), -1 error (continue execution), 0 exit, 1 continue execution
s8 GdbStub::LoopCommand(void) {
    // no other function need to have acces to this,
    // response must be static to retain its value in case if we get
    // a '-' packet (repeat last response)
    static std::string response{};
    static std::string message{};

    if (!this->stub_server->GetMessage(message))
        return 1;

    // Catch the first connection from GDB
    if (!this->client_connected) {
        LOG_INFO(Debug, "Received a connection from GDB. Interrupting all threads...");
        this->predator->ChildThreadInterruptAll();
        this->client_connected = true;
    }

    s8 preprocess_status = Preprocess(message);

    if (preprocess_status == -1) {
        LOG_ERROR(Debug, "Error while receiving packet");
        this->SendMessage(E01);
        return -1;
    }

    if (preprocess_status == 0) {
        // '+' packet, ACK
        this->SendMessage(message, true);
        return 1;
    }
    if (preprocess_status == 2) {
        // '-' packet, repeat last response
        LOG_WARNING(Debug, "Client requested last response: < {} >", response);
        this->SendMessage(response);
        return 1;
    }

    if (preprocess_status != 1) {
        LOG_ERROR(Debug, "This shouldn't happen");
        this->SendMessage(E01);
        return -2;
    }

    GdbCommand cmd = ParsePacket(message);
#ifdef DEBUG_COMM
    LOG_INFO(Debug, "Received data:\n\tRAW: {}\n\tCMD: {}\n\tARG: {}", cmd.raw, cmd.cmd, cmd.arg);
#endif
    s8 open_ended_handler_status = HandleContinuous(cmd);

    if (open_ended_handler_status == -1) {
        LOG_ERROR(Debug, "Some error. Investigate into GdbStub::HandleContinuous");
        this->SendMessage(E01);
        return -1;
    }

    if (open_ended_handler_status == 1) {
        LOG_INFO(Debug, "No response to GDB");
        return 1;
    }

    if (open_ended_handler_status == 0) {
        std::string handler_effect = HandlePacket(cmd);
        if (handler_effect == TOUCH_GRASS) {
            this->SendMessage(OK);
            this->predator->ChildThreadContinueAll();
            return 0;
        }
        if (handler_effect == DETACH) {
            this->SendMessage(OK);
            this->stub_server->RestartSession();
            this->client_connected = false;
            LOG_INFO(Debug, "Client GDB detached itself. Continuing execution...");
            this->predator->ChildThreadContinueAll();
            return 1;
        }

        response = handler_effect;
        this->SendMessage(response);
        return 1;
    }

    return -2;
}

// -2 error (yeet), -1 error (continue execution), 0 exit, 1 continue execution
bool GdbStub::LoopTrace(void) {
    static thread_event_t evt{};

    if (!listener->Poll(evt))
        return 1;

    if (child_thread_exited(evt.status)) {
        LOG_INFO(Debug, "[--] Thread {} exited with code {:02}", evt.tid,
                 child_thread_exit_reason(evt.status));

        std::string thread_exit_notification =
            std::format("W{:02x};process:{:x};", child_thread_exit_reason(evt.status), evt.tid);
        if (!this->SendMessage(thread_exit_notification))
            predator->ChildThreadContinue(evt.tid);

        return 1;
    }

    if (child_thread_killed(evt.status)) {
        LOG_ERROR(Debug, "stub");
        LOG_INFO(Debug, "[__] Thread {} was killed with {:02}", evt.tid,
                 child_thread_kill_reason(evt.status));
        // There's no packet to signal thread being *killed*
        return 1;
    }

    if (!child_thread_stopped(evt.status))
        return 1;

    int stop_reason = child_thread_stop_reason(evt.status);

    // child stopped, update state
    if (thread_state_t* thr = predator->FindThread(evt.tid); thr != nullptr) {
        predator->UpdateRunningState(*thr, stop_reason);
    }

    if (child_thread_sigtrap_is_syscall(evt.status)) {
        LOG_ERROR(Debug, "stub");
        LOG_INFO(Debug, "[*!] Thread {} got SYSCALL SIGTRAP", evt.tid);
        std::string thread_stop_sigtrap_syscall_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_stop_sigtrap_syscall_notification))
            predator->ChildThreadContinue(evt.tid);
    }

    if (stop_reason == SIGSTOP) {
        LOG_INFO(Debug, "[*!] Thread {} got SIGSTOP", evt.tid);
        if (thread_state_t* _ = predator->FindThread(evt.tid); _ == nullptr) {
            // *likely* a child that raised SIGSTOP faster than parent could emit an event
            // push it back and hope it will get resolved by itself
            listener->Place(evt);
            return 1;
        }

        std::string thread_stop_sigstop_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_stop_sigstop_notification))
            predator->ChildThreadContinue(evt.tid);
        return 1;
    }

    if (stop_reason == SIGCONT) {
        // Shouldn't happen anyway
        LOG_INFO(Debug, "[**] Thread {} continuing", evt.tid);
        return 1;
    }

    if (stop_reason == SIGTRAP) {
        LOG_INFO(Debug, "[*!] Thread {} got SIGTRAP", evt.tid);

        if (child_thread_evt_clone(evt.status)) {
            unsigned long new_tid = 0;
            ptrace(PTRACE_GETEVENTMSG, evt.tid, nullptr, &new_tid);
            LOG_INFO(Debug, "[*+] New thread/process: {}", new_tid);

            // Child will sigstop on its own
            thread_event_t clone_evt = listener->Wait();

            this->predator->ThreadRegister(clone_evt.tid, SIGSTOP);
            this->predator->ChildThreadInterruptAll();

            std::string thread_evt_creation_notification =
                std::format("T{:02x}thread:{:x};clone:{:x};", stop_reason, evt.tid, clone_evt.tid);
            if (!this->SendMessage(thread_evt_creation_notification))
                predator->ChildThreadContinueAll();

            //  predator.ChildThreadContinue(evt.tid);
            // predator.ChildThreadContinue(clone_evt.tid);

            return 1;
        }

        if (child_thread_evt_exit(evt.status)) {
            LOG_INFO(Debug, "[*-] Thread {} exits with status {}", evt.tid, evt.status);

            // check if it's main thread and return 0 i think
            this->predator->ThreadRemove(evt.tid);

            std::string thread_evt_exit_notification =
                std::format("w{:02x};{:x}", evt.status,
                            evt.tid); // may need to change status to stop_reason lol
            if (!this->SendMessage(thread_evt_exit_notification))
                this->predator->ChildThreadContinue(evt.tid); // or continue all, idk yet

            return 1;
        }

        // no other events, carry on
        //  predator.ChildThreadContinue(evt.tid);
        return -1; // unknown other event
    }
    if (stop_reason == SIGSEGV) {
        siginfo_t info;

        if (ptrace(PTRACE_GETSIGINFO, evt.tid, 0, &info) != 0)
            return -1;

        // Apparently we DO like this particular kind (Linux only?)
        if (info.si_code == SEGV_ACCERR) {
            this->predator->ChildThreadContinue(evt.tid, SIGSEGV, true);
            return 1;
        }

        std::string thread_sigsegv_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_sigsegv_notification)) {
            this->predator->DumpRegs(evt.tid);
            LOG_ERROR(Debug, "[*] Thread {} got undesired SIGSEGV {:02} at RIP=0x{:X} (:X)",
                      evt.tid, info.si_code, predator->user_regs.rip,
                      predator->user_regs.rip - 0x7FF000000);

            this->predator->ChildThreadContinue(evt.tid, SIGSEGV);
        }
    }

    LOG_INFO(Debug, "[*] Thread {} stopped with signal {:02}", evt.tid, stop_reason);
    std::string thread_stop_other_notification =
        std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
    if (!this->SendMessage(thread_stop_other_notification))
        this->predator->ChildThreadContinue(evt.tid);

    return 1;
}

// -1 fail, 0 wrong handler, 1 - action done, don't continue in Loop
// doesn't return anything to client
s8 GdbStub::HandleContinuous(GdbCommand cmd) {
    char maincmd = cmd.cmd[0];
    if (maincmd == 'c' || maincmd == 'C') {
        LOG_ERROR(Debug, "Stub. Don't implement unless gdb doesn't speak vCont");
        return -1;
    }
    /*
    if (maincmd == 'C') {
        LOG_WARNING(Debug, "stub. basically 'c' with passing on a signal");
    }
    if (maincmd == 'c' || maincmd == 'C') {
        // TODO: throw out somewhere
        LOG_WARNING(Debug, "?? continuation address ?? not implemented yet");
        ThreadID target = this->predator->thread_sel_flow;

        u8 sig = 0; // take from the argument

        // return 1 - if it throws an error, it will make gdb think the program stopped
        if (target == predator->main_thread) {
            predator->ChildThreadContinueAll(sig);
            return 1;
        }
        predator->ChildThreadContinue(target, sig);
        return 1;
    }*/

    if (cmd.cmd == "vCont") {
        handle_packet_vCont(cmd.arg);
        return 1;
    }

    return 0;
}

std::string GdbStub::HandlePacket(GdbCommand cmd) {
    char maincmd = cmd.cmd[0];

    if (maincmd == '?') {
        // this is the "running" half that returns nothing if main thread is running
        LOG_WARNING(Debug, "stub, update stop reason signal,change to T ???and list threads??");
        thread_state_t* target = this->predator->FindThread(0);

        // shouldn't happen lol
        if (target == nullptr)
            return E01;

        if (target->running) {
            LOG_ERROR(Debug, "Child threads didn't stop on GDB attach");
            return E01;
        }

        // in this case signal always means stop, so we can ignore possibility of SIGCONT
        return std::format("T{:02x}", target->signal);
    }
    if (maincmd == 'D') {
        return DETACH;
    }

    if (maincmd == 'k') {
        return TOUCH_GRASS;
    }

    if (maincmd == 'T') {
        u8 cmd_end_idx = cmd.raw.find(static_cast<char>(ControlCode::PacketEnd));
        std::string correct_arg = cmd.raw.substr(2, cmd_end_idx - 2);
        std::cout << cmd.raw << correct_arg << std::endl;
        std::cout.flush();

        ThreadID ttid = std::stoul(correct_arg, nullptr, 16);
        if (thread_state_t* thread = this->predator->FindThread(ttid); thread != nullptr) {
            return OK;
        }
        return "";
    }

    if (maincmd == '\03') {
        // TODO: throw out somewhere
        LOG_WARNING(Debug, "stub. confirm if interrupting an already stopped thread will cause "
                           "ptrace() to throw a fail (even though it's stopped)");

        ThreadID target = this->predator->GetTargetFlowControl();
        // reminder: 0 for main, -1 is all (caught as main), specific for specific
        thread_state_t* target_thread = this->predator->FindThread(target);

        if (target == -1) {
            predator->ChildThreadInterruptAll();
        } else if (target_thread == nullptr) {
            return E01;
        } else {
            predator->ChildThreadInterrupt(target_thread->tid);
        }

        return std::format("T{:02x}thread:{:x};", target_thread->signal, target_thread->tid);
    }

    if (maincmd == 'm') {
        LOG_WARNING(Debug, "Stub. May crash on backtrace in gdb. Check boundaries and stuff");
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
        // apparently regs must be ready by now
        return PrintRegisters(&this->predator->user_regs, &this->predator->user_fpregs);
    }

    if (maincmd == 'p') {
        if (this->predator->user_regs_dirty) {
            this->predator->DumpRegs(this->predator->GetTargetRegDump());
        }
        u16 targetReg = std::stol(cmd.arg, nullptr, 16);

        switch (targetReg) {
        default:
            break;
        case 0x3A:
            return ByteSwap(this->predator->user_regs.fs_base, 16);
        case 0x3B:
            return ByteSwap(this->predator->user_regs.gs_base, 16);
        }
        return "xxxxxxxxxxxxxxxx";
    }

    if (maincmd == 'H') {
        u8 cmd_end_idx = cmd.raw.find(static_cast<char>(ControlCode::PacketEnd));
        std::string correct_arg = cmd.raw.substr(3, cmd_end_idx - 3);

        ThreadID ttid = std::stoul(correct_arg, nullptr, 16);
        ThreadID* threadActionTarget = nullptr;

        char subcmd = cmd.cmd[1];

        if (subcmd == 'g') {
            threadActionTarget = &this->predator->thread_sel_reg_dump;
        }
        if (subcmd == 'c') {
            threadActionTarget = &this->predator->thread_sel_flow;
        }

        if (threadActionTarget != nullptr) {
            if (ttid == 0) {
                *threadActionTarget = this->predator->main_thread;
                LOG_WARNING(Debug, "GDB H[{}] packet -> selected main thread ({})", subcmd,
                            *threadActionTarget);
            } else if (ttid == -1) {
                LOG_WARNING(Debug, "GDB H[{}] packet -> all threads", subcmd);
                *threadActionTarget = -1;
            } else if (this->predator->FindThread(ttid) != nullptr) {
                LOG_WARNING(Debug, "GDB H[{}] packet -> selected thread {}", subcmd, ttid);
                *threadActionTarget = ttid;
            } else {
                LOG_ERROR(Debug, "GDB H[{}] requested nonexistent thread {}", subcmd, ttid);
                return E01;
            }

            // GDB doesn't always call 'g' after changing target thread
            if (subcmd == 'g') {
                this->predator->DumpRegs(this->predator->GetTargetRegDump());
            }

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
            return "vCont;c;C;s;S;t"; // step currently not implemented
        }
        return "";
    }

    if (maincmd == 'q') {
        const std::vector<std::string> argTokens = Split(cmd.arg, ':');

        if (cmd.cmd[1] == 'T') {
            // I think qT packets can be safely ignored
            // Could pose problems if user wants to see the variables though :')
            // Let's make it work first
            // Yes, empty is valid
            return "";
        }
        if (cmd.cmd == "qC") {
            // target disputable, works for now
            return std::format("QC{:x}", this->predator->GetTargetRegDump());
        }
        if (cmd.cmd == "qAttached") {
            return this->client_connected ? "1" : "0";
        }
        if (cmd.cmd == "qSupported") {
            //  - probably necessary in the near future
            // binary-upload+ - unnecessary for now, maybe ever
            std::string resp = "PacketSize=1024;multiprocess-;qXfer:threads:read+;QThreadEvents+;"
                               "vContSupported+;vCont+";
            // just in case i'm far enough to need breakpoints
            if (resp.find("swbreak+"))
                resp += ";swbreak+";
            return resp;
        }

        if (cmd.cmd == "qXfer") {
            if (argTokens[1] == "read") {
                if (argTokens[0] == "threads") {
                    predator->ThreadRefresh();
                    return ThreadList();
                }
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
            }
        }
    }
    LOG_ERROR(Debug, "Not implemented: {}", cmd.cmd);
    return "";
}

void GdbStub::End(int code) {
    SendMessage(std::format("W{:02x}", code));
}

std::string GdbStub::ThreadList() {
    std::string buffer = "";
    buffer += R"*(l<?xml version="1.0"?><threads>)*";

    for (auto [tid, thread_info] : predator->threads) {
        buffer += fmt::format(R"*(<thread id="{:x}" name="{}" handle="{:x}"/>)*", tid,
                              thread_info.name, tid);
    }

    buffer += "</threads>";
    return buffer;
}

// we need this to map user_regs_struct to GDB
// exact order **must** follow GDBs order
// either in gdb/features/i386/64bit-core OR
// see what's the order in `info reg` OR
// `maint print register-groups` with option `set architecture i386:x86-64`
#define X86_64_REG_COUNT 24
const u16 user_reg_size[X86_64_REG_COUNT] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
                                             8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 4};
// registers 0-23
// fs_base - 152
// gs_base - 153
const u16 user_reg_offsets[X86_64_REG_COUNT] = {
    offsetof(struct user_regs_struct, rax), offsetof(struct user_regs_struct, rbx),
    offsetof(struct user_regs_struct, rcx), offsetof(struct user_regs_struct, rdx),
    offsetof(struct user_regs_struct, rsi), offsetof(struct user_regs_struct, rdi),
    offsetof(struct user_regs_struct, rbp), offsetof(struct user_regs_struct, rsp),
    offsetof(struct user_regs_struct, r8),  offsetof(struct user_regs_struct, r9),
    offsetof(struct user_regs_struct, r10), offsetof(struct user_regs_struct, r11),
    offsetof(struct user_regs_struct, r12), offsetof(struct user_regs_struct, r13),
    offsetof(struct user_regs_struct, r14), offsetof(struct user_regs_struct, r15),
    offsetof(struct user_regs_struct, rip), offsetof(struct user_regs_struct, eflags),
    offsetof(struct user_regs_struct, cs),  offsetof(struct user_regs_struct, ss),
    offsetof(struct user_regs_struct, ds),  offsetof(struct user_regs_struct, es),
    offsetof(struct user_regs_struct, fs),  offsetof(struct user_regs_struct, gs)};

std::string GdbStub::PrintRegisters(const struct user_regs_struct* regs,
                                    const struct user_fpregs_struct* fpregs) {
    std::string out{};

    // why map all registers when we have a copy in a known place
    // and thanks to preprocessor we have exact offsets of its members
    const void* base = static_cast<const void*>(regs);
    for (u8 idx = 0; idx < X86_64_REG_COUNT; idx++) {
        u8 reg_size = user_reg_size[idx]; // bytes
        size_t offset = user_reg_offsets[idx];
        u64 buf = 0;
        memcpy(&buf, static_cast<const u8*>(base) + offset, reg_size);
        out = out + ByteSwap(buf, reg_size * 2);
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

bool GdbStub::ReadMemory(const u64 address, const u64 length, std::string* out) {
    //    const auto mem = Core::Memory::Instance();

    //  if (!mem->IsValidAddress(reinterpret_cast<void*>(address))) {
    //      return false;
    // }

    for (u64 i = 0; i < length; ++i) {
        *out += fmt::format("{:02x}", *reinterpret_cast<u8*>(address + i));
    }

    return true;
}

bool GdbStub::SendMessage(std::string message, bool raw_and_mute) {
    if (!this->client_connected)
        return false;

    if (!raw_and_mute) {
#ifdef DEBUG_COMM
        LOG_INFO(Debug, "Sending:\n\tRES: {}", message);
#endif
        message = MakeResponse(message);
    }

    bool send_successful = this->stub_server->SendMessage(message);
    if (!send_successful)
        LOG_ERROR(Debug, "Client disconnected without detaching!");
    return send_successful;
}

void GdbStub::handle_packet_vCont(std::string arg) {
    std::vector<std::string> targets = Split(arg, ';');

    // we assume that 1) one vCont doesn't mix c/s/t packets,
    // and 2) the "general" action is always last
    // latter is meh, unlikely. first one is problematic,
    // as it'd need a list of threads with pending operations
    for (std::string combination : targets) {
        auto sep_idx = combination.find(':');
        char action = combination[0];
        int signal = 0;
        ThreadID target = 0;

        // Example: C13:D3AF;c
        if (combination.length() >= 3 && sep_idx >= 3) {
            // sep_idx not found basically so it'll be bigger than 3
            // length >3 so no problem. right where we want it.
            signal = std::strtol(combination.substr(1, 2).c_str(), nullptr, 16);
        }

        if (sep_idx != std::string::npos) {
            target = std::strtol(combination.substr(sep_idx + 1).c_str(), nullptr, 16);
        }

        thread_state_t* target_thread = this->predator->FindThread(target);

        switch (action) {
        case 'C': ///< Supplies its own code
        case 'c': ///< No code (default: 0)
            if (target == 0)
                predator->ChildThreadContinueAll(signal);
            else
                predator->ChildThreadContinue(target, signal);
            break;
        }
    }
}