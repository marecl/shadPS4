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

#include "breakpoint.h"
#include "childtools.h"
#include "common/debug.h"
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "gdb_registers.h"
#include "gdb_stub.h"
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
        LOG_INFO(Debug, "Received a connection from GDB");
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
            this->stub_server->RestartSession();
            this->client_connected = false;
            this->predator->ChildThreadContinueAll();
            return 0;
        }
        if (handler_effect == DETACH) {
            this->SendMessage(OK);
            this->stub_server->RestartSession();
            this->client_connected = false;
            LOG_INFO(Debug, "Client GDB detached itself");
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
void GdbStub::LoopTrace(void) {
    static thread_event_t evt{};

    if (!listener->Poll(evt))
        return;

    if (child_thread_exited(evt.status)) {
        LOG_INFO(Debug, "[--] EXIT: {} exited with code {:02}", evt.tid,
                 child_thread_exit_reason(evt.status));

        predator->ThreadRemove(evt.tid);
        return;
    }

    if (child_thread_killed(evt.status)) {
        LOG_ERROR(Debug, "untested: child_thread_killed");
        LOG_INFO(Debug, "[__] KILL?: {} was killed with {:02}", evt.tid,
                 child_thread_kill_reason(evt.status));
        // There's no packet to signal thread being *killed*        return;
    }

    if (!child_thread_stopped(evt.status))
        return;

    int stop_reason = child_thread_stop_reason(evt.status);

    // child stopped, update state
    thread_state_t* thread_in_question = predator->FindThread(evt.tid);
    if (thread_in_question != nullptr) {
        predator->UpdateRunningState(*thread_in_question, stop_reason);
    }

    // GDB probably expects regs to be dumped from the calling thread,
    // since the target stopped by itself
    this->predator->DumpRegs(evt.tid);
    this->predator->ThreadRefresh();

    if (child_thread_sigtrap_is_syscall(evt.status)) {
        LOG_ERROR(Debug, "untested: child_thread_sigtrap_is_syscall");
        LOG_INFO(Debug, "[*!] SIGTRAP (SYSCALL): {} ({})", evt.tid, thread_in_question->name);
        std::string thread_stop_sigtrap_syscall_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_stop_sigtrap_syscall_notification))
            predator->ChildThreadContinue(evt.tid);
    }

    if (stop_reason == SIGSTOP) {
        if (thread_in_question == nullptr) {
            LOG_WARNING(Debug, "[*!] {} SIGSTOP-ped earlier than its parent after clone()",
                        evt.tid);
            // *likely* a child that raised SIGSTOP faster than parent could emit an event
            // push it back and hope it will get resolved by itself
            listener->Place(evt);
            return;
        }

        LOG_INFO(Debug, "[*!] SIGSTOP: {} ({})", evt.tid, thread_in_question->name);

        std::string thread_stop_sigstop_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_stop_sigstop_notification))
            predator->ChildThreadContinue(evt.tid);
        return;
    }

    if (stop_reason == SIGCONT) {
        // Shouldn't happen anyway
        LOG_INFO(Debug, "[**] SIGCONT: {}", evt.tid);
        return;
    }

    if (stop_reason == SIGTRAP) {
        std::string thread_evt_notification{};

        // why can't we just stop them all here? (see: evt_clone)
        // also, DON'T MOVE THAT LOWER
        // so far its the only edge case, where threads can't be stopped immediately after entering

        if (child_thread_evt_clone(evt.status)) {
            unsigned long new_tid = 0;
            ptrace(PTRACE_GETEVENTMSG, evt.tid, 0, &new_tid);
            LOG_INFO(Debug, "[*+] SIGTRAP EVENT: {} ({}) created new thread: {}", evt.tid,
                     thread_in_question->name, new_tid);

            // we have to wait for the spawned thread *first* because it emits SIGSTOP
            // and it may or may not happen *before* parent thread stops
            thread_event_t clone_evt = listener->Wait();

            this->predator->ChildThreadInterruptAll();
            this->predator->ThreadRegister(clone_evt.tid, SIGSTOP);

            thread_evt_notification =
                std::format("T{:02x}thread:{:x};clone:{:x};", stop_reason, evt.tid, clone_evt.tid);
        } else
            this->predator->ChildThreadInterruptAll();

        if (child_thread_evt_none(evt.status)) {
            // Upon stopping at 0xCC RIP already points to the next address
            // It's stub's responsibility to correct that
            struct user_regs_struct* bp_regs = &this->predator->user_regs;

            auto bp_rip = bp_regs->rip - 1;
            bp_regs->rip = bp_rip;
            ptrace(PTRACE_SETREGS, evt.tid, 0, bp_regs);

            LOG_INFO(Debug, "[*!] SIGTRAP: {} ({}) caught a breakpoint at 0x{:x}", evt.tid,
                     thread_in_question->name, bp_rip);

            // Find if it was our breakpoint
            if (BreakpointFind_SW(bp_rip) == nullptr)
                LOG_ERROR(Debug, "Breakpoint was not created by user");

            // We also assume SIGTRAP will occur *only* on sw breakpoints
            thread_evt_notification =
                std::format("T{:02x}thread:{:x};swbreak:;", stop_reason, evt.tid);
        }

        if (child_thread_evt_exit(evt.status)) {
            LOG_INFO(Debug, "[*-] SIGTRAP EVENT: {} ({}) exits with status {}", evt.tid,
                     thread_in_question->name, evt.status);

            // data is available to read, but there's no guarantee the thread itself is there
            thread_evt_notification = std::format("w{:x};{:x}", evt.status, evt.tid);
        }

        if (child_thread_evt_fork(evt.status)) {
            LOG_ERROR(Debug, "SIGTRAP EVENT: [not implemented] child_thread_evt_fork");
        }

        if (child_thread_evt_execve(evt.status)) {
            // may need to re-set the PTRACE_O_TRACEEXEC option
            LOG_ERROR(Debug, "SIGTRAP EVENT: [not implemented] child_thread_evt_execve");
        }

        // end of event handlers
        if (thread_evt_notification.empty()) {
            LOG_ERROR(Debug, "unknown or unhandled event. status: {}", evt.status);
            LOG_ERROR(Debug, "program may hang here. i don't care.");
            return;
        }

        if (this->SendMessage(thread_evt_notification))
            return;

        // event happened, not sent so we're not attached. let's go
        this->predator->ChildThreadContinueAll();
        return;
    }

    if (stop_reason == SIGSEGV) {
        siginfo_t info;

        if (ptrace(PTRACE_GETSIGINFO, evt.tid, 0, &info) != 0)
            return;

        // Apparently we DO like this particular kind (Linux only?)
        if (info.si_code == SEGV_ACCERR) {
            this->predator->ChildThreadContinue(evt.tid, SIGSEGV, true);
            return;
        }

        LOG_ERROR(Debug, "[untested] handling SIGSEGV other than SEGV_ACCERR");
        LOG_ERROR(Debug, "[*] Thread {} got undesired SIGSEGV {:02} at RIP=0x{:X} (0x{:X})",
                  evt.tid, info.si_code, predator->user_regs.rip,
                  predator->user_regs.rip - 0x7FF000000);

        std::string thread_sigsegv_notification =
            std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
        if (!this->SendMessage(thread_sigsegv_notification)) {
            this->predator->ChildThreadContinue(evt.tid, SIGSEGV);
        }
        return;
    }

    LOG_INFO(Debug, "[*] Thread {} stopped with signal {:02}", evt.tid, stop_reason);
    std::string thread_stop_other_notification =
        std::format("T{:02x}thread:{:x};", stop_reason, evt.tid);
    if (!this->SendMessage(thread_stop_other_notification))
        this->predator->ChildThreadContinue(evt.tid);
    return;
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
        handle_packet_vCont(cmd);
        return 1;
    }

    return 0;
}

// sometimes parser may interpret letters in arguments
// as parts of the command. i'm lazy and i don't want to
// deal with edge cases, so every command needs to fix itself
void fix(GdbCommand& cmd, u8 argstart) {
    std::string combo = cmd.cmd + cmd.arg;
    cmd.cmd = combo.substr(0, argstart);
    cmd.arg = combo.substr(argstart);
}

std::string GdbStub::HandlePacket(GdbCommand cmd) {
    char maincmd = cmd.cmd[0];

    if (maincmd == '?') {
        thread_state_t* target = this->predator->FindThread(0);

        // shouldn't happen lol
        if (target == nullptr)
            return E01;

        if (target->running) {
            LOG_ERROR(Debug, "Child threads didn't stop on GDB attaching");
            return E01;
        }

        return std::format("T{:02x}", target->signal);
    }

    if (maincmd == 'D') {
        return DETACH;
    }

    if (maincmd == 'k') {
        return TOUCH_GRASS;
    }

    if (maincmd == 'z' || maincmd == 'Z')
        return handle_packet_z(cmd);

    if (maincmd == 'T') {
        fix(cmd, 1);

        ThreadID ttid = std::stoul(cmd.arg, nullptr, 16);
        if (thread_state_t* thread = this->predator->FindThread(ttid); thread != nullptr) {
            return OK;
        }
        return "";
    }

    if (maincmd == '\03') {
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

        this->predator->DumpRegs(this->predator->GetTargetRegDump());
        return std::format("T{:02x}thread:{:x};", target_thread->signal, target_thread->tid);
    }

    if (maincmd == 'm') {
        fix(cmd, 1);
        u8 sepidx = cmd.arg.find(',');
        u64 addr = std::stoull(cmd.raw.substr(2, sepidx), nullptr, 16);
        u64 len = std::stoull(cmd.arg.substr(sepidx + 1), nullptr, 16);
        LOG_INFO(Debug, "GDB m packet read from address 0x{:x} length {}", addr, len);
        std::vector<u8> mem{};
        if (!ReadMemory(this->predator->main_thread, addr, len, mem)) {
            return E01;
        }
        return BytesToString(mem);
    }

    if (maincmd == 'M') {
        fix(cmd, 1);
        u8 comma_idx = cmd.arg.find(',');
        u64 addr = std::stoull(cmd.arg.substr(0, comma_idx), nullptr, 16);
        u64 len = std::stoull(cmd.arg.substr(comma_idx + 1), nullptr, 16);
        u8 semicolon_idx = cmd.arg.find(':');
        std::string data_str = cmd.arg.substr(semicolon_idx + 1);

        LOG_INFO(Debug, "GDB M packet write to address 0x{:x} length {} data ", addr, len,
                 data_str);

        bool ret = WriteMemory(this->predator->main_thread, addr, len, StringToBytes(data_str));
        return ret ? OK : E01;
    }

    if (maincmd == 'g') {
        // should be dumped by 'Hg', '\03' or trace handler (if stopped)
        return PrintRegisters(&this->predator->user_regs, &this->predator->user_fpregs);
    }

    if (maincmd == 'p') {
        // same as 'g'
        u16 target_reg = std::stol(cmd.arg, nullptr, 16);
        u64 reg_value{};
        u16 reg_size{};

        bool reg_correct = RegisterRead(target_reg, &reg_value, &reg_size,
                                        &this->predator->user_regs, &this->predator->user_fpregs);

        if (!reg_correct) {
            LOG_ERROR(Debug, "Requested register {} is unavailable", target_reg);
            std::string _unavailable{};
            for (u8 idx = 0; idx < reg_size; idx++) {
                // ghidra stops regdump when 'x'-unavailable register is sent
                //_unavailable += "xx";
                _unavailable += "00";
            }

            return _unavailable;
        }

        // LOG_ERROR(Debug, "Requested register {} val 0x{:x}", target_reg, reg_value);
        return ByteSwap(reg_value, reg_size * 2);
    }

    if (maincmd == 'H') {
        // assumed 2 characters at all times
        fix(cmd, 2);

        ThreadID ttid = std::stoul(cmd.arg, nullptr, 16);
        ThreadID* threadActionTarget = nullptr;

        char subcmd = cmd.cmd[1];

        if (subcmd == 'g') {
            threadActionTarget = &this->predator->thread_sel_reg_dump;
        }

        if (subcmd == 'c') {
            threadActionTarget = &this->predator->thread_sel_flow;
        }

        if (threadActionTarget == nullptr) {
            LOG_ERROR(Debug, "Cannot parse argument for H packet");
            return E01;
        }

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

        if (subcmd == 'g') {
            this->predator->DumpRegs(this->predator->GetTargetRegDump());
        }

        return OK;
    }

    if (maincmd == 'v') {
        if (cmd.cmd == "vMustReplyEmpty") {
            // all unknown v packets must return the same thing (this)
            return "";
        }
        if (cmd.cmd == "vCont?") {
            // return "vCont;c;C;s;S;t";
            return "vCont;c;C;s;S"; // stop not supported (yet)
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
            std::string resp =
                "PacketSize=1024;multiprocess-;qXfer:threads:read+"; //;QThreadEvents+";
            // just in case i'm far enough to need breakpoints
            // vContSupported+ must be sent by gdb, otherwise no debugging
            if (resp.find("swbreak+"))
                resp += ";swbreak+";
            // not just yet
            // if (resp.find("hwbreak+"))
            //     resp += ";hwbreak+";
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

std::string GdbStub::PrintRegisters(const struct user_regs_struct* regs,
                                    const struct user_fpregs_struct* fpregs) {
    std::string out{};
    u64 reg_val{};
    u16 reg_size{};

    const void* base = static_cast<const void*>(regs);
    for (u8 idx = X86_64_REG_BASE; idx < (X86_64_REG_BASE + X86_64_REG_COUNT); idx++) {
        RegisterRead(idx, &reg_val, &reg_size, regs, fpregs);
        // this register section is *assumed* to be correct at all times
        out = out + ByteSwap(reg_val, reg_size * 2);
    }

    // Uncomment for some insider knowledge

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

    return out;
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

void GdbStub::handle_packet_vCont(GdbCommand cmd) {
    std::string arg = cmd.arg;
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
        default:
            // check vCont? if implementing these
            LOG_ERROR(Debug, "vCont:{} not supported (yet)");
            break;
        case 'C': ///< Supplies its own code
        case 'c': ///< No code (default: 0)
            if (target == 0)
                predator->ChildThreadContinueAll(signal);
            else
                predator->ChildThreadContinue(target, signal);
            break;
        case 'S':
        case 's':
            if (target == 0) {
                LOG_ERROR(Debug, "Didn't know GDB can single-step everything at once :)))");
                break;
            }
            ptrace(PTRACE_SINGLESTEP, target, 0, signal);
            break;
        }
    }
}

std::string GdbStub::handle_packet_z(GdbCommand cmd) {

    LOG_ERROR(Debug, "Stub");
    char maincmd = cmd.cmd[0];
    u8 arglen = cmd.arg.length() + 1;
    char* tmp = new char[arglen]();
    strncpy(tmp, cmd.arg.c_str(), arglen);

    u16 kind = std::strtoul(std::strtok(tmp, ","), nullptr, 16);
    u64 addr = std::strtoull(std::strtok(nullptr, ","), nullptr, 16);
    u16 length = std::strtoul(std::strtok(nullptr, ","), nullptr, 16);

    LOG_ERROR(Debug, "Breakpoint type {} requested at 0x{:x} len:{}", kind, addr, length);

    // 0 - swbreak, 1 - hwbreak, 2 - write watch, 3 - read watch, 4 - address watch
    if (maincmd == 'Z' && kind == 0) {
        thread_state_t* mainthread = this->predator->FindThread(0);
        if (mainthread == nullptr)
            return E01;

        BreakpointSetMainThread(mainthread->tid);
        breakpoint_sw_t* bp = BreakpointAdd_SW(kind, addr, length);

        if (bp == nullptr) {
            LOG_ERROR(Debug, "Cannot add breakpoint at 0x{:x}", addr);
            return E01;
        }

        if (!BreakpointEnable_SW(addr)) {
            LOG_ERROR(Debug, "Error during adding breakpoint at 0x{:x}", addr);
            return E01;
        }

        return OK;
    }

    if (maincmd == 'z' && kind == 0) {
        thread_state_t* mainthread = this->predator->FindThread(0);
        if (mainthread == nullptr)
            return E01;

        BreakpointSetMainThread(mainthread->tid);
        breakpoint_sw_t* bp = BreakpointFind_SW(addr);
        if (bp == nullptr) {
            LOG_ERROR(Debug, "Requested to remove a breakpoint not set by user?! at 0x{:x}", addr);
            // not much we can do
            return OK;
        }

        if (!BreakpointDisable_SW(addr)) {
            LOG_ERROR(Debug, "Error during removing breakpoint at 0x{:x}", addr);
            return E01;
        }

        return OK;
    }

    return "";
}