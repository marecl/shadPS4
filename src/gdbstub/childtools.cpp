// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <fstream>
#include <unordered_map>

#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "childtools.h"
#include "common/logging/log.h"
#include "common/types.h"
#include "threadinfo.h"

#define SIGTRAP_SYSCALL (SIGTRAP | 0x80)

// remember to waitpid()!!!
// we assume thread is stopped on a SIGTRAP/SIGSTOP already (new child)
bool Predator::ChildThreadHijack(ThreadID target) {
    return -1 != ptrace(PTRACE_SEIZE, target, NULL,
                        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
}

void Predator::ChildThreadRegister(ThreadID target, int signal) {
    thread_state_t new_thread = {.tid = target,
                                 .name = std::format("Thr{}", target), ///< Temporary name
                                 .signal = signal};
    new_thread.running = (signal == SIGCONT); ///< Only this one allows execution
    new_thread.name.reserve(20);
    this->threads[target] = new_thread;
}

bool Predator::ChildThreadContinue(ThreadID target, int signal) {
    thread_state_t* thread = this->FindThread(target);
    if (thread == nullptr) {
        return false;
    }

    if (!thread->running) {
        if (ptrace(PTRACE_CONT, target, NULL, signal) == -1) {
            return false;
        }
    }

    thread->running = true;
    thread->signal = SIGCONT;
    return true;
}

ThreadID Predator::Wait(ThreadID target, int* status, int options) {
    ThreadID receiver = waitpid(target, status, options);
    return receiver;
}

u8 Predator::IsRunning(ThreadID target) {
    thread_state_t* thread = this->FindThread(target);
    if (thread == nullptr)
        return -1;

    return thread->running ? 1 : 0;
}

bool Predator::ChildThreadInterrupt(ThreadID target) {
    if (ptrace(PTRACE_INTERRUPT, target, NULL, signal) == -1)
        return false;

    int status{};
    if (!this->Wait(target, &status, 0))
        return false;

    if (!child_thread_stopped(status) && (child_thread_stop_reason(status) != SIGTRAP))
        return false;

    thread_state_t* thread = &this->threads[target];
    thread->running = false;
    thread->signal = SIGTRAP;
    return true;
}

bool Predator::ChildThreadRemove(ThreadID target) {
    // errors if no or multiple children are removed
    // shouldn't happen though
    if (target == this->_main_thread) {
        LOG_WARNING(Debug, "Main thread unregistered!");
        LOG_ERROR(Debug, "Consider killing the child");
    }
    return this->threads.erase(target) == 1;
}

bool Predator::DumpRegs(ThreadID target) {
    if (this->IsRunning(target))
        return false;

    if (ptrace(PTRACE_GETREGS, target, nullptr, &this->user_regs) == -1) {
        return false;
    }
    if (ptrace(PTRACE_GETFPREGS, target, nullptr, &this->user_fpregs) == -1) {
        return false;
    }
    this->user_regs_dirty = false;

    return true;
}

std::string Predator::ThreadName(ThreadID target) {
    // pthread can't pull out name if it belongs to other process
    // just... really?
    // pthread_getname_np(target, buf, 16);

    std::ifstream thread_name_file_unix(std::format("/proc/{}/comm", target));
    if (!thread_name_file_unix.is_open()) {
        return {};
    }
    std::string name;
    std::getline(thread_name_file_unix, name);
    return name;
}

void Predator::ThreadRefresh(void) {
    bool reg_dump_target_found = false;
    bool flow_ctrl_target_found = false;
    for (auto& [tid, info] : this->threads) {
        std::string thrName = this->ThreadName(tid);
        info.name = thrName;

        if (tid == this->thread_sel_reg_dump)
            reg_dump_target_found = true;
        if (tid == this->thread_sel_flow)
            flow_ctrl_target_found = true;
    }

    if (!reg_dump_target_found) {
        LOG_ERROR(Debug, "Stub didn't notice disappearing thread {}", this->thread_sel_reg_dump);
        this->thread_sel_reg_dump = this->_main_thread;
    }
    if (!flow_ctrl_target_found) {
        LOG_ERROR(Debug, "Stub didn't notice disappearing thread {}", this->thread_sel_flow);
        this->thread_sel_flow = this->_main_thread;
    }
}

void Predator::RegDumpInvalidate() {
    this->user_regs_dirty = true;
}

thread_state_t* Predator::FindThread(ThreadID target) {
    auto thread_found = this->threads.find(target);
    if (thread_found == this->threads.end())
        return nullptr;
    return &thread_found->second;
}

bool child_thread_stopped(int status) {
    return WIFSTOPPED(status);
}

int child_thread_stop_reason(int status) {
    return WSTOPSIG(status);
}

bool child_thread_exited(int status) {
    return WIFEXITED(status);
}

int child_thread_exit_reason(int status) {
    return WEXITSTATUS(status);
}

bool child_thread_killed(int status) {
    return WIFSIGNALED(status);
}

int child_thread_kill_reason(int status) {
    return WTERMSIG(status);
}

bool child_thread_evt_clone(int status) {
    return status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8));
}

bool child_thread_evt_exit(int status) {
    return status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8));
}

bool child_thread_sigtrap_is_syscall(int status) {
    return status >> 8 == SIGTRAP_SYSCALL;
}
