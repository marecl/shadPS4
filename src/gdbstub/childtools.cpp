// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <fstream>
#include <iostream>
#include <ranges>
#include <string>
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

static std::string decerrno(void) {
    switch (errno) {
    default:
        return "EXD";
    case EBUSY:
        return "EBUSY";
    case EFAULT:
        return "EFAULT";
    case EINVAL:
        return "EINVAL";
    case EIO:
        return "EIO";
    case EPERM:
        return "EPERM";
    case ESRCH:
        return "ESRCH";
    }
}

// remember to Wait()!!!
// we assume thread is stopped on a SIGTRAP/SIGSTOP already (new child)
bool Predator::ChildThreadHijack(ThreadID target) {
    return -1 != ptrace(PTRACE_SEIZE, target, NULL,
                        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
}

void Predator::ChildThreadRegister(ThreadID target, int signal) {
    thread_state_t new_thread = {.tid = target,
                                 .name = std::format("Thr{}", target), ///< Temporary name
                                 .signal = signal};
    new_thread.running = (signal == 0 || signal == SIGCONT);
    new_thread.name.reserve(20);
    this->threads[target] = new_thread;
}

bool Predator::ChildThreadContinue(ThreadID target, int signal,
                                   bool just_shut_the_fuck_up_about_the_segfaults_please) {
    this->RegDumpInvalidate();

    // this will throw a lot of lines into terminal
    // only because (ask devs why the game throws segfaults)
    // TODO: DON'T
    if (!just_shut_the_fuck_up_about_the_segfaults_please)
        LOG_ERROR(Debug, "[+--] Continuing child {}", target);

    thread_state_t* thread = this->FindThread(target);

    if (thread == nullptr) {
        // Unknown thread, very possible that a child caught SIGSTOP before
        // parent thread could raise an event
        LOG_ERROR(Debug, "[!] Surprise motherfucker {}", target);
        ptrace(PTRACE_CONT, target, NULL, signal);
        return true;
    }

    if (!thread->running) {
        if (ptrace(PTRACE_CONT, target, NULL, signal) == -1) {
            LOG_ERROR(Debug, "[!] Can't continue child {} {}", target, decerrno());
            return false;
        }
    } else {
        LOG_ERROR(Debug, "[!] Continuing running child {}", target);
        return false;
    }
    thread->running = (signal == 0 || signal == SIGCONT);
    thread->signal = (signal == SIGCONT) ? 0 : signal;

    return true;
}

bool Predator::ChildThreadContinueAll(int signal) {
    this->RegDumpInvalidate();

    bool was_error = false;
    for (auto& [tid, state] : this->threads) {
        // LOG_ERROR(Debug, "[+++] Continuing child {}", tid);

        if (!state.running) {
            if (ptrace(PTRACE_CONT, tid, NULL, signal) == -1) {
                was_error = true;
                LOG_ERROR(Debug, "[!] Can't continue child {} {}", tid, decerrno());
            }
        } else {
            was_error = true;
            LOG_ERROR(Debug, "[!] Continuing running child {}", tid);
        }

        state.running = (signal == 0 || signal == SIGCONT);
        state.signal = (signal == SIGCONT) ? 0 : signal;
    }

    return !was_error;
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
    LOG_INFO(Debug, "Interrupting thread {}", target);
    thread_state_t* thread_info = this->FindThread(target);
    if (thread_info->running) {
        if (int ret = ptrace(PTRACE_INTERRUPT, target, NULL, 0); ret == -1)
            LOG_ERROR(Debug, "[!] Can't interrupt child {} {}", target, decerrno());
        return false;
    }

    thread_event_t evt = listener->Wait();

    if (evt.tid != target) {
        LOG_ERROR(Debug, "[!] Response from wrong thread {} != {}", target, evt.tid);
        return false;
    }

    if (child_thread_exited(evt.status) || child_thread_killed(evt.status)) {
        LOG_ERROR(Debug, "[!] Thread {} disappeared before interrupting", evt.tid);
        return false;
    }

    if (child_thread_stopped(evt.status) && child_thread_stop_reason(evt.status) == SIGSTOP) {
        LOG_INFO(Debug, "[!] Thread {} interrupted successfully", evt.tid);
        thread_state_t* target_thread = this->FindThread(evt.tid);
        target_thread->running = false;
        target_thread->signal = SIGINT;
        return true;
    }

    return false;
}

bool Predator::ChildThreadInterruptAll(void) {
    std::vector<ThreadID> target_threads{};

    LOG_INFO(Debug, "Interrupting {} thread(s)", this->threads.size());
    for (auto [tid, info] : this->threads) {
        if (!info.running)
            continue;
        if (ptrace(PTRACE_INTERRUPT, tid, NULL, 0) == -1) {
            LOG_ERROR(Debug, "[!] Can't interrupt child {} {}", tid, decerrno());
            continue;
        }
        target_threads.push_back(tid);
    }

    thread_event_t evt{};
    bool all_stopped = false;

    while (!target_threads.empty()) {
        if (!listener->Poll(evt))
            continue;

        if (child_thread_exited(evt.status) || child_thread_killed(evt.status)) {
            LOG_ERROR(Debug, "[!] Thread {} disappeared before interrupting", evt.tid);
        }

        if (child_thread_stopped(evt.status) && child_thread_stop_reason(evt.status) == SIGSTOP) {
            // LOG_INFO(Debug, "[!] Thread {} interrupted successfully", evt.tid);
            thread_state_t* target_thread = this->FindThread(evt.tid);
            target_thread->running = false;
            target_thread->signal = SIGINT;
        }
        if (int erased = std::erase(target_threads, evt.tid); erased != 1) {
            LOG_ERROR(Debug, "One thread did something funky wunky {} {}", evt.tid, erased);
        }
    }

    return true;
}

bool Predator::ChildThreadRemove(ThreadID target) {
    // errors if no or multiple children are removed
    // shouldn't happen though
    if (target == 0) {
        target = this->main_thread;
        LOG_WARNING(Debug, "Main thread unregistered!");
        LOG_ERROR(Debug, "Consider killing the child");
    }
    return this->threads.erase(target) == 1;
}

bool Predator::DumpRegs(ThreadID target) {
    if (this->IsRunning(target) == 1) {
        LOG_ERROR(Debug, "Target running");
        return false;
    }

    if (ptrace(PTRACE_GETREGS, target, nullptr, &this->user_regs) == -1) {
        LOG_ERROR(Debug, "qweqweqwe");
        return false;
    }
    if (ptrace(PTRACE_GETFPREGS, target, nullptr, &this->user_fpregs) == -1) {
        LOG_ERROR(Debug, "rtyrtyrty");
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
    ThreadID* reg_dump_target = &this->thread_sel_reg_dump;
    ThreadID* flow_ctrl_target = &this->thread_sel_flow;
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

    if (!reg_dump_target_found && *reg_dump_target != -1) {
        LOG_ERROR(Debug, "Stub didn't notice disappearing thread {}", *reg_dump_target);
        *reg_dump_target = this->main_thread;
    }
    if (!flow_ctrl_target_found && *flow_ctrl_target != -1) {
        LOG_ERROR(Debug, "Stub didn't notice disappearing thread {}", *flow_ctrl_target);
        *flow_ctrl_target = this->main_thread;
    }
}

void Predator::RegDumpInvalidate(void) {
    this->user_regs_dirty = true;
}

thread_state_t* Predator::FindThread(ThreadID target) {
    if (target == 0)
        target = this->main_thread;
    auto target_found = this->threads.find(target);

    return target_found == this->threads.end() ? nullptr : &target_found->second;
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
