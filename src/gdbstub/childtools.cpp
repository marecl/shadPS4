// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <fstream>
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
    new_thread.running = (signal == 0 || signal == SIGCONT);
    new_thread.name.reserve(20);
    this->threads[target] = new_thread;
}

bool Predator::ChildThreadContinue(ThreadID target, int signal) {
    this->RegDumpInvalidate();

    LOG_ERROR(Debug, "[+--] Continuing child {}", target);
    thread_state_t* thread = this->FindThread(target);

    if (!thread->running) {
        if (ptrace(PTRACE_CONT, target, NULL, signal) == -1) {
            LOG_ERROR(Debug, "[!] Can't continue child {}", target);
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

bool Predator::ChildThreadContinueGroup(ThreadID target, int signal) {
    this->RegDumpInvalidate();

    // Assume the target is a singular thread
    std::vector<ThreadID> target_threads{target};
    // The assumption was wrong
    if (target == this->_main_thread) {
        target_threads.clear();
        std::ranges::copy(this->threads | std::views::keys, std::back_inserter(target_threads));
    }

    bool was_error = false;
    for (ThreadID tid : target_threads) {
        LOG_ERROR(Debug, "[+++] Continuing child {}", tid);
        thread_state_t* thread = this->FindThread(tid);

        if (!thread->running) {
            if (ptrace(PTRACE_CONT, target, NULL, signal) == -1) {
                was_error = true;
                LOG_ERROR(Debug, "[!] Can't continue child {}", tid);
            }
        } else {
            was_error = true;
            LOG_ERROR(Debug, "[!] Continuing running child {}", tid);
        }

        thread->running = (signal == 0 || signal == SIGCONT);
        thread->signal = (signal == SIGCONT) ? 0 : signal;
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

/**
 * Interrupt a list of children AND WAIT FOR THEM!
 */
bool Predator::ChildThreadInterrupt(ThreadID target) {
    // Assume the target is a singular thread
    std::vector<ThreadID> target_threads{target};
    // The assumption was wrong
    if (target == this->_main_thread) {
        target_threads.clear();
        std::ranges::copy(this->threads | std::views::keys, std::back_inserter(target_threads));
    }

    for (auto tid : target_threads) {
        int ret = ptrace(PTRACE_INTERRUPT, tid, NULL, 0);
        if (ret == -1)
            LOG_ERROR(Debug, "[!] Can't interrupt child {}", tid);
    }

    int status;
    ThreadID waitpid_responder;
    bool all_stopped = false;

    while (!all_stopped) {
        waitpid_responder = this->Wait(-1, &status, __WALL);
        if (waitpid_responder == -1) {
            LOG_ERROR(Debug, "Co do huja nawet nie wiem co to oznacza, nie da sie zaczekac na "
                             "zjebany proces ktory mial sie przerwac");
            continue;
        }

        if (!child_thread_stopped(status))
            continue;

        int stop_reason = child_thread_stop_reason(status);

        if (stop_reason == (SIGTRAP | 0x80)) {
            LOG_ERROR(Debug, "[*] Thread {} got SYSCALL SIGTRAP", waitpid_responder);
        } else if (stop_reason == SIGTRAP) {
            LOG_ERROR(Debug, "[*] Thread {} got SIGTRAP", waitpid_responder);
        } else if (stop_reason == SIGSTOP) {
            LOG_ERROR(Debug, "[*] Thread {} got SIGSTOP", waitpid_responder);
        } else {
            LOG_ERROR(Debug, "[*] Thread {} stopped with code {}", waitpid_responder, stop_reason);
        }

        if (int erased = std::erase(target_threads, waitpid_responder) != 1) {
            LOG_ERROR(Debug, "One thread did something funky wunky {} {}", waitpid_responder,
                      erased);
        }

        thread_state_t* target_thread = this->FindThread(waitpid_responder);

        target_thread->running = false;
        target_thread->signal = stop_reason;

        all_stopped = target_threads.empty();
    }

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
        *reg_dump_target = this->_main_thread;
    }
    if (!flow_ctrl_target_found && *flow_ctrl_target != -1) {
        LOG_ERROR(Debug, "Stub didn't notice disappearing thread {}", *flow_ctrl_target);
        *flow_ctrl_target = this->_main_thread;
    }
}

void Predator::RegDumpInvalidate(void) {
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
