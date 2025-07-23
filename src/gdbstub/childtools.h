// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef CHILDTOOLS_H
#define CHILDTOOLS_H

#include <string>
#include <unordered_map>
#include <vector>

#include <sys/user.h>

#include "common/types.h"
#include "ptrace_listener.h"
#include "threadinfo.h"

enum SignalStop : int { STOP = SIGSTOP, INTERRUPT = SIGINT, TRAP = SIGTRAP };
typedef struct _thread_state_t {
    ThreadID tid = -1;
    std::string name{};
    bool running{false};
    int signal{0};
} thread_state_t;

class Predator {
public:
    Predator(ThreadID main_thread, PtraceListener* listener)
        : main_thread(main_thread), thread_sel_flow(main_thread), thread_sel_reg_dump(main_thread),
          listener(listener) {};
    ~Predator() {};

    // Flow control

    bool ChildThreadHijack(ThreadID target);
    // Default signal for continuing is 0, SIGCONT doesn't really exist in GDB
    void ChildThreadRegister(ThreadID target, int signal = 0);
    bool ChildThreadContinue(ThreadID target, int signal = 0,
                             bool just_shut_the_fuck_up_about_the_segfaults_please = false);
    bool ChildThreadContinueAll(int signal = 0);
    ThreadID Wait(ThreadID target, int* status,
                  int options); ///< possibly split into __WALL, WSTOPPED
    u8 IsRunning(ThreadID target);
    bool ChildThreadInterrupt(ThreadID target);
    bool ChildThreadInterruptAll(void);
    /**
     * Remove thread from tracked list. 0 for main
     */
    bool ChildThreadRemove(ThreadID target);

    // Metadata

    /**
     * Dump registers from (hopefully) stopped thread.
     */
    bool DumpRegs(ThreadID target);
    /**
     * Update thread names, check if threads scheduled for
     * flow control / regdump are still active.
     */
    void ThreadRefresh(void);

    // Misc

    /**
     * Mark latest register dump as dirty, i.e. they weren't
     * dumped after changing target thread or continuing execution.
     */
    void RegDumpInvalidate(void);
    /**
     * Find thread state. 0 for main.
     */
    thread_state_t* FindThread(ThreadID target);

    // Misc, static pro publico bono

    /**
     * Extract thread name directly
     */
    static std::string ThreadName(ThreadID target);

    // temporarily
    // private:
    PtraceListener* listener;
    std::unordered_map<pid_t, thread_state_t> threads{}; ///< TID + name

    const ThreadID main_thread = -1;         ///< make this const at program startup??
    ThreadID thread_sel_reg_dump = -1;       ///< selected for g-action
    ThreadID thread_sel_flow = -1;           ///< selected for s/c/t action
    bool user_regs_dirty{true};              ///< thread changed, true if regs weren't updated
    struct user_regs_struct user_regs{};     ///< latest thread regs dump
    struct user_fpregs_struct user_fpregs{}; ///< latest thread floating point regs dump
};

// static
bool child_thread_stopped(int status);
int child_thread_stop_reason(int status);
bool child_thread_exited(int status);
int child_thread_exit_reason(int status);
bool child_thread_killed(int status);
int child_thread_kill_reason(int status);
bool child_thread_evt_clone(int status);
bool child_thread_evt_exit(int status);
bool child_thread_sigtrap_is_syscall(int status);

#endif // CHILDTOOLS_H