#ifndef PROCESSTOOLS_H
#define PROCESSTOOLS_H

#include <sys/ptrace.h>
#include <sys/wait.h>
#include "common/logging/log.h"
#include "common/types.h"
#include "processtools.h"
#include "threadinfo.h"

void thread_stop(ThreadID tid) {
    ptrace(PTRACE_INTERRUPT, tid, 0, 0);
    waitpid(tid, nullptr, 0);
}

bool process_stop(struct SharedVector* threads, pid_t target) {
    kill(target, SIGSTOP);

    bool all_stopped = false;
    while (!all_stopped) {
        all_stopped = true;
        for (u16 idx = 0; idx < threads->size; idx++) {
            struct ThreadInfo* thd = &threads->threads[idx];
            int status = 0;
            waitpid(thd->tid, &status, __WALL);
            if (!WIFSTOPPED(status)) {
                all_stopped = false;
                LOG_ERROR(Debug, "wątek {:x} ({}) nie jest zatrzymany\n", thd->tid, thd->name);
            }
        }
    }
    return all_stopped;
}

bool thread_stopped(ThreadID tid) {
    siginfo_t si;
    return ptrace(PTRACE_GETSIGINFO, tid, NULL, &si) == 0;
}

bool ptrace_dump_regs(ThreadID tid, struct user_regs_struct* regs,
                      struct user_fpregs_struct* fpregs) {

    if (ptrace(PTRACE_GETREGS, tid, nullptr, regs) == -1) {
        return false;
    }
    if (ptrace(PTRACE_GETFPREGS, tid, nullptr, fpregs) == -1) {
        return false;
    }

    return true;
}

#endif // PROCESSTOOLS_H