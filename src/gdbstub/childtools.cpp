#include "childtools.h"

#include <fstream>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "threadinfo.h"

bool child_continue(ThreadID tid, int signal) {
    return ptrace(PTRACE_CONT, tid, NULL, signal) != -1;
}

bool child_hijack(ThreadID target) {
    ThreadID targetTID = waitpid(target, nullptr, WSTOPPED);
    if (targetTID != target)
        return false;

    if (ptrace(PTRACE_SEIZE, targetTID, NULL, NULL) == -1)
        return false;
    if (ptrace(PTRACE_SETOPTIONS, targetTID, 0,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD) == -1)
        return false;

    return true;
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
    return status >> 8 == (SIGTRAP | 0x80);
}

bool child_thread_dump_regs(ThreadID tid, struct user_regs_struct* regs,
                            struct user_fpregs_struct* fpregs) {
    if (ptrace(PTRACE_GETREGS, tid, nullptr, regs) == -1) {
        return false;
    }
    if (ptrace(PTRACE_GETFPREGS, tid, nullptr, fpregs) == -1) {
        return false;
    }

    return true;
}

std::string child_thread_name(ThreadID tid) {
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