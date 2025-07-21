
#ifndef CHILDTOOLS_H
#define CHILDTOOLS_H

#include <string>
#include <sys/user.h>

#include "threadinfo.h"

bool child_continue(ThreadID tid, int signal = 0);

bool child_hijack(ThreadID target);

bool child_thread_stopped(int status);
int child_thread_stop_reason(int status);
bool child_thread_exited(int status);
int child_thread_exit_reason(int status);
bool child_thread_killed(int status);
int child_thread_kill_reason(int status);
bool child_thread_evt_clone(int status);
bool child_thread_evt_exit(int status);
bool child_thread_sigtrap_is_syscall(int status);

bool child_thread_dump_regs(ThreadID tid, struct user_regs_struct* regs,
                            struct user_fpregs_struct* fpregs);
std::string child_thread_name(ThreadID tid);

#endif // CHILDTOOLS_H