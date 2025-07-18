#ifndef PROCESSTOOLS_H
#define PROCESSTOOLS_H

#include "threadinfo.h"

void thread_stop(ThreadID tid);
bool process_stop(struct SharedVector* threads, pid_t pid);
bool thread_stopped(ThreadID tid);
bool ptrace_dump_regs(struct user_regs_struct* regs, struct user_fpregs_struct* fpregs);

#endif // PROCESSTOOLS_H