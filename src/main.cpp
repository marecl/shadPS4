// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "mainReal.h"

#include "gdbstub/threadinfo.h"
// #include "gdbstub/gdb_data.h"
// #include "gdbstub/gdb_stub.h"
#include "gdbstub/childtools.h"
#include "gdbstub/gdb_server.h"

int main(int argc, char* argv[]) {
    pid_t parentpid = getpid();
    pid_t target = fork();

    if (target == 0) {
        raise(SIGSTOP);
        auto ret = mainReal(argc, argv);
        exit(ret);

    } else if (target > 0) {
        prctl(PR_SET_NAME, "shaddebug", 0, 0);

        Common::Log::Initialize();
        Common::Log::Start();

        // Core::Devtools::GdbStub stub = Core::Devtools::GdbStub(13377, target);

        if (!child_hijack(target)) {
            LOG_ERROR(Debug, "[-] Cannot seize thread {}", target);
            return -1;
        }
        LOG_INFO(Debug, "[*] Thread {} seized", target);

        /*if (!stub.CreateSocket()) {
            LOG_ERROR(Debug, "Stub can't access socket for GDB");
            return -1;
        }*/
        StubServer srv(13377);
        srv.Start();

        while (1) {
            std::string msg;
            if (srv.GetMessage(msg)) {
                LOG_WARNING(Debug, "{}", msg);
            }

            int status = 0;
            pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
            if (tid == 0) {
                continue;
            }
            if (tid == -1) {
                break;
            }

            if (child_thread_stopped(status)) {
                if (child_thread_stop_reason(status) == SIGSEGV) {
                    siginfo_t info;
                    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &info) == 0) {
                        // Apparently we DO like this particular kind (Linux only?)
                        if (info.si_code != SEGV_ACCERR) {
                            // The rest is highly undesired
                            struct user_regs_struct regs;
                            ptrace(PTRACE_GETREGS, tid, 0, &regs);

                            LOG_ERROR(Debug,
                                      "[*] Thread {} got undesired SIGSEGV {:X} at RIP=0x{:X} (:X)",
                                      tid, regs.rip, regs.rip - 0x7FF000000);
                        }
                        child_continue(tid, SIGSEGV);
                    }

                } else if (child_thread_stop_reason(status) == SIGTRAP) {
                    LOG_INFO(Debug, "[*] Thread {} got SIGTRAP {:X}", tid,
                             child_thread_stop_reason(status));

                } else {
                    LOG_INFO(Debug, "[*] Thread {} stopped with signal {:X}", tid,
                             child_thread_stop_reason(status));
                }

            } else if (child_thread_exited(status)) {
                LOG_INFO(Debug, "[-] Thread {} ended with code {:X}", tid,
                         child_thread_exit_reason(status));
            } else if (child_thread_killed(status)) {
                LOG_INFO(Debug, "[-] Thread {} was killed with {:X}", tid,
                         child_thread_kill_reason(status));
            }

            if (child_thread_evt_clone(status)) {
                unsigned long new_tid = 0;
                ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid);

                LOG_INFO(Debug, "[+] New thread/process: {}", new_tid);

                ptrace(PTRACE_SEIZE, new_tid, nullptr, nullptr);
                ptrace(PTRACE_SETOPTIONS, new_tid, nullptr,
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);

                child_continue(new_tid);
                child_continue(tid);
                // children.push_back(new_tid);
            }
            if (child_thread_evt_exit(status)) {
                LOG_INFO(Debug, "[-] Thread {} ends with status {:X}", tid, status);
                // children.erase(std::remove(children.begin(), children.end(), tid),
                // children.end());
                if (tid == target) {
                    break;
                }
            }
            if (child_thread_sigtrap_is_syscall(status)) {
                LOG_INFO(Debug, "[*] Syscall trap, continuing");
                child_continue(tid);
            }
        }
        srv.Stop();
        std::cout << "Parent out" << std::endl;
    } else {
        std::cout << "Fork error" << std::endl;
    }

    return 0;
}
