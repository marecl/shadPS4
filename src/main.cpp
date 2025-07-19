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
#include "mainReal.h"
#include "common/logging/log.h"
#include "common/logging/backend.h"

#include "gdbstub/threadinfo.h"
// #include "gdbstub/gdb_data.h"
// #include "gdbstub/gdb_stub.h"

int main(int argc, char* argv[]) {
    pid_t parentpid = getpid();
    pid_t target = fork();

    if (target == 0) {
        raise(SIGSTOP);
        auto ret = mainReal(argc, argv);
        exit(ret);
    } else if (target > 0) {
        prctl(PR_SET_NAME, "shadgdb", 0, 0);

        Common::Log::Initialize("debug.log");
        Common::Log::Start();

        LOG_INFO(Debug, "XDXDXD");
        LOG_WARNING(Debug, "XDXDXD");
        LOG_CRITICAL(Debug, "XDXDXD");

        int status = 0;
        ThreadID targetTID = waitpid(target, &status, WSTOPPED);


        std::vector<ThreadID> actthr;
        actthr.push_back(targetTID);

        ptrace(PTRACE_SEIZE, targetTID, NULL, NULL);
        ptrace(PTRACE_SETOPTIONS, targetTID, 0,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_CONT, targetTID, NULL, NULL);

        /*

                ptrace(PTRACE_SEIZE, target, NULL, NULL);
                ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);
                ptrace(PTRACE_CONT, target, NULL, NULL);
                waitpid(target, &status, 0);

                // auto gdb_stub = Core::Devtools::GdbStub(13377, target, sharedMem);
                // int ret = gdb_stub.Run();
                std::cout << "XDXDXD" << std::endl;*/
        bool go = true;
        while (go) {
            int status = 0;
            pid_t tid = waitpid(-1, &status, __WALL);
            if (tid == -1) {
                break;
            }

            if (WIFSTOPPED(status)) {
                if (WSTOPSIG(status) == SIGSEGV) {
                    siginfo_t info;
                    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &info) == 0) {
                        // Apparently we DO like this particular kind (Linux only?)
                        if (info.si_code != SEGV_ACCERR) {
                            // The rest is highly undesired
                            struct user_regs_struct regs;
                            ptrace(PTRACE_GETREGS, tid, 0, &regs);
                            std::cout << "[*] Thread " << tid << " got undesired SIGSEGV "
                                      << std::hex << info.si_code << " at RIP=0x" << regs.rip
                                      << " (" << regs.rip - 0x7FF000000 << ")" << std::dec
                                      << std::endl;
                        }
                        ptrace(PTRACE_CONT, tid, nullptr, SIGSEGV);
                    }

                } else {
                    std::cout << std::dec << "[*] Thread " << tid << " stopped with signal "
                              << WSTOPSIG(status) << std::endl;
                }

            } else if (WIFEXITED(status)) {
                std::cout << "[-] Thread " << tid << " ended with code " << WEXITSTATUS(status)
                          << std::endl;
            } else if (WIFSIGNALED(status)) {
                std::cout << "[-] Thread " << tid << " was killed with " << WTERMSIG(status)
                          << std::endl;
            }

            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                unsigned long new_tid = 0;
                ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid);
                actthr.push_back(new_tid);

                std::cout << "[+] New thread/process: " << new_tid << "\n";

                ptrace(PTRACE_SEIZE, new_tid, nullptr, nullptr);
                ptrace(PTRACE_SETOPTIONS, new_tid, nullptr,
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
                ptrace(PTRACE_CONT, new_tid, nullptr, nullptr);
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            }

            if (status >> 8 == (SIGTRAP | 0x80)) {
                std::cout << "[*] Syscall trap, continuing" << std::endl;
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                continue;
            }

            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                std::cout << "[-] Thread " << tid << " ends " << status << "\n";
                actthr.erase(std::remove(actthr.begin(), actthr.end(), tid), actthr.end());
                if (tid == target)
                    go = false;
            }
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
                std::cout << "[*] Thread " << tid << " forks " << status << "\n";
            }
        }
    } else {
        std::cout << "Fork error" << std::endl;
    }

    return 0;
}
