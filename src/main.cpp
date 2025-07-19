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

#include "gdbstub/threadinfo.h"
// #include "gdbstub/gdb_data.h"
// #include "gdbstub/gdb_stub.h"

int main(int argc, char* argv[]) {
    pid_t parentpid = getpid();
    pid_t target = fork();

    // don't move this to forked process. plz.
    // auto sharedMem = GdbData.thread_shared();
    if (target == 0) {
        raise(SIGSTOP);
        auto ret = mainReal(argc, argv);
        std::cout << "Child done\n";
        exit(ret);
    } else if (target > 0) {
        prctl(PR_SET_NAME, "shadgdb", 0, 0);
        sleep(1);

        int status = 0;
        ThreadID targetTID = waitpid(target, &status, WSTOPPED);
        if (!WIFSTOPPED(status)) {
            std::cout << "Dziecko nie zostało zatrzymane przez SIGSTOP\n";
            return -1;
        }

        std::vector<ThreadID> actthr;
        actthr.push_back(targetTID);

        ptrace(PTRACE_SEIZE, targetTID, NULL, NULL);
        ptrace(PTRACE_SETOPTIONS, targetTID, 0,
               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
        ptrace(PTRACE_CONT, targetTID, NULL, NULL);

        /*
                // Common::Log::Initialize("debug.log");
                // Common::Log::Start();
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
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, tid, 0, &regs);
                    std::cout << "[*] Thread " << tid << " got SIGSEGV at RIP=0x" << std::hex
                              << regs.rip << " (" << regs.rip - 0x7FF000000 << ")" << std::dec
                              << std::endl;
                    /*
                                        unsigned char code[32];
                                        std::cout << std::setw(2) << std::setfill('0') << std::hex;
                                        for (int i = 1; i < 33; ++i) {
                                            long data = ptrace(PTRACE_PEEKDATA, tid, regs.rip + i -
                       1, NULL); if (data == -1) break; printf("%02X ", static_cast<unsigned
                       char>(data)); if (i % 4 == 0) std::cout << std::endl;
                                        }
                                        std::cout << std::endl << std::dec;

                                        std::cout << "Nacisnij enter aby kontynuowac po
                       segfaulcie\n"; std::cin.get();
                                        */

                    ptrace(PTRACE_CONT, tid, nullptr, SIGSEGV);
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

                // for (auto& XD : actthr)
                //    std::cout << '\t' << std::dec << XD << std::endl;

                ptrace(PTRACE_SEIZE, new_tid, nullptr, nullptr);
                ptrace(PTRACE_SETOPTIONS, new_tid, nullptr,
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD);
                ptrace(PTRACE_CONT, new_tid, nullptr, nullptr);
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            }

            if (status >> 16 == (SIGTRAP | 0x80)) {
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
        std::cout << "Parent done\n";
    } else {
        std::cout << "huj" << std::endl;
    }

    return 0;
}
