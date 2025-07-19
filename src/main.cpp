// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <iostream>
#include <string>
#include <vector>
#include <sys/prctl.h>
#include <sys/ptrace.h>
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
        ptrace(PTRACE_SETOPTIONS, targetTID, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);
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

        while (1) {
            int status = 0;
            pid_t tid = waitpid(-1, &status, __WALL);
            if (tid == -1) {
                break;
            }

            if (WIFSTOPPED(status)) {
                std::cout << "[*] Wątek " << tid << " zatrzymany przez sygnał " << WSTOPSIG(status)
                          << std::endl;
                //if (WSTOPSIG(status) == SIGSEGV)
                 //   ptrace(PTRACE_CONT, tid, nullptr, nullptr);

            } else if (WIFEXITED(status)) {
                std::cout << "[*] Wątek " << tid << " zakończył się kodem " << WEXITSTATUS(status)
                          << std::endl;
            } else if (WIFSIGNALED(status)) {
                std::cout << "[*] Wątek " << tid << " został zabity sygnałem " << WTERMSIG(status)
                          << std::endl;
            }

            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                unsigned long new_tid = 0;
                ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid);
                actthr.push_back(new_tid);

                std::cout << "[*] Nowy wątek/proces utworzony: " << new_tid << "\n";

                // for (auto& XD : actthr)
                //    std::cout << '\t' << std::dec << XD << std::endl;

                ptrace(PTRACE_SEIZE, new_tid, nullptr, nullptr);
                ptrace(PTRACE_SETOPTIONS, new_tid, nullptr,
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                ptrace(PTRACE_CONT, new_tid, nullptr, nullptr);
            }
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                std::cout << "[-] Wątek " << tid << " kończy się " << status << "\n";
                actthr.erase(std::remove(actthr.begin(), actthr.end(), tid), actthr.end());
            }
            if (status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
                std::cout << "[-] Wątek " << tid << " forkuje " << status << "\n";
            }
        }
        std::cout << "Parent done\n";
    } else {
        std::cout << "huj" << std::endl;
    }

    return 0;
}
