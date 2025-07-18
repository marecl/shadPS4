// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "iostream"
#include "string"

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

// #include "gdbstub/gdb_data.h"
#include "gdbstub/gdb_stub.h"
#include "mainReal.h"

int main(int argc, char* argv[]) {
    pid_t parentpid = getpid();
    pid_t target = fork();

    // don't move this to forked process. plz.
    // auto sharedMem = GdbData.thread_shared();

    if (target > 0) {
        std::vector<ThreadID> actthr;
        actthr.push_back(target);

        prctl(PR_SET_NAME, "shadgdb", 0, 0);
        Common::Log::Initialize("debug.log");
        Common::Log::Start();

        int status = 0;
        std::cout << "XDXDXD" << std::endl;

        ptrace(PTRACE_SEIZE, target, NULL, NULL);
        ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT);
        ptrace(PTRACE_CONT, target, NULL, NULL);
        waitpid(target, &status, 0);

        // auto gdb_stub = Core::Devtools::GdbStub(13377, target, sharedMem);
        // int ret = gdb_stub.Run();
        std::cout << "XDXDXD" << std::endl;

        while (1) {
            for (auto& tid : actthr) {
                int status = 0;
                pid_t res = waitpid(tid, &status, 0);
                if (res == -1) {
                    perror("waitpid");
                    break;
                }

                if (WIFSTOPPED(status)) {
                    int sig = WSTOPSIG(status);
                    std::cout << "[*] Wątek " << tid << " zatrzymany przez sygnał " << sig
                              << std::endl;

                    // np. ignoruj wszystkie sygnały
                    ptrace(PTRACE_CONT, tid, 0, 0);
                } else if (WIFEXITED(status)) {
                    std::cout << "[*] Wątek " << tid << " zakończył się kodem "
                              << WEXITSTATUS(status) << std::endl;
                } else if (WIFSIGNALED(status)) {
                    std::cout << "[*] Wątek " << tid << " został zabity sygnałem "
                              << WTERMSIG(status) << std::endl;
                }
            }
        }
    }

    if (target == 0) {
        mainReal(argc, argv);
    }

    return 0;
}
