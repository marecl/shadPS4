// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <common/types.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "mainReal.h"

#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "gdbstub/childtools.h"
#include "gdbstub/gdb_server.h"
#include "gdbstub/gdb_stub.h"
#include "gdbstub/ptrace_listener.h"
#include "gdbstub/threadinfo.h"

int main(int argc, char* argv[]) {
    ThreadID parent_pid = getpid();
    ThreadID child_pid = fork();

    if (child_pid == 0) {
        auto ret = MainReal(argc, argv);
        std::cout << "Child exited\n";
        return ret;

    } else if (child_pid > 0) {
        prctl(PR_SET_NAME, "shaddebug", 0, 0);

        Common::Log::Initialize();
        Common::Log::Start();

        StubServer stub_server(13377);
        stub_server.Start();

        PtraceListener ptrace_listener;
        Predator predator(child_pid, &ptrace_listener);
        GdbStub stub = GdbStub(&predator, &ptrace_listener, &stub_server);

        if (!predator.HijackChild(child_pid)) {
            LOG_ERROR(Debug, "[-] Cannot seize thread {}", child_pid);
            return -1;
        }

        thread_event_t hijack_evt = ptrace_listener.Wait();
        if (!child_thread_stopped(hijack_evt.status) &&
            child_thread_stop_reason(hijack_evt.status) != SIGSTOP) {
            LOG_ERROR(Debug, "[!] Child didn't stop properly, doesn't exist or idk");
            return -1;
        }

        if (hijack_evt.tid != child_pid) {
            LOG_ERROR(Debug, "[!] Wrong child replied. Yeet");
            return -1;
        }

        // At this point we're sure we're talking to the right child
        LOG_INFO(Debug, "[*] Thread {} seized", child_pid);
        predator.ThreadRegister(child_pid, SIGSTOP);

        // wait for GDB
        // we're holding child thread stopped in case if the user
        // wants to track the app from the beginning
        sleep(1);
        if (!stub_server.ClientConnected()) {
            LOG_ERROR(Debug, "GDB not connected");
            // if GDB is not connected, continue as normal
            if (!predator.ChildThreadContinue(child_pid)) {
                LOG_ERROR(Debug, "Cannot wake up child {}", child_pid);
                return -1;
            }
        }

        // could link it directly to server, but let's keep it in case of getting '-' packet

        bool do_continue_what_you_do{true};

        while (do_continue_what_you_do) {

            if (thread_state_t* mthr = predator.FindThread(0); mthr == nullptr) {
                do_continue_what_you_do = false;
            }

            s8 stub_status_loop_command = stub.LoopCommand();

            if (stub_status_loop_command == 0) {
                do_continue_what_you_do = false;
                LOG_ERROR(Debug, "Terminate child here");
                // exit(0);
            } else if (stub_status_loop_command == -1) {
                LOG_ERROR(Debug, "Stub recoverable error");

            } else if (stub_status_loop_command == -2) {
                do_continue_what_you_do = false;
                LOG_ERROR(Debug, "Stub unrecoverable error");
                // exit(1);
            }

            if (stub.LoopTrace())
                continue;
        }

       // ptrace(PTRACE_DETACH, child_pid, nullptr, SIGINT);
        // change 0 to a variable returned by parent (or a child if ended with an error)
        // but idk
        // stub.End(0);
        // ptrace_listener.Stop(); // this fucker can't get a hint to exit waitpid()
        stub_server.Stop();
        std::cout << "Parent exited\n";
    } else { ///< if (child_pid > 0)
        std::cout << "Fork error\n";
    }
    std::cout << "Fin\n";
    return 0;
}
