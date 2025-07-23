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
    pid_t parentpid = getpid();
    pid_t target = fork();

    if (target == 0) {
        auto ret = MainReal(argc, argv);
        exit(ret);

    } else if (target > 0) {
        prctl(PR_SET_NAME, "shaddebug", 0, 0);

        Common::Log::Initialize();
        Common::Log::Start();

        PtraceListener pl;
        StubServer srv(13377);
        Predator ct(target, &pl);
        Core::Devtools::GdbStub::predator = &ct;
        Core::Devtools::GdbStub::listener = &pl;

        srv.Start();

        if (!ct.ChildThreadHijack(target)) {
            LOG_ERROR(Debug, "[-] Cannot seize thread {}", target);
            return -1;
        }

        thread_event_t hijack_evt = pl.Wait();
        if (!child_thread_stopped(hijack_evt.status) &&
            child_thread_stop_reason(hijack_evt.status) != SIGSTOP) {
            LOG_ERROR(Debug, "[!] Child didn't stop properly, doesn't exist or idk");
            return -1;
        }

        if (hijack_evt.tid != target) {
            LOG_ERROR(Debug, "[!] Wrong child replied. Yeet");
            return -1;
        }

        // At this point we're sure we're talking to the right child
        LOG_INFO(Debug, "[*] Thread {} seized", target);
        ct.ChildThreadRegister(target, SIGSTOP);

        // wait for GDB
        // we're holding child thread stopped in case if the user
        // wants to track the app from the beginning
        sleep(1);
        if (!srv.ClientConnected()) {
            LOG_ERROR(Debug, "GDB not connected");
            // if GDB is not connected, continue as normal
            if (!ct.ChildThreadContinue(target)) {
                LOG_ERROR(Debug, "Cannot wake up child {}", target);
                return -1;
            }
        }

        // could link it directly to server, but let's keep it in case of getting '-' packet
        std::string response{};
        std::string msg{};
        thread_event_t evt{};
        bool do_continue_what_you_do{true};

        while (do_continue_what_you_do) {
            using namespace Core::Devtools;

            if (srv.GetMessage(msg)) {
                GdbStub::LoopAction send_response = GdbStub::Loop(msg, response);

                switch (send_response) {
                case GdbStub::LoopAction::ERROR:
                    srv.SendMessage(GdbStub::MakeResponse(GdbStub::E01));
                    break;
                case GdbStub::LoopAction::BACK_TO_SENDER: ///< as-is
                    srv.SendMessage(msg);
                    break;
                case GdbStub::LoopAction::EXIT:
                    ct.ChildThreadContinueAll();
                    kill(target, SIGTERM);
                    do_continue_what_you_do = false;
                case GdbStub::LoopAction::REPEAT: ///< Response is not modified
                case GdbStub::LoopAction::SEND:   ///< Response is modified
                    srv.SendMessage(GdbStub::MakeResponse(response));
                    break;
                case GdbStub::LoopAction::NOSEND:
                    break;
                }
            }

            if (!pl.Poll(evt))
                continue;

            if (child_thread_exited(evt.status)) {
                LOG_INFO(Debug, "[-] Thread {} exited with code {:02}", evt.tid,
                         child_thread_exit_reason(evt.status));
                continue;
            }

            if (child_thread_killed(evt.status)) {
                LOG_INFO(Debug, "[-] Thread {} was killed with {:02}", evt.tid,
                         child_thread_kill_reason(evt.status));
                continue;
            }

            if (!child_thread_stopped(evt.status))
                continue;

            int stop_reason = child_thread_stop_reason(evt.status);

            if (thread_state_t* thr = ct.FindThread(evt.tid); thr != nullptr) {
                thr->running = (stop_reason == 0 || stop_reason == SIGCONT);
                thr->signal = (stop_reason == SIGCONT) ? 0 : stop_reason;
            }

            if (child_thread_sigtrap_is_syscall(evt.status)) {
                LOG_INFO(Debug, "[*] Thread {} got SYSCALL SIGTRAP", evt.tid);
                // ct.ChildThreadContinue(tid);
            }

            if (stop_reason == SIGTRAP) {
                LOG_INFO(Debug, "[*] Thread {} got SIGTRAP", evt.tid);

                if (child_thread_evt_clone(evt.status)) {
                    unsigned long new_tid = 0;
                    ptrace(PTRACE_GETEVENTMSG, evt.tid, nullptr, &new_tid);
                    LOG_INFO(Debug, "[+] New thread/process: {}", new_tid);

                    // Child will sigstop on its own
                    thread_event_t clone_evt = pl.Wait();

                    ct.ChildThreadRegister(clone_evt.tid, SIGSTOP);

                    ct.ChildThreadContinue(evt.tid);
                    ct.ChildThreadContinue(clone_evt.tid);
                    continue;
                }

                if (child_thread_evt_exit(evt.status)) {
                    LOG_INFO(Debug, "[-] Thread {} exits with status {}", evt.tid, evt.status);
                    ct.ChildThreadRemove(evt.tid);
                    continue;
                }
                // no other events, carry on
                ct.ChildThreadContinue(evt.tid);

            } else if (stop_reason == SIGSEGV) {
                siginfo_t info;
                if (ptrace(PTRACE_GETSIGINFO, evt.tid, 0, &info) == 0) {
                    // Apparently we DO like this particular kind (Linux only?)
                    if (info.si_code == SEGV_ACCERR) {
                        ct.ChildThreadContinue(evt.tid, SIGSEGV, true);
                    } else { // The rest is highly undesired

                        ct.DumpRegs(evt.tid);
                        LOG_ERROR(Debug,
                                  "[*] Thread {} got undesired SIGSEGV {:02} at RIP=0x{:X} (:X)",
                                  evt.tid, info.si_code, ct.user_regs.rip,
                                  ct.user_regs.rip - 0x7FF000000);
                    }
                }
            } else if (stop_reason == SIGSTOP) {
                LOG_INFO(Debug, "[*] Thread {} got SIGSTOP", evt.tid);

                if (thread_state_t* _ = ct.FindThread(evt.tid); _ != nullptr) {
                    ct.ChildThreadContinue(evt.tid);
                } else {
                    // *likely* a child that raised SIGSTOP faster than parent could emit an event
                    pl.Place(evt);
                }

            } else if (stop_reason == SIGCONT) {
                LOG_INFO(Debug, "[*] Thread {} continuing", evt.tid);
                // ct.ChildThreadContinue(evt.tid);
            } else {
                LOG_INFO(Debug, "[*] Thread {} stopped with signal {:02}", evt.tid, stop_reason);
                ct.ChildThreadContinue(evt.tid);
            }

            // ct.ChildThreadContinue(evt.tid);
        }

        LOG_INFO(Debug, "Parent exited");
        srv.Stop();
    } else { ///< if (target > 0)
        std::cout << "Fork error" << std::endl;
    }
    return 0;
}
