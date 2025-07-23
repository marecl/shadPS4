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

        StubServer srv(13377);
        Predator ct(target);
        Core::Devtools::GdbStub::predator = &ct;

        srv.Start();

        int wait_pid_status{};
        ThreadID is_target = ct.Wait(target, &wait_pid_status, WSTOPPED);
        if (is_target != target && !child_thread_stopped(wait_pid_status)) {
            LOG_ERROR(Debug, "[!] Child didn't stop properly, doesn't exist or idk");
            return -1;
        }

        if (!ct.ChildThreadHijack(target)) {
            LOG_ERROR(Debug, "[-] Cannot seize thread {}", target);
            return -1;
        }

        LOG_INFO(Debug, "[*] Thread {} seized", target);
        ct.ChildThreadRegister(target, SIGSTOP);

        // wait for GDB
        // we're holding child thread stopped in case if the user
        // wants to track the app from the beginning
        sleep(1);
        if (!srv.ClientConnected()) {
            // if GDB is not connected, continue as normal
            if (!ct.ChildThreadContinue(target)) {
                LOG_ERROR(Debug, "Cannot wake up child {}", target);
                return -1;
            }
        }

        is_target = ct.Wait(target, &wait_pid_status, WSTOPPED);
        if (is_target != target && !child_thread_stopped(wait_pid_status)) {
            LOG_ERROR(Debug, "[!] Child didn't stop properly, doesn't exist or idk");
            return -1;
        }

        // could link it directly to server, but let's keep it in case of getting '-' packet
        std::string response{};
        std::string msg{};
        bool do_continue_what_you_do = true;

        while (do_continue_what_you_do) {
            using namespace Core::Devtools;

            if (srv.GetMessage(msg)) {
                GdbStub::LoopAction send_response = GdbStub::Loop(msg, response);

                switch (send_response) {
                case GdbStub::LoopAction::ERROR:
                    srv.SendMessage(GdbStub::MakeResponse(GdbStub::E01));
                    break;
                case GdbStub::LoopAction::EXIT:
                    kill(target, SIGTERM);
                    break;
                case GdbStub::LoopAction::BACK_TO_SENDER: ///< as-is
                    srv.SendMessage(msg);
                    break;
                case GdbStub::LoopAction::REPEAT: ///< Response is not modified
                case GdbStub::LoopAction::SEND:   ///< Response is modified
                    srv.SendMessage(GdbStub::MakeResponse(response));
                    break;
                case GdbStub::LoopAction::NOSEND:
                    break;
                }
            }

            if (ct.FindThread(target) == nullptr) {
                LOG_INFO(Debug, "main exit lol");
                do_continue_what_you_do = false;
            }

            int status = 0;
            ThreadID tid = ct.Wait(-1, &status, __WALL | WNOHANG);
            if (tid == 0) {
                continue;
            }
            if (tid == -1) {
                break;
            }

            if (child_thread_exited(status)) {
                LOG_INFO(Debug, "[-] Thread {} exited with code {:02}", tid,
                         child_thread_exit_reason(status));
            }

            if (child_thread_killed(status)) {
                LOG_INFO(Debug, "[-] Thread {} was killed with {:02}", tid,
                         child_thread_kill_reason(status));
            }

            if (!child_thread_stopped(status))
                continue;

            int stop_reason = child_thread_stop_reason(status);

            thread_state_t* thr = ct.FindThread(tid);
            thr->running = false;
            thr->signal = stop_reason;

            if (child_thread_sigtrap_is_syscall(status)) {
                LOG_INFO(Debug, "[*] Thread {} got SYSCALL SIGTRAP", tid);
                // ct.ChildThreadContinue(tid);
            }

            if (stop_reason == SIGTRAP) {
                LOG_INFO(Debug, "[*] Thread {} got SIGTRAP", tid);

                if (child_thread_evt_clone(status)) {
                    unsigned long new_tid = 0;
                    ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &new_tid);
                    LOG_INFO(Debug, "[+] New thread/process: {}", new_tid);

                    // Child will sigstop on its own
                    // ThreadID responder = ct.Wait(new_tid, nullptr, WSTOPPED);

                    ct.ChildThreadRegister(new_tid);

                    ct.ChildThreadContinue(tid);
                    // ct.ChildThreadContinue(new_tid);
                    continue;
                }

                if (child_thread_evt_exit(status)) {
                    LOG_INFO(Debug, "[-] Thread {} exits with status {}", tid, status);
                    ct.ChildThreadRemove(tid);
                    continue;
                }
                // no other events, carry on
                ct.ChildThreadContinue(tid);

            } else if (stop_reason == SIGSEGV) {
                siginfo_t info;
                if (ptrace(PTRACE_GETSIGINFO, tid, 0, &info) == 0) {
                    // Apparently we DO like this particular kind (Linux only?)
                    if (info.si_code == SEGV_ACCERR) {
                        ct.ChildThreadContinue(tid, SIGSEGV);
                    } else { // The rest is highly undesired

                        ct.DumpRegs(tid);
                        LOG_ERROR(
                            Debug, "[*] Thread {} got undesired SIGSEGV {:02} at RIP=0x{:X} (:X)",
                            tid, info.si_code, ct.user_regs.rip, ct.user_regs.rip - 0x7FF000000);
                    }
                }
            } else if (stop_reason == SIGSTOP) {
                LOG_INFO(Debug, "[*] Thread {} got SIGSTOP", tid);
                ct.ChildThreadContinue(tid);
            } else if (stop_reason == SIGCONT) {
                LOG_INFO(Debug, "[*] Thread {} continuing", tid);
                // ct.ChildThreadContinue(tid);
            } else {
                LOG_INFO(Debug, "[*] Thread {} stopped with signal {:02}", tid, stop_reason);
                ct.ChildThreadContinue(tid);
            }

            // ct.ChildThreadContinue(tid);
        }

        LOG_INFO(Debug, "Parent exited");
        srv.Stop();
    } else { ///< if (target > 0)
        std::cout << "Fork error" << std::endl;
    }
    return 0;
}
