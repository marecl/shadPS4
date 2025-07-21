// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
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
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "mainReal.h"

#include "gdbstub/childtools.h"
#include "gdbstub/gdb_server.h"
#include "gdbstub/gdb_stub.h"
#include "gdbstub/threadinfo.h"

int main(int argc, char* argv[]) {
    pid_t parentpid = getpid();
    pid_t target = fork();

    if (target == 0) {
        auto ret = mainReal(argc, argv);
        exit(ret);

    } else if (target > 0) {
        prctl(PR_SET_NAME, "shaddebug", 0, 0);

        Common::Log::Initialize();
        Common::Log::Start();

        if (!child_hijack(target)) {
            LOG_ERROR(Debug, "[-] Cannot seize thread {}", target);
            return -1;
        }
        LOG_INFO(Debug, "[*] Thread {} seized", target);
        Core::Devtools::GdbStub::ThreadRegister(target);

        StubServer srv(13377);
        srv.Start();

        // wait for GDB
        // we're holding child thread stopped in case if the user
        // needs to debug the app itself
        sleep(1);
        if (!srv.ClientConnected()) {
            // if GDB is not connected, continue as normal
            if (!child_continue(target)) {
                LOG_ERROR(Debug, "Cannot wake up child {}", target);
                return -1;
            }
        }

        // Rebuild just in case. On init there's only one thread active anyway
        Core::Devtools::GdbStub::ThreadRefresh();
        Core::Devtools::GdbStub::g_system_state.thread_sel_reg_dump = target;
        Core::Devtools::GdbStub::g_system_state.thread_sel_flow = target;
        Core::Devtools::GdbStub::g_system_state.thread_main = target;

        // keep there for '-' packet
        std::string response{};
        std::string msg{};
        Core::Devtools::GdbStub::GdbCommand cmd;

        bool do_continue_what_you_do = true;
        while (do_continue_what_you_do) {
            // looks pretty generic too
            using namespace Core::Devtools;

            if (srv.GetMessage(msg)) {
                s8 ret = GdbStub::Preprocess(msg);
                bool send_response = true;

                switch (ret) {
                case -1:
                    send_response = false;
                    LOG_ERROR(Debug, "Error while receiving packet");
                    break;
                case 0:
                    // LOG_INFO(Debug, "Back to sender: {}", msg);
                    response = msg;
                    break;
                case 1: {
                    response = "";
                    cmd = GdbStub::ParsePacket(msg);
                    s8 openEndedHandlerStatus = GdbStub::HandleContinuous(cmd);

                    if (openEndedHandlerStatus == -1) {
                        LOG_ERROR(Debug, "Some error. Investigate into GdbStub::HandleContinuous");
                        response = GdbStub::E01;
                    } else if (openEndedHandlerStatus == 0) {
                        // Needs the response
                        std::string handler_effect = GdbStub::HandlePacket(cmd);
                        if (handler_effect == GdbStub::touch_grass) {
                            do_continue_what_you_do = false;
                            handler_effect = GdbStub::OK;
                        }

                        response = GdbStub::MakeResponse(handler_effect);
                    } else {
                        // all errors were already disclosed
                        send_response = false;
                    }
                    LOG_INFO(Debug, "Received data:\n\tRAW: {}\n\tCMD: {}\n\tARG: {}\n\tRESP: {}",
                             cmd.raw, cmd.cmd, cmd.arg, response);
                } break;
                case 2:
                    LOG_INFO(Debug, "Repeat response requested: {}", response);
                    break;
                }

                if (send_response)
                    srv.SendMessage(response);
            }
            // end of generic

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
                        // I might regret adding this
                        // GdbStub::g_system_state.running = true;
                    }

                } else if (child_thread_stop_reason(status) == SIGTRAP) {
                    LOG_INFO(Debug, "[*] Thread {} got SIGTRAP {:X}", tid,
                             child_thread_stop_reason(status));
                    // GdbStub::g_system_state.running = false;
                } else if (child_thread_sigtrap_is_syscall(status)) {
                    LOG_INFO(Debug, "[*] Thread {} got SYSCALL SIGTRAP {:X}", tid,
                             child_thread_stop_reason(status));
                    // GdbStub::g_system_state.running = false;
                    //  child_continue(tid);
                } else {
                    LOG_INFO(Debug, "[*] Thread {} stopped with signal {:X}", tid,
                             child_thread_stop_reason(status));
                    // GdbStub::g_system_state.running = false;
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

                GdbStub::ThreadRegister(new_tid);

                child_continue(new_tid);
                child_continue(tid);
                // GdbStub::g_system_state.running = true;
            }
            if (child_thread_evt_exit(status)) {
                LOG_INFO(Debug, "[-] Thread {} ends with status {:X}", tid, status);
                GdbStub::ThreadUnregister(tid);
                if (tid == target) {
                    break;
                }
            }
        }
        srv.Stop();
        std::cout << "Parent out" << std::endl;
    } else {
        std::cout << "Fork error" << std::endl;
    }

    return 0;
}
