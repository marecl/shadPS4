// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <ucontext.h>
#include "gdb_data.h"
#include "threadinfo.h"

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace Core::Devtools {

namespace GdbStub {

#define MAX_REGISTERED_THREADS 2137

struct system_state_t {
    bool running;
    // make this const at program startup
    ThreadID thread_main;
    // this not
    // in case if gdb can select multiple threads, be prepared to turn this into vector
    ThreadID thread_selected;
    std::unordered_map<pid_t, std::string> threads;
};
extern struct system_state_t g_system_state;

enum class ControlCode : char {
    Ack = '+',
    Nack = '-',
    PacketStart = '$',
    PacketEnd = '#',
    Interrupt = '\03',
};

struct GdbCommand {
    std::string raw{};
    std::string cmd{};
    std::string arg{};
};

std::string HandlePacket(GdbCommand cmd);
void ThreadRegister(ThreadID id);
void ThreadUnregister(ThreadID id);
void ThreadRefresh(void);
std::string ThreadList(void);
ThreadID ThreadMainOrElse(void);

// pretty generic if you asked me
s8 Preprocess(std::string& data);
GdbCommand ParsePacket(const std::string data);
std::string MakeResponse(const std::string response);

std::string ThreadGetName(ThreadID tid);

} // namespace GdbStub
/*
class GdbStub2 {
public:
    explicit GdbStub2(pid_t target);
    ~GdbStub2();
    bool Run();

    std::string ThreadList(void);

private:
    std::vector<ThreadID> children;

    static volatile sig_atomic_t stop_flag;

    // Taken from xenia
    enum class ControlCode : char {
        Ack = '+',
        Nack = '-',
        PacketStart = '$',
        PacketEnd = '#',
        Interrupt = '\03',
    };

    ThreadInfo* selectedThread;

    const pid_t target_pid;
    const pid_t self_pid;

    // Taken from xenia
    typedef struct _GdbCommand {
        std::string raw{};
        std::string cmd{};
        std::string arg{};
    } GdbCommand;

    static bool IsValidAddress(u64 address, u64 length);
    static bool ReadMemory(u64 address, u64 length, std::string* out);
    static GdbCommand ParsePacket(const std::string& data);
    bool HandleIncomingData(const int client);
    static GdbStub::GdbCommand HandleCommand(const GdbCommand& command);
    ThreadInfo* getThreadHandleFromString(const std::string& data);
    std::string dumpRegistersFromThread(struct user_regs_struct* regs,
                                        struct user_fpregs_struct* fpregs);
    std::string handler(const GdbCommand& command);
    std::string handle_v_packet(const GdbCommand& command);
    std::string handle_H_packet(const GdbCommand& command);
    std::string handle_q_packet(const GdbCommand& command);
    std::string handle_Q_packet(const GdbCommand& command) {
        return "E.Stub";
    }
};*/

} // namespace Core::Devtools
