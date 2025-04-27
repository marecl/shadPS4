// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>
#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "common/assert.h"
#include "common/debug.h"
#include "core/debug_state.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/libraries/libs.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"

using namespace DebugStateType;

using namespace ::Libraries::Kernel;

namespace Data {

typedef std::tuple<std::string, u32> thread_meta_t;
typedef std::tuple<u64, u64, std::string> loadable_info_t;

static std::mutex guest_threads_mutex{};
static std::unordered_map<ThreadID, thread_meta_t> thread_list_name_pthr;
static std::unordered_map<ThreadID, ucontext_t> captured_contexts;
static std::unordered_map<ThreadID, std::condition_variable> cond_vars;
static std::unordered_map<ThreadID, std::mutex> cond_mutexes;
static std::unordered_map<ThreadID, std::atomic<bool>> ready_flags;

// loadables
static std::vector<loadable_info_t> loaded_binaries;

// void -> thread name, thread ID, short thread ID
static std::vector<thread_meta_t> thread_list(void);

} // namespace Data

namespace Core::Devtools::GdbData {

using namespace ::Libraries::Kernel;

DebugStateImpl& DebugState = *Common::Singleton<DebugStateImpl>::Instance();

void gdbdata_initialize() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = capture_context_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
}

bool thread_register(ThreadID tid) {
    /*
        std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    guest_threads.push_back(id);
    */

    std::lock_guard lock{Data::guest_threads_mutex};
    try {
        const u32 tid_encoded = 1 + ((~tid) & 0x7FFFFFFF);

        char XD[128];
        pthread_getname_np(tid, XD, 256);
        std::string thrname = std::string(XD);

        Data::thread_meta_t newThread = Data::thread_meta_t(thrname, tid_encoded);
        Data::thread_list_name_pthr[tid] = newThread;

        LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", thrname, tid, tid_encoded);
        return true;
    } catch (...) {
    }
    LOG_ERROR(Debug, "Failed to register thread: {:x}", tid);
    return false;
}

bool thread_unregister(ThreadID tid) {
    /*
        std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    std::erase_if(guest_threads, [&](const ThreadID& v) { return v == id; });
    */

    std::lock_guard lock{Data::guest_threads_mutex};
    try {
        Data::thread_meta_t toBeRemoved = Data::thread_list_name_pthr[tid];
        Data::thread_list_name_pthr.erase(tid);

        LOG_INFO(Debug, "Thread unregistered: {} ({:x})", std::get<0>(toBeRemoved), tid);
        return true;
    } catch (...) {
    }

    LOG_ERROR(Debug, "Failed to unregister thread: {:x}", tid);
    return false;
}

bool thread_pause(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    SuspendThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
}

bool thread_resume(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    ResumeThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
}

ThreadID thread_decode_id(u32 encID) {
    if (encID == 0 || encID == -1)
        return 0; // return MainThread here!!!

    try {
        for (const auto& meta : Data::thread_list_name_pthr) {
            ThreadID maybeTargetThread = std::get<1>(meta);
            if (maybeTargetThread== id) {
                return maybeTargetThread;
            }
        }
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", encID);
    return 0;
}

bool thread_resume_all(bool is_guest_threads_paused) {
    std::lock_guard lock{Data::guest_threads_mutex};
    if (!is_guest_threads_paused) {
        return;
    }

    for (const auto& [id, _] : Data::thread_list_name_pthr) {
        thread_resume(id);
    }
    is_guest_threads_paused = false;
}

bool thread_pause_all(ThreadID dont_pause_me_bro_or_sth_i_dunno_lol, bool is_guest_threads_paused) {

    std::unique_lock lock{Data::guest_threads_mutex};
    if (is_guest_threads_paused) {
        return;
    }

    bool self_guest = false;

    for (const auto& [id, _] : Data::thread_list_name_pthr) {
        if (id == dont_pause_me_bro_or_sth_i_dunno_lol) {
            self_guest = true;
        } else {
            thread_pause(id);
            std::unique_lock<std::mutex> lock(Data::cond_mutexes[id]);
            Data::cond_vars[id].wait(lock, [&] { return Data::ready_flags[id].load(); });
        }
    }

    is_guest_threads_paused = true;
    lock.unlock();

    // pause debug state????
    if (self_guest) {
        thread_pause(dont_pause_me_bro_or_sth_i_dunno_lol);
    }

    for (auto& [id, ctx] : Data::captured_contexts) {
        std::string out = "";
        u8 bfr[32];
        memcpy(bfr, ctx.uc_stack.ss_sp - 32, 32);

        for (u8 i = 0; i < 32; i++)
            out += std::format("{:02x} ", bfr[i]);
        /*LOG_INFO(Debug, "{:x} -> RIP: {:x} -> RDI: {:x} -> RSI: {:x} -> RBP: {:x} -> RBX: {:x}",
                 reinterpret_cast<u64>(id), ctx.uc_mcontext.gregs[REG_RIP],
                 ctx.uc_mcontext.gregs[REG_RDI], ctx.uc_mcontext.gregs[REG_RSI],
                 ctx.uc_mcontext.gregs[REG_RBP], ctx.uc_mcontext.gregs[REG_RBX]);
        LOG_INFO(Debug, "\t->Stack Dump: {}", out);*/
    }
}

#include <pthread.h>
/*

Stephen — 23:28
Core::MemoryManager holds the emulated memory stuff, while Core::AddressSpace has the all the
corresponding host memory mappings.


*/
// Name, original ID, short/encoded ID
std::vector<std::tuple<std::string, u64, u32>> thread_list(void) {
    std::vector<std::tuple<std::string, u64, u32>> out;

    for (auto& [pid, encoded_id] : Data::thread_list_name_pthr) {
        char XD[128];
        pthread_getname_np(pid, XD, 256);
        std::string thrname = std::string(XD);
        out.emplace_back(thrname, pid, encoded_id);
    }

    return out;
}

void loadable_register(u64 base_addr, u64 size, std::string name) {
    Data::loadable_info_t entry(base_addr, size, name);
    Data::loaded_binaries.emplace_back(entry);
    LOG_INFO(Debug, "Loadable registered: {} ({:x} len:{:x})", name, base_addr, size);

    if (name != "eboot")
        return;

    u8 rdata[256];
    std::memcpy(rdata, reinterpret_cast<void*>(base_addr + 0x6CF84), 256);
    std::string out = "";
    for (u16 i = 0; i < 256; i++) {
        if (i % 16 == 0) {
            LOG_INFO(Debug, "{}", out);
            out = "";
        }
        out = out + std::format("{:02x} ", rdata[i]);
    }
    LOG_INFO(Debug, "{}", out);
    return;
}

void loadable_unregister() {
    LOG_WARNING(Debug, "If you see this we're fucked (this function is never called)");
}

static void capture_context_handler(int sig, siginfo_t* si, void* ucontext) {
    ThreadID this_id = pthread_self();

    std::unique_lock<std::mutex> lock(Data::cond_mutexes[this_id]);
    std::memcpy(&Data::captured_contexts[this_id], ucontext, sizeof(ucontext_t));
    Data::ready_flags[this_id] = true;
    Data::cond_vars[this_id].notify_one();
}

} // namespace Core::Devtools::GdbData