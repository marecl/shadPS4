// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <unordered_map>
#include <fmt/xchar.h>
#include <magic_enum/magic_enum_utility.hpp>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "common/assert.h"
#include "common/debug.h"
#include "common/singleton.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/libraries/libs.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"

using namespace ::Libraries::Kernel;
using namespace GdbDataType;
GdbDataImpl& GdbData = *Common::Singleton<GdbDataImpl>::Instance();

std::mutex GdbDataImpl::guest_threads_mutex;
std::unordered_map<ThreadID, thread_meta_t> GdbDataImpl::thread_list_name_pthr;
std::unordered_map<ThreadID, ucontext_t> GdbDataImpl::captured_contexts;
std::unordered_map<ThreadID, std::condition_variable> GdbDataImpl::cond_vars;
std::unordered_map<ThreadID, std::mutex> GdbDataImpl::cond_mutexes;
std::unordered_map<ThreadID, std::atomic<bool>> GdbDataImpl::ready_flags;
std::vector<loadable_info_t> GdbDataImpl::loaded_binaries;

GdbDataImpl::GdbDataImpl(void) {
    // backup those???
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = capture_context_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
}

bool GdbDataImpl::thread_register(ThreadID tid) {
    /*
        std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    guest_threads.push_back(id);
    */

    std::lock_guard lock{GdbDataImpl::guest_threads_mutex};
    try {
        const u32 tid_encoded = 1 + ((~tid) & 0x7FFFFFFF);

        char XD[128];
        pthread_getname_np(tid, XD, 256);
        std::string thrname = std::string(XD);

        thread_meta_t newThread = thread_meta_t(thrname, tid_encoded);
        GdbDataImpl::thread_list_name_pthr[tid] = newThread;

        LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", thrname, tid, tid_encoded);
        return true;
    } catch (...) {
    }
    LOG_ERROR(Debug, "Failed to register thread: {:x}", tid);
    return false;
}

bool GdbDataImpl::thread_unregister(ThreadID tid) {
    /*
        std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    std::erase_if(guest_threads, [&](const ThreadID& v) { return v == id; });
    */

    std::lock_guard lock{guest_threads_mutex};
    try {
        thread_meta_t toBeRemoved = GdbDataImpl::thread_list_name_pthr[tid];
        GdbDataImpl::thread_list_name_pthr.erase(tid);

        LOG_INFO(Debug, "Thread unregistered: {} ({:x})", std::get<0>(toBeRemoved), tid);
        return true;
    } catch (...) {
    }

    LOG_ERROR(Debug, "Failed to unregister thread: {:x}", tid);
    return false;
}

bool GdbDataImpl::thread_pause(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    SuspendThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
    return true;
}

bool GdbDataImpl::thread_resume(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    ResumeThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
    return true;
}

ThreadID GdbDataImpl::thread_decode_id(u32 encID) {
    if (encID == 0 || encID == -1)
        return 0; // return MainThread here!!!

    try {
        for (const auto& [id, meta] : thread_list_name_pthr) {
            ThreadID maybeTargetThread = std::get<1>(meta);
            if (maybeTargetThread == encID) {
                return maybeTargetThread;
            }
        }
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", encID);
    return 0;
}

bool GdbDataImpl::thread_resume_all(std::atomic<bool>* is_guest_threads_paused) {
    std::lock_guard lock{GdbDataImpl::guest_threads_mutex};
    if (!*is_guest_threads_paused) {
        return false;
    }

    for (const auto& [id, _] : GdbDataImpl::thread_list_name_pthr) {
        thread_resume(id);
    }
    *is_guest_threads_paused = false;
    return true;
}

bool GdbDataImpl::thread_pause_all(ThreadID dont_pause_me_bro_or_sth_i_dunno_lol,
                                   std::atomic<bool>* is_guest_threads_paused) {

    std::unique_lock lock{guest_threads_mutex};
    if (*is_guest_threads_paused) {
        return false;
    }

    bool self_guest = false;

    for (const auto& [id, _] : GdbDataImpl::thread_list_name_pthr) {
        if (id == dont_pause_me_bro_or_sth_i_dunno_lol) {
            self_guest = true;
        } else {
            thread_pause(id);
            std::unique_lock<std::mutex> lock(cond_mutexes[id]);
            GdbDataImpl::cond_vars[id].wait(lock,
                                            [&] { return GdbDataImpl::ready_flags[id].load(); });
        }
    }

    *is_guest_threads_paused = true;
    lock.unlock();

    // pause debug state????
    if (self_guest) {
        thread_pause(dont_pause_me_bro_or_sth_i_dunno_lol);
    }

    for (auto& [id, ctx] : captured_contexts) {
        std::string out = "";
        u8 bfr[32];
        memcpy(bfr, reinterpret_cast<u8*>(ctx.uc_stack.ss_sp) - 32, 32);

        for (u8 i = 0; i < 32; i++)
            out += std::format("{:02x} ", bfr[i]);
        LOG_INFO(Debug, "{:x} -> RIP: {:x} -> RDI: {:x} -> RSI: {:x} -> RBP: {:x} -> RBX: {:x}",
                 reinterpret_cast<u64>(id), ctx.uc_mcontext.gregs[REG_RIP],
                 ctx.uc_mcontext.gregs[REG_RDI], ctx.uc_mcontext.gregs[REG_RSI],
                 ctx.uc_mcontext.gregs[REG_RBP], ctx.uc_mcontext.gregs[REG_RBX]);
        LOG_INFO(Debug, "\t->Stack Dump: {}", out);
    }
    return true;
}

#include <pthread.h>
/*

Stephen — 23:28
Core::MemoryManager holds the emulated memory stuff, while Core::AddressSpace has the all the
corresponding host memory mappings.


*/
// Name, original ID, short/encoded ID
std::vector<thread_list_entry_t> GdbDataImpl::thread_list(void) {
    std::vector<std::tuple<std::string, u64, u32>> out;

    for (auto& [pid, meta] : thread_list_name_pthr) {

        out.emplace_back(std::get<0>(meta), pid, std::get<1>(meta));
    }

    return out;
}

void GdbDataImpl::loadable_register(u64 base_addr, u64 size, std::string name) {
    loadable_info_t entry(base_addr, size, name);
    loaded_binaries.emplace_back(entry);
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

void GdbDataImpl::loadable_unregister() {
    LOG_WARNING(Debug, "If you see this we're fucked (this function is never called)");
}

void GdbDataImpl::capture_context_handler(int sig, siginfo_t* si, void* ucontext) {
    ThreadID this_id = pthread_self();

    std::unique_lock<std::mutex> lock(GdbDataImpl::cond_mutexes[this_id]);
    std::memcpy(&GdbDataImpl::captured_contexts[this_id], ucontext, sizeof(ucontext_t));
    ready_flags[this_id] = true;
    cond_vars[this_id].notify_one();
}
