// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "gdb_data.h"

#include <unordered_map>
#include "common/singleton.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/libraries/libs.h"
#include "core/memory.h"

using namespace ::Libraries::Kernel;
using namespace GdbDataType;
GdbDataImpl& GdbData = *Common::Singleton<GdbDataImpl>::Instance();

std::mutex GdbDataImpl::guest_threads_mutex;
std::vector<thread_meta_t> GdbDataImpl::thread_list_name_pthr;
std::vector<loadable_info_t> GdbDataImpl::loaded_binaries;

bool GdbDataImpl::thread_register(ThreadID tid) {

    std::lock_guard lock{GdbDataImpl::guest_threads_mutex};
    try {
        const u32 tid_encoded = 1 + ((~tid) & 0x7FFFFFFF);

        char XD[128];
        pthread_getname_np(tid, XD, 256);
        std::string thrname = std::string(XD);

        GdbDataImpl::thread_list_name_pthr.push_back(thread_meta_t(tid, thrname, tid_encoded));

        LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", thrname, tid, tid_encoded);
        return true;
    } catch (...) {
    }
    LOG_ERROR(Debug, "Failed to register thread: {:x}", tid);
    return false;
}

bool GdbDataImpl::thread_unregister(ThreadID tid) {

    std::lock_guard lock{guest_threads_mutex};
    try {
        LOG_INFO(Debug, "Unregistering thread: {:x}", tid);
        std::erase_if(thread_list_name_pthr, [&](const auto& v) { return std::get<0>(v) == tid; });

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
        for (const auto& thread : thread_list_name_pthr) {
            ThreadID maybeTargetThread = std::get<2>(thread);
            if (maybeTargetThread == encID) {
                return std::get<0>(thread);
            }
        }
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", encID);
    return 0;
}

bool GdbDataImpl::thread_resume_all(std::atomic<bool>* is_guest_threads_paused) {
    std::lock_guard lock{GdbDataImpl::guest_threads_mutex};
    if (!is_guest_threads_paused->load()) {
        return false;
    }

    for (const auto& thread : thread_list_name_pthr) {
        auto id = std::get<0>(thread);
        auto name = std::get<1>(thread);
        LOG_WARNING(Debug, "Resuming thread: {} ({:x})", name, id);
        thread_resume(id);
    }

    is_guest_threads_paused->store(false);
    return true;
}

bool GdbDataImpl::thread_pause_all(ThreadID dont_pause_me_bro_or_sth_i_dunno_lol,
                                   std::atomic<bool>* is_guest_threads_paused) {

    std::unique_lock lock{guest_threads_mutex};
    if (is_guest_threads_paused->load()) {
        return false;
    }

    bool self_guest = false;

    for (const auto& thread : thread_list_name_pthr) {
        auto tid = std::get<0>(thread);
        auto name = std::get<1>(thread);
        if (tid == dont_pause_me_bro_or_sth_i_dunno_lol) {
            self_guest = true;
        } else {
            LOG_WARNING(Debug, "Pausing thread: {} ({:x})", name, tid);
            thread_pause(tid);
            // std::unique_lock<std::mutex> lock(cond_mutexes[id]);
            // GdbDataImpl::cond_vars[id].wait(lock,
            //                                [&] { return GdbDataImpl::ready_flags[id].load(); });
        }
    }

    is_guest_threads_paused->store(true);
    lock.unlock();

    // pause debug state????
    if (self_guest) {
        thread_pause(dont_pause_me_bro_or_sth_i_dunno_lol);
    }

    return true;
}

/*

Stephen — 23:28
Core::MemoryManager holds the emulated memory stuff, while Core::AddressSpace has the all the
corresponding host memory mappings.


*/
// Name, original ID, short/encoded ID
/*std::vector<thread_list_entry_t> GdbDataImpl::thread_list(void) {
    std::vector<std::tuple<std::string, u64, u32>> out;

    for (auto& meta : thread_list_name_pthr) {

        out.emplace_back(std::get<1>(meta), pid, std::get<1>(meta));
    }

    return out;
}*/

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

std::unordered_map<ThreadID, ucontext_t> GdbDataImpl::captured_contexts;
std::unordered_map<ThreadID, std::mutex> GdbDataImpl::cond_mutexes;

void ctx_dump_handler(int sig, siginfo_t* si, void* ucontext) {

    ThreadID this_id = pthread_self();
    // LOG_ERROR(Debug, "CTX handler reached: {:x}", this_id);

    std::unique_lock<std::mutex> lock(GdbDataImpl::cond_mutexes[this_id]);
    std::memcpy(&GdbDataImpl::captured_contexts[this_id], ucontext, sizeof(ucontext_t));

    // can be removed, just to make sure we're not collecting garbage
    // also to verify that ghidra gets correct information
#define STACK_DUMP_SIZE 32
    ucontext_t ctx = GdbDataImpl::captured_contexts[this_id];
    std::string out = "";
    u8 bfr[STACK_DUMP_SIZE];
    memcpy(bfr, reinterpret_cast<u8*>(ctx.uc_stack.ss_sp) - STACK_DUMP_SIZE, STACK_DUMP_SIZE);

    for (u8 i = 0; i < STACK_DUMP_SIZE; i++)
        out += std::format("{:02x} ", bfr[i]);
    LOG_INFO(
        Debug,
        "{:x} -> RIP: {:x} -> RDI: {:x} -> RSI: {:x} -> RBP: {:x} -> RBX: {:x}\n\t->Stack Dump: {}",
        reinterpret_cast<u64>(this_id), ctx.uc_mcontext.gregs[REG_RIP],
        ctx.uc_mcontext.gregs[REG_RDI], ctx.uc_mcontext.gregs[REG_RSI],
        ctx.uc_mcontext.gregs[REG_RBP], ctx.uc_mcontext.gregs[REG_RBX], out);

    return;
}