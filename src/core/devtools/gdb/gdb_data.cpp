// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "gdb_data.h"

#include "common/singleton.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/libraries/libs.h"
#include "core/memory.h"

using namespace ::Libraries::Kernel;
using namespace GdbDataType;
GdbDataImpl& GdbData = *Common::Singleton<GdbDataImpl>::Instance();

std::mutex GdbDataImpl::thread_list_mutex;
std::vector<thread_meta_t> GdbDataImpl::thread_list;
std::vector<loadable_info_t> GdbDataImpl::loaded_binaries;

std::unordered_map<ThreadID, ucontext_t> GdbDataImpl::ctx_dumps;
std::unordered_map<ThreadID, std::mutex> GdbDataImpl::ctx_dump_mutex;

static std::string getThreadName(ThreadID tid) {
    char _rawName[128];
    pthread_getname_np(tid, _rawName, 128);
    return std::string(_rawName);
}

void GdbDataImpl::thread_register(ThreadID tid) {
    std::lock_guard lock{GdbDataImpl::thread_list_mutex};
    const u32 tid_encoded = 1 + ((~tid) & 0x7FFFFFFF);
    GdbDataImpl::thread_list.push_back(thread_meta_t(tid, tid_encoded));

    LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", getThreadName(tid), tid, tid_encoded);
}

void GdbDataImpl::thread_unregister(ThreadID tid) {
    std::lock_guard lock{thread_list_mutex};

    if (std::erase_if(thread_list, [&](const auto& v) { return std::get<0>(v) == tid; }) == 1) {
        LOG_INFO(Debug, "Unregistered thread: {:x}", tid);
        return;
    }
    LOG_INFO(Debug, "Failed to unregister thread: {:x}", tid);
    return;
}

void GdbDataImpl::thread_pause(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    SuspendThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
    return;
}

void GdbDataImpl::thread_resume(ThreadID pid) {
// check if running
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pid);
    ResumeThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(pid, SIGUSR1);
#endif
    return;
}

ThreadID GdbDataImpl::thread_decode_id(u32 encID) {
    if (encID == 0 || encID == -1)
        return 0; // return MainThread here!!!

    for (const auto& thread : thread_list) {
        ThreadID maybeTargetThread = std::get<1>(thread);
        if (maybeTargetThread == encID) {
            return std::get<0>(thread);
        }
    }

    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", encID);
    return 0;
}

void GdbDataImpl::thread_resume_all(std::atomic<bool>* is_guest_threads_paused) {
    std::lock_guard lock{GdbDataImpl::thread_list_mutex};

    if (!is_guest_threads_paused->load()) {
        return;
    }

    for (const auto& thread : thread_list) {
        auto id = std::get<0>(thread);
        LOG_WARNING(Debug, "Resuming thread: {} ({:x})", getThreadName(id), id);
        thread_resume(id);
    }

    is_guest_threads_paused->store(false);
    return;
}

void GdbDataImpl::thread_pause_all(ThreadID pause_me_last,
                                   std::atomic<bool>* is_guest_threads_paused) {

    std::unique_lock lock{thread_list_mutex};
    if (is_guest_threads_paused->load()) {
        return;
    }

    bool self_guest = false;

    for (const auto& thread : thread_list) {
        auto tid = std::get<0>(thread);
        if (tid == pause_me_last) {
            self_guest = true;
        } else {
            LOG_WARNING(Debug, "Pausing thread: {} ({:x})", getThreadName(tid), tid);
            thread_pause(tid);
        }
    }

    if (self_guest) {
        LOG_WARNING(Debug, "Pausing last thread: {} ({:x})", getThreadName(pause_me_last),
                    pause_me_last);
        thread_pause(pause_me_last);
    }

    is_guest_threads_paused->store(true);

    lock.unlock();
    return;
}

void GdbDataImpl::thread_dump_ctx(ThreadID tid, void* ucontext) {
    std::unique_lock<std::mutex> lock(GdbDataImpl::ctx_dump_mutex[tid]);
    std::memcpy(&GdbDataImpl::ctx_dumps[tid], ucontext, sizeof(ucontext_t));
}

ucontext_t GdbDataImpl::thread_get_ctx(ThreadID tid) {
    std::unique_lock<std::mutex> lock(GdbDataImpl::ctx_dump_mutex[tid]);
    return GdbDataImpl::ctx_dumps[tid];
}

// Name, original ID, short/encoded ID
/*std::vector<thread_list_entry_t> GdbDataImpl::thread_list(void) {
    std::vector<std::tuple<std::string, u64, u32>> out;

    for (auto& meta : thread_list) {

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

void ctx_dump_handler(int sig, siginfo_t* si, void* ucontext) {

    ThreadID this_id = pthread_self();
    GdbDataImpl::thread_dump_ctx(this_id, ucontext);
    // more dramatic but visible
    // LOG_ERROR(Debug, "CTX handler reached: {:x}", this_id);

    // can be removed, just to make sure we're not collecting garbage
    // also to verify that ghidra gets correct information
#define STACK_DUMP_SIZE 32
    ucontext_t ctx = GdbDataImpl::thread_get_ctx(this_id);
    std::string out = "";
    u8 bfr[STACK_DUMP_SIZE];
    memcpy(bfr, reinterpret_cast<u8*>(ctx.uc_stack.ss_sp) - STACK_DUMP_SIZE, STACK_DUMP_SIZE);

    for (u8 i = 0; i < STACK_DUMP_SIZE; i++)
        out += std::format("{:02x} ", bfr[i]);
    LOG_INFO(Debug,
             "{} ({:x}) -> RIP: {:x} -> RDI: {:x} -> RSI: {:x} -> RBP: {:x} -> RBX: "
             "{:x}\n\t->Stack Dump: {}",
             getThreadName(this_id), reinterpret_cast<u64>(this_id), ctx.uc_mcontext.gregs[REG_RIP],
             ctx.uc_mcontext.gregs[REG_RDI], ctx.uc_mcontext.gregs[REG_RSI],
             ctx.uc_mcontext.gregs[REG_RBP], ctx.uc_mcontext.gregs[REG_RBX], out);

    return;
}