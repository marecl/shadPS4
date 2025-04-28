// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <atomic>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <ucontext.h>
#include "common/types.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>
using ThreadID = DWORD;
#else
#include <pthread.h>
#include <signal.h>
using ThreadID = pthread_t;
#endif

void ctx_dump_handler(int sig, siginfo_t* si, void* ucontext);

namespace Libraries::Kernel {
struct Pthread;
} // namespace Libraries::Kernel

namespace GdbDataType {

typedef std::tuple<ThreadID, u32> thread_meta_t;
typedef std::tuple<std::string, ThreadID, u32> thread_list_item_t;
typedef std::vector<thread_list_item_t> thread_list_t;
typedef std::tuple<u64, u64, std::string> loadable_info_t;

using namespace ::Libraries::Kernel;

/****** THREADS ******/
/*
 * Thread ID is a mess. You can get it easily, but referring
 * back to it will raise an exception. IDK why.
 *
 * Explanation ------ ptrace expected P(rocess)ID, not T(thread)ID,
 * as was suggested before
 * :)
 *
 * Short thread ID is needed because some programs don't handle u32
 * variables well, which causes them to become negative numbers. Not good.
 * Since thread ID is (most likely) 32bit anyway, we can turn it into complimentary
 * positive number.
 */

#define GAME_MAIN_THREAD_NAME (const char*)"GAME_MainThread"

class GdbDataImpl {

public:
    void thread_register(ThreadID pid);
    void thread_unregister(ThreadID pid);
    // void -> thread name, thread ID, short thread ID
    // std::vector<thread_list_entry_t> thread_list(void);

    void thread_pause(ThreadID pid);
    void thread_resume(ThreadID pid);

    void thread_pause_all(ThreadID pause_me_last, std::atomic<bool>* is_guest_threads_paused);
    void thread_resume_all(std::atomic<bool>* is_guest_threads_paused);

    static void thread_dump_ctx(ThreadID tid, void* ucontext);
    static ucontext_t thread_get_ctx(ThreadID tid);

    ThreadID thread_decode_id(u32 encID);

    /****** LOADED BINARIES ******/
    /*
     * TODO: this
     */
    void loadable_register(u64 base_addr, u64 size, std::string name);
    void loadable_unregister();

private:
    //  main list mutex
    static std::mutex thread_list_mutex;
    // thread list
    static std::vector<thread_meta_t> thread_list;

    // Thread ctx-s
    static std::unordered_map<ThreadID, ucontext_t> ctx_dumps;
    // mutex for ctx dump
    static std::unordered_map<ThreadID, std::mutex> ctx_dump_mutex;

    // loadables
    static std::vector<loadable_info_t> loaded_binaries;
};

// Why are the dogs peeing with one paw up?

} // namespace GdbDataType

extern GdbDataType::GdbDataImpl& GdbData;
