// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <condition_variable>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>
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

namespace Libraries::Kernel {
struct Pthread;
} // namespace Libraries::Kernel

namespace GdbDataType {

typedef std::tuple<std::string, u32> thread_meta_t;
typedef std::tuple<std::string, ThreadID, u32> thread_list_entry_t;
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
explicit GdbDataImpl(void);
//~GdbDataImpl(void);


    bool thread_register(ThreadID pid);
    bool thread_unregister(ThreadID pid);
    // void -> thread name, thread ID, short thread ID
    std::vector<thread_list_entry_t> thread_list(void);

    bool thread_pause(ThreadID pid);
    bool thread_resume(ThreadID pid);

    bool thread_pause_all(ThreadID dont_pause_me_bro_or_sth_i_dunno_lol,
                          std::atomic<bool>* is_guest_threads_paused);
    bool thread_resume_all(std::atomic<bool>* is_guest_threads_paused);

    ThreadID thread_decode_id(u32 encID);

    static void capture_context_handler(int sig, siginfo_t* si, void* ucontext);

    /****** LOADED BINARIES ******/
    /*
     * TODO: this
     */
    void loadable_register(u64 base_addr, u64 size, std::string name);
    void loadable_unregister();

    // private:
    //  main list mutex
    static std::mutex guest_threads_mutex;
    // thread list
    static std::unordered_map<ThreadID, thread_meta_t> thread_list_name_pthr;

    // Thread ctx-s
    static std::unordered_map<ThreadID, ucontext_t> captured_contexts;
    // i forgot
    static std::unordered_map<ThreadID, std::condition_variable> cond_vars;
    // mutex for ctx dump
    static std::unordered_map<ThreadID, std::mutex> cond_mutexes;
    // ctx dumped
    static std::unordered_map<ThreadID, std::atomic<bool>> ready_flags;

    // loadables
    static std::vector<loadable_info_t> loaded_binaries;
};

// Why are the dogs peeing with one paw up?

} // namespace GdbDataType

extern GdbDataType::GdbDataImpl& GdbData;