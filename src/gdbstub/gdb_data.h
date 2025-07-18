// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <atomic>
#include <cstring>
#include <tuple>
#include <unordered_map>
#include <vector>
#include <sys/mman.h>
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "common/types.h"
#include "threadinfo.h"

namespace Libraries::Kernel {
struct Pthread;
} // namespace Libraries::Kernel

namespace GdbDataType {

typedef std::tuple<ThreadID, u32> thread_meta_t;
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


class GdbDataImpl {

public:
    GdbDataImpl() {
        shared =
            static_cast<SharedVector*>(mmap(nullptr, sizeof(SharedVector), PROT_READ | PROT_WRITE,
                                            MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (shared == MAP_FAILED) {
            perror("mmap");
            shared = nullptr;
            return;
        }

        shared->size = 0;
        memset(shared->threads, 0, sizeof(shared->threads));
    }
    ~GdbDataImpl() {
        // LOG_ERROR(Debug, "XXDDXXDD");
        // munmap(shared, sizeof(SharedVector));
    }

    SharedVector* thread_shared();
    void thread_rebuild();

    /********** THREADS ***********/
    void thread_register(ThreadID tid);
    void thread_unregister(ThreadID tid);
    // void -> thread name, thread ID, short thread ID
    // std::vector<thread_list_entry_t> thread_list(void);

    void thread_pause(ThreadID tid);
    void thread_resume(ThreadID tid);

    void thread_pause_all(ThreadID pause_me_last, std::atomic<bool>* is_guest_threads_paused);
    void thread_resume_all(std::atomic<bool>* is_guest_threads_paused);

    static std::string getThreadName(ThreadID tid);

    ThreadID thread_decode_id(u32 encID);
    u32 thread_encode_id(ThreadID tid);

    /********** MEMORY ***********/

    /****** LOADED BINARIES ******/
    /*
     * TODO: this
     */
    // void loadable_register(u64 base_addr, u64 size, std::string name);
    // void loadable_unregister();

    struct SharedVector* shared;

private:
    //  main list mutex
    static std::mutex thread_list_mutex;
    // thread list
    static std::vector<thread_meta_t> thread_list;

    // loadables
    static std::vector<loadable_info_t> loaded_binaries;
};

// Why are the dogs peeing with one paw up?

} // namespace GdbDataType

extern GdbDataType::GdbDataImpl& GdbData;
