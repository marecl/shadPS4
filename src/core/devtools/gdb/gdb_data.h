// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>
#include "common/types.h"

namespace Libraries::Kernel {
struct Pthread;
} // namespace Libraries::Kernel

namespace Core::Devtools::GdbData {

using namespace ::Libraries::Kernel;

/****** THREADS ******/
/*
 * Thread ID is a mess. You can get it easily, but referring
 * back to it will raise an exception. IDK why.
 *
 * Short thread ID is needed because some programs don't handle u32
 * variables well, so they are transformed into a negative number.
 * Since thread ID is (most likely) 32bit anyway, it can be truncated,
 * and made into a positive number.
 */

#define GAME_MAIN_THREAD_NAME (const char*)"GAME_MainThread"

void gdbdata_initialize();

bool thread_register(ThreadID pid);
bool thread_unregister(ThreadID pid);

bool thread_pause(ThreadID pid);
bool thread_resume(ThreadID pid);

bool thread_pause_all(ThreadID dont_pause_me_bro_or_sth_i_dunno_lol, bool is_guest_threads_paused);
bool thread_resume_all(bool is_guest_threads_paused);

ThreadID thread_decode_id(u32 encID);

/****** LOADED BINARIES ******/
/*
 * TODO: this
 */
void loadable_register(u64 base_addr, u64 size, std::string name);
void loadable_unregister();

static void capture_context_handler(int sig, siginfo_t* si, void* ucontext);

// Why are the dogs peeing with one paw up?

} // namespace Core::Devtools::GdbData