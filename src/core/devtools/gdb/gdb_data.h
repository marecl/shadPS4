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

bool thread_register(u64 pid);

bool thread_unregister(u64 pid);

u64 thread_decode_id(u32 id);
// void -> thread name, thread ID, short thread ID
std::vector<std::tuple<std::string, u64, u32>> thread_list(void);

/****** LOADED BINARIES ******/
/*
 * TODO: this
 */
void loadable_register(u64 base_addr, u64 size, std::string name);
void loadable_unregister();

} // namespace Core::Devtools::GdbData