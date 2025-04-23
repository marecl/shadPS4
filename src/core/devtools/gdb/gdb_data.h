// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <thread>
#include <tuple>
#include <unordered_map>
#include <vector>
#include "common/types.h"

namespace Core::Devtools::GdbData {

bool thread_register(u64 id, const char* name);
bool thread_unregister(u64 id);
u32 thread_encode_id(u64 id);
u64 thread_decode_id(u32 id);

std::vector<std::tuple<const char*, u64, u32>> thread_list(void);


}