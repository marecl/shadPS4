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
#include "core/libraries/kernel/kernel.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"

namespace Core::Devtools::GdbData {

namespace Data {
static std::unordered_map<u64, const char*> thread_list_name;
static std::unordered_map<u64, u32> thread_list_pid_forTool;  // for outside tools
static std::unordered_map<u32, u64> thread_list_pid_fromTool; // for internal use
} // namespace Data

bool thread_register(u64 id, const char* name) {
    try {
        const u32 id_encoded = 1 + ((~id) & 0x7FFFFFFF);

        Data::thread_list_name[id] = name;
        Data::thread_list_pid_forTool[id] = id_encoded;
        Data::thread_list_pid_fromTool[id_encoded] = id;

        LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", name, id, id_encoded);
        return true;
    } catch (...) {
    }
    return false;
}

bool thread_unregister(u64 id) {
    try {
        const u32 id_encoded = Data::thread_list_pid_forTool[id];
        std::string name = std::string(Data::thread_list_name[id]);

        Data::thread_list_name.erase(id);
        Data::thread_list_pid_forTool.erase(id);
        Data::thread_list_pid_fromTool.erase(id_encoded);

        LOG_INFO(Debug, "Thread unregistered: {} ({:x} -> {:x})", name, id, id_encoded);
        return true;
    } catch (...) {
    }

    return false;
}

u32 thread_encode_id(u64 id) {
    try {
        return Data::thread_list_pid_forTool[id];
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this ID: {:x}", id);
    return 0;
}

u64 thread_decode_id(u32 id) {
    try {
        return Data::thread_list_pid_fromTool[id];
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", id);
    return 0;
}

// Name, original ID, short/encoded ID
std::vector<std::tuple<const char*, u64, u32>> thread_list(void) {
    std::vector<std::tuple<const char*, u64, u32>> out;

    for (auto& [pthread_id, thread_name] : Data::thread_list_name) {
        out.emplace_back(thread_name, pthread_id, thread_encode_id(pthread_id));
    }

    return out;
}
} // namespace Core::Devtools::GdbData