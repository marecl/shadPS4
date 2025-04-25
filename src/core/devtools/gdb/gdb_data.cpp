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
#include "core/debug_state.h"
#include "core/libraries/kernel/threads/pthread.h"
#include "core/libraries/libs.h"
#include "core/memory.h"
#include "core/thread.h"
#include "gdb_data.h"

using namespace DebugStateType;

using namespace ::Libraries::Kernel;

namespace Data {

std::mutex guest_threads_mutex{};
static std::unordered_map<u64, u32> thread_list_name_pthr;

// loadables
typedef std::tuple<u64, u64, std::string> loadable_info_t;
std::vector<loadable_info_t> loaded_binaries;
} // namespace Data

namespace Core::Devtools::GdbData {

using namespace ::Libraries::Kernel;

DebugStateImpl& DebugState = *Common::Singleton<DebugStateImpl>::Instance();

bool thread_register(u64 tid) {
    std::lock_guard lock{Data::guest_threads_mutex};
    try {
        const u32 id_encoded = 1 + ((~tid) & 0x7FFFFFFF);
        Data::thread_list_name_pthr[tid] = id_encoded;

        char XD[128];
        pthread_getname_np(tid, XD, 256);
        std::string thrname = std::string(XD);

        LOG_INFO(Debug, "Thread registered: {} ({:x} -> {:x})", thrname, tid, id_encoded);
        return true;
    } catch (...) {
    }
    return false;
}

bool thread_unregister(u64 tid) {
    std::lock_guard lock{Data::guest_threads_mutex};
    try {
        Data::thread_list_name_pthr.erase(tid);

        char XD[128];
        pthread_getname_np(tid, XD, 256);
        std::string thrname = std::string(XD);

        LOG_INFO(Debug, "Thread unregistered: {} ({:x})", thrname, tid);
        return true;
    } catch (...) {
    }

    return false;
}

u64 thread_decode_id(u32 id) {
    if (id == 0 || id == -1)
        return 0;

    try {
        for (auto& [tid, encoded_id] : Data::thread_list_name_pthr) {
            if (encoded_id == id) {
                return tid;
            }
        }
    } catch (...) {
    }
    LOG_ERROR(Debug, "Thread doesn't exist with this encoded ID: {:x}", id);
    return 0;
}
#include <pthread.h>
/*

Stephen — 23:28
Core::MemoryManager holds the emulated memory stuff, while Core::AddressSpace has the all the
corresponding host memory mappings.


*/
// Name, original ID, short/encoded ID
std::vector<std::tuple<std::string, u64, u32>> thread_list(void) {
    std::vector<std::tuple<std::string, u64, u32>> out;

    for (auto& [pid, encoded_id] : Data::thread_list_name_pthr) {
        char XD[128];
        pthread_getname_np(pid, XD, 256);
        std::string thrname = std::string(XD);
        out.emplace_back(thrname, pid, encoded_id);
    }

    return out;
}

void loadable_register(u64 base_addr, u64 size, std::string name) {
    Data::loadable_info_t entry(base_addr, size, name);
    Data::loaded_binaries.emplace_back(entry);
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

void loadable_unregister() {
    LOG_WARNING(Debug, "If you see this we're fucked (this function is never called)");
}

} // namespace Core::Devtools::GdbData