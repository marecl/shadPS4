// SPDX-FileCopyrightText: Copyright 2024 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <imgui.h>

#include "common/assert.h"
#include "common/native_clock.h"
#include "common/singleton.h"
#include "debug_state.h"
#include "devtools/widget/common.h"
#include "libraries/kernel/time.h"
#include "libraries/system/msgdialog.h"
#include "video_core/amdgpu/pm4_cmds.h"
#include "video_core/renderer_vulkan/vk_pipeline_cache.h"

using namespace DebugStateType;

DebugStateImpl& DebugState = *Common::Singleton<DebugStateImpl>::Instance();

bool DebugStateType::showing_debug_menu_bar = false;

static ThreadID ThisThreadID() {
#ifdef _WIN32
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif
}

static void PauseThread(ThreadID id) {
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, id);
    SuspendThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(id, SIGUSR1);
#endif
}

static void ResumeThread(ThreadID id) {
#ifdef _WIN32
    auto handle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, id);
    ResumeThread(handle);
    CloseHandle(handle);
#else
    pthread_kill(id, SIGUSR1);
#endif
}

void DebugStateImpl::AddCurrentThreadToGuestList() {
    std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    guest_threads.push_back(id);
}

void DebugStateImpl::RemoveCurrentThreadFromGuestList() {
    std::lock_guard lock{guest_threads_mutex};
    const ThreadID id = ThisThreadID();
    std::erase_if(guest_threads, [&](const ThreadID& v) { return v == id; });
}

std::mutex global_mutex;
std::unordered_map<ThreadID, ucontext_t> captured_contexts;
std::unordered_map<ThreadID, std::condition_variable> cond_vars;
std::unordered_map<ThreadID, std::mutex> cond_mutexes;
std::unordered_map<ThreadID, std::atomic<bool>> ready_flags;

static void capture_context_handler(int sig, siginfo_t* si, void* ucontext) {
    ThreadID this_id = pthread_self();

    std::unique_lock<std::mutex> lock(cond_mutexes[this_id]);
    std::memcpy(&captured_contexts[this_id], ucontext, sizeof(ucontext_t));
    ready_flags[this_id] = true;
    cond_vars[this_id].notify_one();
}

void DebugStateImpl::PauseGuestThreads() {
    struct sigaction sa = {0};
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = capture_context_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    captured_contexts.clear();

    using namespace Libraries::MsgDialog;
    std::unique_lock lock{guest_threads_mutex};
    if (is_guest_threads_paused) {
        return;
    }
    if (ShouldPauseInSubmit()) {
        waiting_submit_pause = false;
        should_show_frame_dump = true;
    }
    bool self_guest = false;
    ThreadID self_id = ThisThreadID();

    for (const auto& id : guest_threads) {
        if (id == self_id) {
            self_guest = true;
        } else {
            PauseThread(id);
            std::unique_lock<std::mutex> lock(cond_mutexes[id]);
            cond_vars[id].wait(lock, [&] { return ready_flags[id].load(); });
        }
    }

    pause_time = Libraries::Kernel::Dev::GetClock()->GetUptime();
    is_guest_threads_paused = true;
    lock.unlock();

    for (auto& [id, ctx] : captured_contexts) {
        std::string out = "";
        u8 bfr[16];
        memcpy(bfr, reinterpret_cast<u8*>(ctx.uc_stack.ss_sp)+ctx.uc_stack.ss_size - 16, 16);

        for (u8 i = 0; i < 16; i++)
            out += std::format("{:02x} ", bfr[i]);
        LOG_INFO(Debug, "{:x} -> RIP: {:x}", reinterpret_cast<u64>(id),
                 ctx.uc_mcontext.gregs[REG_RIP]);
        LOG_INFO(Debug, "\t->Stack Dump: {}", out);
    }

    if (self_guest) {
        PauseThread(self_id);
    }
}

void DebugStateImpl::ResumeGuestThreads() {
    std::lock_guard lock{guest_threads_mutex};
    if (!is_guest_threads_paused) {
        return;
    }

    u64 delta_time = Libraries::Kernel::Dev::GetClock()->GetUptime() - pause_time;
    Libraries::Kernel::Dev::GetInitialPtc() += delta_time;
    for (const auto& id : guest_threads) {
        ResumeThread(id);
    }
    is_guest_threads_paused = false;
}

void DebugStateImpl::RequestFrameDump(s32 count) {
    ASSERT(!DumpingCurrentFrame());
    gnm_frame_dump_request_count = count;
    frame_dump_list.clear();
    frame_dump_list.resize(count);
    const auto f = gnm_frame_count.load() + 1;
    for (size_t i = 0; i < count; ++i) {
        frame_dump_list[i].frame_id = f + i;
    }
    waiting_submit_pause = true;
}

void DebugStateImpl::PushQueueDump(QueueDump dump) {
    ASSERT(DumpingCurrentFrame());
    std::unique_lock lock{frame_dump_list_mutex};
    auto& frame = GetFrameDump();
    { // Find draw calls
        auto data = std::span{dump.data};
        auto initial_data = data.data();
        while (!data.empty()) {
            const auto* header = reinterpret_cast<const AmdGpu::PM4Type3Header*>(data.data());
            const auto type = header->type;
            if (type == 2) {
                data = data.subspan(1);
            } else if (type != 3) {
                UNREACHABLE();
            }
            const AmdGpu::PM4ItOpcode opcode = header->opcode;
            if (Core::Devtools::Widget::IsDrawCall(opcode)) {
                const auto offset =
                    reinterpret_cast<uintptr_t>(header) - reinterpret_cast<uintptr_t>(initial_data);
                const auto addr = dump.base_addr + offset;
                waiting_reg_dumps.emplace(addr, &frame);
                waiting_reg_dumps_dbg.emplace(
                    addr,
                    fmt::format("#{} h({}) queue {} {} {}",
                                frame_dump_list.size() - gnm_frame_dump_request_count, addr,
                                magic_enum::enum_name(dump.type), dump.submit_num, dump.num2));
            }
            data = data.subspan(header->NumWords() + 1);
        }
    }
    frame.queues.push_back(std::move(dump));
}

std::optional<RegDump*> DebugStateImpl::GetRegDump(uintptr_t base_addr, uintptr_t header_addr) {
    const auto it = waiting_reg_dumps.find(header_addr);
    if (it == waiting_reg_dumps.end()) {
        return std::nullopt;
    }
    auto& frame = *it->second;
    waiting_reg_dumps.erase(it);
    waiting_reg_dumps_dbg.erase(waiting_reg_dumps_dbg.find(header_addr));
    return &frame.regs[header_addr - base_addr];
}

void DebugStateImpl::PushRegsDump(uintptr_t base_addr, uintptr_t header_addr,
                                  const AmdGpu::Liverpool::Regs& regs) {
    std::scoped_lock lock{frame_dump_list_mutex};

    auto dump = GetRegDump(base_addr, header_addr);
    if (!dump) {
        return;
    }

    (*dump)->regs = regs;

    for (int i = 0; i < RegDump::MaxShaderStages; i++) {
        if ((*dump)->regs.stage_enable.IsStageEnabled(i)) {
            auto stage = (*dump)->regs.ProgramForStage(i);
            if (stage->address_lo != 0) {
                const auto& info = AmdGpu::Liverpool::SearchBinaryInfo(stage->Address<u32*>());
                auto code = stage->Code();
                (*dump)->stages[i] = PipelineShaderProgramDump{
                    .name = Vulkan::PipelineCache::GetShaderName(Shader::StageFromIndex(i),
                                                                 info.shader_hash),
                    .hash = info.shader_hash,
                    .user_data = *stage,
                    .code = std::vector<u32>{code.begin(), code.end()},
                };
            }
        }
    }
}

void DebugStateImpl::PushRegsDumpCompute(uintptr_t base_addr, uintptr_t header_addr,
                                         const CsState& cs_state) {
    std::scoped_lock lock{frame_dump_list_mutex};

    auto dump = GetRegDump(base_addr, header_addr);
    if (!dump) {
        return;
    }

    (*dump)->is_compute = true;
    auto& cs = (*dump)->regs.cs_program;
    cs = cs_state;

    const auto& info = AmdGpu::Liverpool::SearchBinaryInfo(cs.Address<u32*>());
    (*dump)->cs_data = PipelineComputerProgramDump{
        .name = Vulkan::PipelineCache::GetShaderName(Shader::Stage::Compute, info.shader_hash),
        .hash = info.shader_hash,
        .cs_program = cs,
        .code = std::vector<u32>{cs.Code().begin(), cs.Code().end()},
    };
}

void DebugStateImpl::CollectShader(const std::string& name, Shader::LogicalStage l_stage,
                                   vk::ShaderModule module, std::span<const u32> spv,
                                   std::span<const u32> raw_code, std::span<const u32> patch_spv,
                                   bool is_patched) {
    shader_dump_list.emplace_back(name, l_stage, module, std::vector<u32>{spv.begin(), spv.end()},
                                  std::vector<u32>{raw_code.begin(), raw_code.end()},
                                  std::vector<u32>{patch_spv.begin(), patch_spv.end()}, is_patched);
}
