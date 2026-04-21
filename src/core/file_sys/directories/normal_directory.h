// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <filesystem>

#include "common/types.h"
#include "core/file_sys/directories/base_directory.h"

namespace Core::Directories {

class NormalDirectory final : public BaseDirectory {
public:
    static std::shared_ptr<NormalDirectory> Create(std::string_view guest_path);
    explicit NormalDirectory(std::string_view guest_path);
    ~NormalDirectory() override = default;

    virtual s64 pread(void* buf, u64 nbytes, s64 offset) override;
    virtual s32 fstat(Libraries::Kernel::OrbisKernelStat* stat) override;
    virtual s64 getdents(void* buf, u64 nbytes, s64* basep) override;

private:
#pragma pack(push, 1)
    struct NormalDirectoryDirent {
        u32 d_fileno;
        u16 d_reclen;
        u8 d_type;
        u8 d_namlen;
        char d_name[256];
    };
#pragma pack(pop)

    const std::string guest_directory{};
    std::filesystem::file_time_type previous_write_time{};

    void RebuildDirents();
};
} // namespace Core::Directories
