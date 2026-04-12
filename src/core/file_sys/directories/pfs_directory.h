// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <memory>
#include <string_view>
#include <vector>
#include "common/types.h"
#include "core/file_sys/directories/base_directory.h"
#include "core/libraries/kernel/orbis_error.h"

namespace Core::Directories {

class PfsDirectory final : public BaseDirectory {
public:
    static std::shared_ptr<BaseDirectory> Create(std::string_view guest_path);
    explicit PfsDirectory(std::string_view guest_path);
    ~PfsDirectory() override = default;

    virtual s64 pread(void* buf, u64 nbytes, s64 offset) override;
    virtual s64 lseek(s64 offset, s32 whence) override;
    virtual s32 fstat(Libraries::Kernel::OrbisKernelStat* stat) override;
    virtual s64 getdents(void* buf, u64 nbytes, s64* basep) override;

private:
    u64 suggested_file_offset{};
    bool detect_dirent(const void* buffer, u64 buffer_length);
    s64 backtrack_dirent(const void* buffer, u64 target_offset, u64 buffer_length);

#pragma pack(push, 1)
    struct PfsDirectoryDirent {
        u32 d_fileno;
        u32 d_type;
        u32 d_namlen;
        u32 d_reclen;
        char d_name[256];
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct NormalDirectoryDirent {
        u32 d_fileno;
        u16 d_reclen;
        u8 d_type;
        u8 d_namlen;
        char d_name[256];
    };
#pragma pack(pop)
};
} // namespace Core::Directories
