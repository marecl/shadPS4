// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <filesystem>

#include "common/types.h"
#include "core/file_sys/directories/base_directory.h"

namespace Core::Directories {

class NormalDirectory final : public BaseDirectory {
public:
    using NormalDirectoryDirent = BaseDirectoryDirent;

    static std::shared_ptr<NormalDirectory> Create(std::string_view guest_path);
    static s64 validate_dirent(const NormalDirectoryDirent* dirent) {
        return BaseDirectory::validate_dirent(dirent);
    }

    explicit NormalDirectory(std::string_view guest_path);
    ~NormalDirectory() override = default;

    virtual s64 pread(void* buf, u64 nbytes, s64 offset) override;
    virtual s32 fstat(Libraries::Kernel::OrbisKernelStat* stat) override;
    virtual s64 getdents(void* buf, u64 nbytes, s64* basep) override;

private:
    static const u32 dirent_meta_size =
        sizeof(NormalDirectoryDirent::d_fileno) + sizeof(NormalDirectoryDirent::d_type) +
        sizeof(NormalDirectoryDirent::d_namlen) + sizeof(NormalDirectoryDirent::d_reclen);

    const std::string guest_directory{};
    std::filesystem::file_time_type previous_write_time{};

    void RebuildDirents();
};
} // namespace Core::Directories
