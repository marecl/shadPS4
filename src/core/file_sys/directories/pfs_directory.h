// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <memory>
#include <string_view>

#include "common/types.h"
#include "core/file_sys/directories/base_directory.h"

namespace Core::Directories {

class PfsDirectory final : public BaseDirectory {
public:
#pragma pack(push, 1)
    typedef struct {
        u32 d_fileno;
        u32 d_type;
        u32 d_namlen;
        u32 d_reclen;
        char d_name[256];
    } PfsDirectoryDirent;
#pragma pack(pop)

    static std::shared_ptr<PfsDirectory> Create(std::string_view guest_path);
    static s64 validate_dirent(const PfsDirectoryDirent* dirent);

    explicit PfsDirectory(std::string_view guest_path);
    ~PfsDirectory() override = default;

    virtual s64 pread(void* buf, u64 nbytes, s64 offset) override;
    virtual s64 lseek(s64 offset, s32 whence) override;
    virtual s32 fstat(Libraries::Kernel::OrbisKernelStat* stat) override;
    virtual s64 getdents(void* buf, u64 nbytes, s64* basep) override;

private:
    static const u32 dirent_meta_size =
        sizeof(PfsDirectoryDirent::d_fileno) + sizeof(PfsDirectoryDirent::d_type) +
        sizeof(PfsDirectoryDirent::d_namlen) + sizeof(PfsDirectoryDirent::d_reclen);
    u64 suggested_file_offset{};
    s64 nearest_dirent(const char* buffer, s64 size, s64 offset);
};
} // namespace Core::Directories
