// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "core/libraries/kernel/file_system.h"
#include "core/libraries/kernel/orbis_error.h"

namespace Libraries::Kernel {
struct OrbisKernelStat;
struct OrbisKernelIovec;
struct OrbisKernelDirent;
} // namespace Libraries::Kernel

namespace Core::Directories {

class BaseDirectory {
protected:
#pragma pack(push, 1)
    typedef struct {
        u32 d_fileno;
        u16 d_reclen;
        u8 d_type;
        u8 d_namlen;
        char d_name[256];
    } BaseDirectoryDirent;
#pragma pack(pop)

    static u32 next_fileno() {
        static u32 pool = 10;
        return ++pool;
    }

    u64 file_offset{0};
    u64 directory_size{0};
    std::vector<char> dirent_cache_bin{};
    std::unordered_map<std::filesystem::path, u32> dirent_fileno_cache{};

    static s64 validate_dirent(const BaseDirectoryDirent* dirent);
    static u8 std2bsdFileType(std::filesystem::file_type type);

public:
    explicit BaseDirectory();
    virtual ~BaseDirectory();

    virtual s64 pread(void* buf, u64 nbytes, s64 offset) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }
    virtual s64 read(void* buf, u64 nbytes);
    virtual s64 readv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt);
    virtual s64 preadv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt, s64 offset);

    virtual s64 write(const void* buf, u64 nbytes) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }
    virtual s64 pwrite(const void* buf, u64 nbytes, s64 offset) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }
    virtual s64 writev(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }
    virtual s64 pwritev(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt, s64 offset) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    virtual s64 lseek(s64 offset, s32 whence);

    virtual s32 fstat(Libraries::Kernel::OrbisKernelStat* stat) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    virtual s64 getdents(void* buf, u64 nbytes, s64* basep) {
        return ORBIS_KERNEL_ERROR_EBADF;
    }

    void __reset() {
        this->file_offset = 0;
    }
};

} // namespace Core::Directories