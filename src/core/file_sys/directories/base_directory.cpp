// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/alignment.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/base_directory.h"
#include "core/file_sys/fs.h"
#include "core/libraries/kernel/orbis_error.h"

namespace Core::Directories {

BaseDirectory::BaseDirectory() {
    // remember to handle adding [.] and [..] in derived classes
    this->file_offset = 0;
};

BaseDirectory::~BaseDirectory() = default;

s64 BaseDirectory::read(void* buf, u64 nbytes) {
    auto pread_result = this->pread(buf, nbytes, this->file_offset);
    if (pread_result >= 0)
        this->file_offset += pread_result;
    return pread_result;
}

s64 BaseDirectory::readv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt) {
    if (this->file_offset >= this->directory_size)
        return 0;

    s64 bytes_read = 0;
    for (s32 i = 0; i < iovcnt; i++) {
        const s64 result = read(iov[i].iov_base, iov[i].iov_len);
        if (result < 0) {
            return result;
        }
        bytes_read += result;
    }
    return bytes_read;
}

s64 BaseDirectory::preadv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt, s64 offset) {
    if (this->file_offset >= this->directory_size)
        return 0;

    const u64 old_file_pointer = file_offset;
    file_offset = offset;
    const s64 bytes_read = readv(iov, iovcnt);
    file_offset = old_file_pointer;
    return bytes_read;
}

s64 BaseDirectory::lseek(s64 offset, s32 whence) {
    if (whence < 0 || whence > 4)
        return ORBIS_KERNEL_ERROR_EINVAL;
    if (whence == 3 || whence == 4)
        return ORBIS_KERNEL_ERROR_ENOTTY;

    s64 offset_new{};
    s64 offset_origin = ((0 == whence) * 0) +             // beginning
                        ((1 == whence) * file_offset) +   // curpos
                        ((2 == whence) * directory_size); // end

    if (__builtin_add_overflow(offset_origin, offset, &offset_new)) {
        return ORBIS_KERNEL_ERROR_EOVERFLOW;
    }
    if (offset_new < 0) {
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    file_offset = offset_new;
    return file_offset;
}

s64 BaseDirectory::validate_dirent(const BaseDirectoryDirent* dirent) {
    // N/A it'd need offset to calculate reclen correctly
    // i think this test is duplicated somewhere here too
    // auto _reclen = 8 + dirent->d_namlen + 1;
    // _reclen      = ISAL(_reclen, 8) ? _reclen : ALUP(_reclen, 8);
    // if (_reclen != dirent->d_reclen) return -10;

    // best case scenario tbh
    if (!Common::IsAligned(dirent->d_reclen, 4))
        return -10;
    if (dirent->d_fileno == 0)
        return -11;

    // these don't fail so often
    if (dirent->d_namlen == 0)
        return -12;
    if (dirent->d_type == 0)
        return -13;
    if (dirent->d_reclen == 0)
        return -14;
    if (dirent->d_reclen < 12 || dirent->d_reclen > 512)
        return -16;
    if (dirent->d_type > 15)
        return -17;
    if (strnlen(dirent->d_name, 255) != dirent->d_namlen)
        return -18;

    return 1;
}

u8 BaseDirectory::std2bsdFileType(std::filesystem::file_type type) {
    switch (type) {
    default:
        break;
    case std::filesystem::file_type::fifo:
        return 001;
    case std::filesystem::file_type::character:
        return 002;
    case std::filesystem::file_type::directory:
        return 004;
    case std::filesystem::file_type::block:
        return 006;
    case std::filesystem::file_type::regular:
        return 010;
    case std::filesystem::file_type::symlink:
        return 012;
    case std::filesystem::file_type::socket:
        return 014;
        // DT_WHT 016 unsupported
    }
    // UNREACHABLE_MSG("XD");
    return 000;
}
} // namespace Core::Directories