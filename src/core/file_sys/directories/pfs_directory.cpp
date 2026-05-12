// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <ranges>

#include "common/alignment.h"
#include "common/assert.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/normal_directory.h"
#include "core/file_sys/directories/pfs_directory.h"
#include "core/file_sys/fs.h"

namespace Core::Directories {

std::shared_ptr<PfsDirectory> PfsDirectory::Create(std::string_view guest_directory) {
    return std::make_shared<PfsDirectory>(guest_directory);
}

PfsDirectory::PfsDirectory(std::string_view guest_directory) {
    const std::filesystem::path guest_directory_path = guest_directory;
    directory_size = 0;
    suggested_file_offset = 0;
    dirent_cache_bin.reserve(512);

    std::vector<std::pair<std::filesystem::path, u8>> file_list{};
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();

    mnt->IterateDirectory(guest_directory,
                          [&file_list, this](const auto& file_path, const auto& file_type) {
                              file_list.emplace_back(file_path, std2pfsFileType(file_type));
                          });

    std::ranges::sort(file_list, std::ranges::less{}, &std::pair<std::filesystem::path, u8>::first);
    file_list.emplace(file_list.begin(), "..",
                      std2pfsFileType(std::filesystem::file_type::directory));
    file_list.emplace(file_list.begin(), ".",
                      std2pfsFileType(std::filesystem::file_type::directory));

    for (const auto& [file_path, file_type] : file_list) {
        PfsDirectoryDirent tmp{};

        const auto file_leaf = file_path.filename().string();

        tmp.d_fileno = PfsDirectory::next_fileno();
        tmp.d_namlen = file_leaf.size();
        strncpy(tmp.d_name, file_leaf.c_str(), tmp.d_namlen + 1);

        tmp.d_type = file_type;
        tmp.d_reclen = Common::AlignUp(dirent_meta_size + tmp.d_namlen + 1, 8);
        auto dirent_ptr = reinterpret_cast<const u8*>(&tmp);

        dirent_cache_bin.insert(dirent_cache_bin.end(), dirent_ptr, dirent_ptr + tmp.d_reclen);
        directory_size += tmp.d_reclen;
    }

    directory_size = Common::AlignUpAligned(dirent_cache_bin.size(), 0x10000);
}

s64 PfsDirectory::pread(void* buf, u64 nbytes, s64 offset) {
    if (nbytes == 0)
        return 0;
    if (offset < 0)
        return ORBIS_KERNEL_ERROR_EINVAL;
    if (offset >= this->directory_size)
        return 0;

    s64 total_available = this->directory_size - offset;
    if (total_available <= 0)
        return 0;

    s64 total_buffer_available = this->dirent_cache_bin.size() - offset;
    if (total_buffer_available < 0)
        total_buffer_available = 0;
    s64 data_to_write = std::min(static_cast<s64>(nbytes), total_buffer_available);
    s64 data_to_fill = std::min(static_cast<s64>(nbytes), total_available) - data_to_write;
    if (data_to_fill < 0)
        data_to_fill = 0;

    memcpy(buf, this->dirent_cache_bin.data() + offset, data_to_write);
    memset(static_cast<u8*>(buf) + data_to_write, 0, data_to_fill);

    return data_to_write + data_to_fill;
}

s64 PfsDirectory::lseek(s64 offset, s32 whence) {
    if (auto test = BaseDirectory::lseek(offset, whence); test < 0)
        return test;

    // refresh here, so correct offset is cached
    // we're spending a bit more time here, but lseek() isn't called that often
    // would be a waste if done every time getdents is called
    this->suggested_file_offset = nearest_dirent(this->dirent_cache_bin.data(), this->file_offset);
    return this->file_offset;
}

s32 PfsDirectory::fstat(Libraries::Kernel::OrbisKernelStat* stat) {
    stat->st_mode = 0000777u | 0040000u;
    stat->st_size = directory_size;
    stat->st_blksize = 0x10000;
    stat->st_blocks = 0x80;
    return ORBIS_OK;
}

s64 PfsDirectory::getdents(void* buf, u64 nbytes, s64* basep) {
    // file offset - current offset, used for boundary calculations
    // suggested file offset - next dirent
    // all data between those two is consumed

    s64 apparent_end = this->file_offset + nbytes;
    s64 apparent_end_down = Common::AlignDownAligned(apparent_end, 512);
    s64 file_offset_down = Common::AlignDownAligned(file_offset, 512);

    // within the same sector, no 512b alignment inbetween
    // applies to full dirents only
    if (apparent_end_down <= file_offset_down) {
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    // now that offset
    if (nullptr != basep)
        *basep = file_offset;

    if (this->suggested_file_offset < 0) {
        // no valid dirent found
        this->file_offset = this->directory_size;
        this->suggested_file_offset = this->directory_size;
        return 0;
    }

    if (this->file_offset >= this->dirent_cache_bin.size()) {
        // oob
        this->file_offset = this->directory_size;
        this->suggested_file_offset = this->directory_size;
        return 0;
    }

    // we can now assume that offset is always smaller than size
    const char* dirent_buffer = this->dirent_cache_bin.data();
    s64 allowed_count = std::min(apparent_end_down - file_offset, nbytes);
    u64 bytes_written = 0;
    u64 read_offset = this->suggested_file_offset;
    u64 write_offset = 0;

    while (read_offset < directory_size) {
        const PfsDirectoryDirent* pfs_dirent =
            reinterpret_cast<const PfsDirectoryDirent*>(dirent_buffer + read_offset);

        if (this->validate_dirent(pfs_dirent) < 0) {
            // probably OOB
            break;
        }

        // read + reclen is an invalid break reason here
        // read and true read (dirent) are different:
        //   read - raw pointer, aligned to data
        //   true read - aligned to dirent, ignoring sector boundary

        if ((bytes_written + pfs_dirent->d_reclen) > allowed_count) {
            // last dirent must be complete
            break;
        }

        // reclen for both is the same despite difference in var sizes, extra 0s are padded after
        // the name
        NormalDirectory::NormalDirectoryDirent normal_dirent{};
        normal_dirent.d_fileno = pfs_dirent->d_fileno;
        normal_dirent.d_reclen = pfs_dirent->d_reclen;
        normal_dirent.d_type = pfs2bsdFileType(pfs_dirent->d_type);
        normal_dirent.d_namlen = pfs_dirent->d_namlen;
        memcpy(normal_dirent.d_name, pfs_dirent->d_name, pfs_dirent->d_namlen);

        memcpy(static_cast<u8*>(buf) + bytes_written, &normal_dirent, normal_dirent.d_reclen);
        bytes_written += normal_dirent.d_reclen;
        read_offset += normal_dirent.d_reclen;
    }

    // directory size is for outsiders, aligned to 65536
    this->file_offset = (read_offset >= this->dirent_cache_bin.size())
                            ? this->directory_size
                            : (file_offset + bytes_written);
    this->suggested_file_offset = file_offset;
    return bytes_written;
}

// -1 on not found
// this only used by getdirentries
s64 PfsDirectory::nearest_dirent(const char* buffer, s64 offset) {
    s64 max_advance = std::min(s64(directory_size) - offset, s64(256 + dirent_meta_size));
    if (max_advance < 24) {
        // minimal dirent size
        return -1;
    }

    // there is no point in testing when offset is misaligned
    s64 new_offset = Common::IsAligned(offset, 8) ? offset : Common::AlignUpAligned(offset, 8);
    for (; new_offset < (offset + max_advance); new_offset += 8) {
        const auto* tested_dirent =
            reinterpret_cast<const PfsDirectoryDirent*>(buffer + new_offset);

        if (this->validate_dirent(tested_dirent) < 0)
            continue;

        return new_offset;
    }

    return -1;
}

s64 PfsDirectory::validate_dirent(const PfsDirectoryDirent* dirent) {
    auto _reclen = dirent_meta_size + dirent->d_namlen + 1;
    _reclen = Common::IsAligned(_reclen, 8) ? _reclen : Common::AlignUpAligned(_reclen, 8);
    if (_reclen != dirent->d_reclen)
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
    if ((dirent->d_reclen & 0x07) != 0)
        return -15;
    if (dirent->d_reclen < 24 || dirent->d_reclen > 272)
        return -16;
    if (dirent->d_type > 15)
        return -17;
    if (strnlen(dirent->d_name, 255) != dirent->d_namlen)
        return -18;

    return 1;
}

u8 PfsDirectory::std2pfsFileType(std::filesystem::file_type type) {
    switch (type) {
    default:
        break;
    case std::filesystem::file_type::regular:
        return 002;
    case std::filesystem::file_type::directory:
        return 004;
    }
    return 000;
}

u8 PfsDirectory::pfs2bsdFileType(u8 type) {
    switch (type) {
    default:
        break;
    case 002:
        // regular
        return 010;
    case 004:
        // directory
        return 004;
    }
    // UNREACHABLE_MSG("XD");
    return 000;
}

} // namespace Core::Directories