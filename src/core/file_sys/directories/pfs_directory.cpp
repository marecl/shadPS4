// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <ranges>

#include "common/alignment.h"
#include "common/assert.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/pfs_directory.h"
#include "core/file_sys/fs.h"

namespace Core::Directories {

std::shared_ptr<BaseDirectory> PfsDirectory::Create(std::string_view guest_directory) {
    return std::make_shared<PfsDirectory>(guest_directory);
}

PfsDirectory::PfsDirectory(std::string_view guest_directory) {
    constexpr u32 dirent_meta_size =
        sizeof(PfsDirectoryDirent::d_fileno) + sizeof(PfsDirectoryDirent::d_type) +
        sizeof(PfsDirectoryDirent::d_namlen) + sizeof(PfsDirectoryDirent::d_reclen);

    directory_size = 0;
    dirent_cache_bin.reserve(512);

    std::vector<std::pair<std::filesystem::path, bool>> file_list{};
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();

    mnt->IterateDirectory(guest_directory, [&file_list, this](const std::filesystem::path& ent_path,
                                                              const bool ent_is_file) {
        file_list.emplace_back(ent_path, ent_is_file);
        this->dirent_fileno_cache.emplace(ent_path.filename().string(),
                                          BaseDirectory::next_fileno());
    });

    std::ranges::sort(file_list.begin(), file_list.end());
    file_list.emplace(file_list.begin(), "..", false);
    file_list.emplace(file_list.begin(), ".", false);

    for (const auto& [file_path, is_file] : file_list) {
        PfsDirectoryDirent tmp{};
        std::string leaf(file_path.filename().string());
        auto elem = dirent_fileno_cache.find(leaf);

        tmp.d_fileno = elem->second;
        tmp.d_namlen = leaf.size();
        strncpy(tmp.d_name, leaf.data(), tmp.d_namlen + 1);
        tmp.d_type = is_file ? 2 : 4;
        tmp.d_reclen = Common::AlignUp(dirent_meta_size + tmp.d_namlen + 1, 8);
        auto dirent_ptr = reinterpret_cast<const u8*>(&tmp);

        dirent_cache_bin.insert(dirent_cache_bin.end(), dirent_ptr, dirent_ptr + tmp.d_reclen);
        directory_size += tmp.d_reclen;
    }

    directory_size = Common::AlignUpAligned(dirent_cache_bin.size(), 0x10000);
}

s64 PfsDirectory::pread(void* buf, u64 nbytes, s64 offset) {
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
    BaseDirectory::lseek(offset, whence);
    // refresh here, so correct offset is cached
    // we're spending a bit more time here, but lseek() isn't called that often
    // would be a waste if done every time getdents is called
    this->suggested_file_offset =
        this->file_offset + backtrack_dirent(this->dirent_cache_bin.data(), this->file_offset,
                                             this->dirent_cache_bin.size());
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
    if (basep)
        *basep = file_offset;

    // down-aligned apparent end, last crossed sector
    auto apparent_end = this->file_offset + nbytes;
    auto apparent_end_down = Common::AlignDownAligned(apparent_end, 512);
    auto apparent_end_up = Common::AlignUpAligned(apparent_end, 512);
    auto file_offset_aligned = Common::AlignDownAligned(this->file_offset, 512);

    auto file_offset_up = Common::AlignUpAligned(this->file_offset, 512);

    if (apparent_end_up == file_offset_up)
        return ORBIS_KERNEL_ERROR_EINVAL;

    if (nbytes < (file_offset_up - this->file_offset))
        return 0;

    // navigate to latest backtracked dirent
    if (this->suggested_file_offset < this->file_offset)
        this->file_offset = this->suggested_file_offset;

    apparent_end_down =
        std::min(this->dirent_cache_bin.size() - this->file_offset, apparent_end_down);
    apparent_end_down = std::min(nbytes, apparent_end_down);
    u64 bytes_written = 0;
    u64 buffer_position = this->file_offset;

    // same as others, we just don't need a variable
    if (this->file_offset >= this->dirent_cache_bin.size()) {
        this->file_offset = this->directory_size;
        goto pfs_getdents_end;
    }

    while (bytes_written < apparent_end_down) {
        const PfsDirectoryDirent* pfs_dirent =
            reinterpret_cast<PfsDirectoryDirent*>(this->dirent_cache_bin.data() + buffer_position);

        // bad, incomplete or OOB entry
        if (pfs_dirent->d_namlen == 0)
            break;

        if ((bytes_written + pfs_dirent->d_reclen) > nbytes)
            // dirents are aligned to the last full one
            break;

        // if this dirent breaks alignment, skip
        // dirents are count-aligned here, excess data is simply not written
        // if (Common::AlignUp(buffer_position, count) !=
        //     Common::AlignUp(buffer_position + pfs_dirent->d_reclen, count))
        //     break;

        // reclen for both is the same despite difference in var sizes, extra 0s are padded after
        // the name
        NormalDirectoryDirent normal_dirent{};
        normal_dirent.d_fileno = pfs_dirent->d_fileno;
        normal_dirent.d_reclen = pfs_dirent->d_reclen;
        normal_dirent.d_type = (pfs_dirent->d_type == 2) ? 8 : 4;
        normal_dirent.d_namlen = pfs_dirent->d_namlen;
        memcpy(normal_dirent.d_name, pfs_dirent->d_name, pfs_dirent->d_namlen);

        memcpy(static_cast<u8*>(buf) + bytes_written, &normal_dirent, normal_dirent.d_reclen);
        bytes_written += normal_dirent.d_reclen;
        buffer_position += normal_dirent.d_reclen;
    }

    this->file_offset = (buffer_position >= this->dirent_cache_bin.size())
                            ? directory_size
                            : (file_offset + bytes_written);
pfs_getdents_end:
    this->suggested_file_offset = this->file_offset;
    return bytes_written;
}

bool PfsDirectory::detect_dirent(const void* buffer, u64 buffer_length) {
    const PfsDirectoryDirent* dirent = reinterpret_cast<const PfsDirectoryDirent*>(buffer);

    // these are ordered by how likely it is to fail first

    // size aligned to 8 bytes
    if ((dirent->d_reclen & 0x07) != 0)
        return false;
    // valid sizes is 24-272
    if (dirent->d_type > 15)
        return false;
    if (dirent->d_reclen > 272)
        return false;
    if (dirent->d_reclen < 24)
        return false;
    if (std::min(buffer_length - 16, static_cast<u64>(dirent->d_namlen)) > 255)
        return false;

    return true;
}

// return relative position of a backtracked dirent
// always negative lmao
// 5-6it for short names, 34 at most for maxed out dirent
// but at one point certainly faster for huge directories
s64 PfsDirectory::backtrack_dirent(const void* buffer, u64 target_offset, u64 buffer_length) {
    // can't go further back, just start over
    if (target_offset < 272)
        return -target_offset;

    u64 offset{}; // max dirent size, no point in looking further back

    for (offset = target_offset; offset >= (target_offset - 272); offset -= 8) {
        if (!detect_dirent(reinterpret_cast<const u8*>(buffer) + offset,
                           std::min(buffer_length, (u64)255)))
            continue;
        break;
    }

    return offset - target_offset;
}

} // namespace Core::Directories