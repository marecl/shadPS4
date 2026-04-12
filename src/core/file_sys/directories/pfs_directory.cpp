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
    if (this->file_offset >= this->directory_size)
        return 0;
        
        // could simplify it, but we are not going to allocate entire 64k blocks for a single directory
    s64 data_to_write = this->dirent_cache_bin.size() - offset;
    if (data_to_write < 0)
        data_to_write = 0;
    data_to_write = std::min(data_to_write, static_cast<s64>(nbytes));

    s64 data_to_fill = nbytes - data_to_write;
    if (data_to_fill < 0)
        data_to_fill = 0;

    s64 total_available = this->directory_size - offset;
    if (total_available > data_to_write)
        total_available -= data_to_write;
    if (total_available < data_to_fill)
        data_to_fill = total_available;

    memcpy(buf, this->dirent_cache_bin.data() + offset, data_to_write);
    memset(static_cast<u8*>(buf) + data_to_write, 0, data_to_fill);

    return data_to_write + data_to_fill;
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
    auto read_limit = Common::AlignDownAligned(this->file_offset + nbytes, 512);

    // offset aligned up = next ceiling to cross (when data will be read at all)
    if (read_limit < Common::AlignUpAligned(this->file_offset, 512)) {
        // apparent end is not equal or greater than nearest sector alignment
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    // same as others, we just don't need a variable
    if (this->file_offset > this->dirent_cache_bin.size()) {
        this->file_offset = this->directory_size;
        return 0;
    }

    read_limit = std::min(this->dirent_cache_bin.size() - this->file_offset, read_limit);
    u64 bytes_written = 0;
    u64 starting_offset = 0;
    u64 buffer_position = 0;

    while (buffer_position < read_limit) {
        const PfsDirectoryDirent* pfs_dirent =
            reinterpret_cast<PfsDirectoryDirent*>(this->dirent_cache_bin.data() + buffer_position);

        // bad, incomplete or OOB entry
        if (pfs_dirent->d_namlen == 0)
            break;

        if (starting_offset < file_offset) {
            // reading starts from the nearest full dirent
            starting_offset += pfs_dirent->d_reclen;
            buffer_position = bytes_written + starting_offset;
            continue;
        }

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
        buffer_position = bytes_written + starting_offset;
    }

    file_offset = (buffer_position >= this->dirent_cache_bin.size())
                      ? directory_size
                      : (file_offset + bytes_written);
    return bytes_written;
}
} // namespace Core::Directories