// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <filesystem>

#include "common/alignment.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/normal_directory.h"
#include "core/file_sys/fs.h"

namespace Core::Directories {

#define BP(x)                                                                                      \
    {                                                                                              \
        for (u16 i = 0; i < 1; i++) {                                                              \
            continue;                                                                              \
        }                                                                                          \
    }

std::shared_ptr<NormalDirectory> NormalDirectory::Create(std::string_view guest_directory) {
    return std::make_shared<NormalDirectory>(guest_directory);
}

NormalDirectory::NormalDirectory(std::string_view guest_directory)
    : guest_directory(std::move(std::string(guest_directory))) {
    this->dirent_fileno_cache.emplace(".", BaseDirectory::next_fileno());  // can be random
    this->dirent_fileno_cache.emplace("..", BaseDirectory::next_fileno()); // should not be random

    RebuildDirents();
}

s64 NormalDirectory::pread(void* buf, u64 nbytes, s64 offset) {
    RebuildDirents();

    if (nbytes == 0)
        return 0;
    if (offset < 0)
        return ORBIS_KERNEL_ERROR_EINVAL;
    if (offset >= this->directory_size)
        return 0;

    // data is contiguous. read goes like any regular file would: start at offset, read n bytes
    // output is always aligned up to 512 bytes with 0s
    // offset - classic. however at the end of read any unused (exceeding dirent buffer size) buffer
    // space will be left untouched
    // reclen always sums up to end of current alignment

    s64 bytes_available =
        std::min<s64>(this->dirent_cache_bin.size() - offset, static_cast<s64>(nbytes));
    if (bytes_available < 0)
        return ORBIS_KERNEL_ERROR_EINVAL;

    // data
    memcpy(buf, this->dirent_cache_bin.data() + offset, bytes_available);

    return bytes_available;
}

s32 NormalDirectory::fstat(Libraries::Kernel::OrbisKernelStat* stat) {
    stat->st_mode = 0000777u | 0040000u;
    stat->st_size = directory_size;
    stat->st_blksize = 0x8000;
    stat->st_blocks = 8;
    return ORBIS_OK;
}

s64 NormalDirectory::getdents(void* buf, u64 nbytes, s64* basep) {
    RebuildDirents();

    s64 apparent_end = this->file_offset + nbytes;
    s64 apparent_end_down = Common::AlignDownAligned(apparent_end, 512);
    s64 file_offset_down = Common::AlignDownAligned(file_offset, 512);

    // within the same sector, no 512b alignment inbetween
    if (apparent_end_down <= file_offset_down) {
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    if (nullptr != basep)
        *basep = file_offset;
    if (file_offset >= directory_size) {
        return 0;
    }

    // we can now assume that offset is always smaller than size
    s64 allowed_count = std::min(u64(apparent_end_down - file_offset), nbytes);
    allowed_count = std::min(u64(allowed_count), directory_size - file_offset);
    allowed_count = Common::AlignDownAligned(allowed_count, 4);

    u64 bytes_written = 0;
    u64 read_offset = file_offset;
    u64 write_offset = 0;

    const char* dirent_buffer = this->dirent_cache_bin.data();

    auto dirent_offset = nearest_dirent(dirent_buffer, allowed_count, read_offset);
    if (0 > dirent_offset) {
        LOG_ERROR(Kernel_Fs, "Error during seeking dirent {}", dirent_offset);
        return 0;
    }
    {
        auto to_copy = std::min(dirent_offset, allowed_count);
        memcpy(buf, dirent_buffer + file_offset, to_copy);
        read_offset += to_copy;
        bytes_written += to_copy;
    }

    while (bytes_written < allowed_count) {
        const auto* dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(dirent_buffer + read_offset);

        if (!validate_dirent(dirent)) {
            break;
        }

        if ((bytes_written + dirent->d_reclen) > allowed_count)
            // dirents are aligned to the last full one
            break;

        memcpy(static_cast<char*>(buf) + bytes_written, dirent_buffer + read_offset,
               dirent->d_reclen);
        bytes_written += dirent->d_reclen;
        read_offset += dirent->d_reclen;
    }

    file_offset += bytes_written;
    return bytes_written;
}

// -1 on not found
// this only used by getdirentries
s64 NormalDirectory::nearest_dirent(const char* buffer, s64 size, s64 offset) {
    // max size is 272, last 23 bytes are never starting a dirent
    s64 offset_adj = Common::IsAligned(offset, 4) ? offset : Common::AlignUpAligned(offset, 4);
    s64 max_advance = std::min(size - offset_adj, s64(256 + dirent_meta_size));
    if (max_advance < 12)
        return -2;

    s64 status{};

    for (s64 out_offset = offset_adj; out_offset <= offset_adj + max_advance; out_offset += 4) {
        const auto* tested_dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(buffer + out_offset);

        if (validate_dirent(tested_dirent) < 0)
            continue;

        out_offset
    }

    for (s64 out_offset = offset_adj; out_offset <= offset_adj + max_advance; out_offset += 4) {
        const auto* tested_dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(buffer + out_offset);

        if (validate_dirent(tested_dirent) < 0)
            continue;

        return out_offset - offset;
    }

    return status;
}

void NormalDirectory::RebuildDirents() {
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();

    const std::filesystem::file_time_type write_time =
        std::filesystem::last_write_time(mnt->GetHostPath(this->guest_directory, nullptr));

    // regenerate only when contents changed
    if (write_time == previous_write_time)
        return;
    previous_write_time = write_time;

    std::vector<std::pair<std::filesystem::path, bool>> file_list{{".", false}, {"..", false}};

    mnt->IterateDirectory(guest_directory, [&file_list, this](const std::filesystem::path& ent_path,
                                                              const bool ent_is_file) {
        file_list.emplace_back(ent_path, ent_is_file);
        this->dirent_fileno_cache.emplace(ent_path.filename().string(),
                                          BaseDirectory::next_fileno());
    });

    u64 fcnt = 0; // entry counter, can be removed
    u64 last_reclen_offset = 4;
    u16* last_reclen_data_ptr{};
    dirent_cache_bin.clear();
    dirent_cache_bin.reserve(512);
    dirent_cache_bin.resize(0);

    char sector[512]{0};
    s16 sector_remaining = 512;
    for (const auto& [file_path, is_file] : file_list) {
        if (sector_remaining < 0)
            break;
        NormalDirectoryDirent tmp{};
        std::string leaf(file_path.filename().string());

        auto [elem, inserted] = dirent_fileno_cache.emplace(leaf, 0);
        if (inserted) {
            elem->second = BaseDirectory::next_fileno();
        }

        // prepare dirent
        tmp.d_fileno = elem->second;
        tmp.d_namlen = elem->first.size();
        strncpy(tmp.d_name, leaf.data(), tmp.d_namlen + 1);
        tmp.d_type = (is_file ? 0100000 : 0040000) >> 12;
        tmp.d_reclen = Common::AlignUp(dirent_meta_size + tmp.d_namlen + 1, 4);

        // next element may break 512 byte alignment
        if (sector_remaining - tmp.d_reclen < 0) { // 12 bytes is the minimal size
            // align previous dirent's size to the current ceiling
            last_reclen_data_ptr = reinterpret_cast<u16*>(sector + last_reclen_offset);
            // any other way of updating last reclen??? this seems to be not working :<
            *last_reclen_data_ptr += sector_remaining;

            sector_remaining = 512;
            dirent_cache_bin.insert(dirent_cache_bin.end(), sector, sector + 512);
            memset(sector, 0, 512);
        }

        // current dirent's reclen position
        memcpy(sector + 512 - sector_remaining, &tmp, tmp.d_reclen);
        last_reclen_offset = 512 - sector_remaining + 4;
        sector_remaining -= tmp.d_reclen;
        fcnt++;
    }

    if (sector_remaining > 0 &&
        sector_remaining < 512) { // 0 is covered by if statement, 512 sector has been just written
        last_reclen_data_ptr = reinterpret_cast<u16*>(sector + last_reclen_offset);
        *last_reclen_data_ptr += sector_remaining;
        dirent_cache_bin.insert(dirent_cache_bin.end(), sector, sector + 512);
    }
    // i have no idea if this is the case, but lseek returns size aligned to 512
    directory_size = dirent_cache_bin.size();

    LOG_ERROR(Kernel_Fs, "Refreshed directory: {} , {} entries indexed , size {}",
              this->guest_directory, fcnt, this->directory_size);
}

} // namespace Core::Directories