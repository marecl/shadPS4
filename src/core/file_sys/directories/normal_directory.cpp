// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <filesystem>

#include "common/alignment.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/normal_directory.h"
#include "core/file_sys/fs.h"

namespace Core::Directories {

std::shared_ptr<NormalDirectory> NormalDirectory::Create(std::string_view guest_directory) {
    return std::make_shared<NormalDirectory>(guest_directory);
}

NormalDirectory::NormalDirectory(std::string_view guest_directory)
    : guest_directory(std::move(std::filesystem::path(guest_directory))) {
    suggested_file_offset = 0;
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

    // data is contiguous. read goes like any regular file would: start at offset, read
    // n bytes output is always aligned up to 512 bytes with 0s offset - classic.
    // however at the end of read any unused (exceeding dirent buffer size) buffer space
    // will be left untouched reclen always sums up to end of current alignment

    s64 bytes_available = std::min<s64>(this->directory_size - offset, static_cast<s64>(nbytes));
    if (bytes_available < 0)
        return ORBIS_KERNEL_ERROR_EINVAL;

    // data
    memcpy(buf, this->dirent_cache_bin.data() + offset, bytes_available);

    return bytes_available;
}

s64 NormalDirectory::lseek(s64 offset, s32 whence) {
    if (auto test = BaseDirectory::lseek(offset, whence); test < 0)
        return test;

    // refresh here, so correct offset is cached
    // we're spending a bit more time here, but lseek() isn't called that often
    // would be a waste if done every time getdents is called
    this->suggested_file_offset = this->file_offset;
    if (auto _tmp = nearest_dirent(this->dirent_cache_bin.data(), this->file_offset); _tmp >= 0)
        // keep positive values only though
        this->suggested_file_offset = _tmp;
    else
        LOG_ERROR(Kernel_Fs, "Error during seeking dirent {}", _tmp);

    return this->file_offset;
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
    // applies to full dirents only
    if (apparent_end_down <= file_offset_down) {
        return ORBIS_KERNEL_ERROR_EINVAL;
    }

    // now that offset
    if (nullptr != basep)
        *basep = file_offset;

    if (this->file_offset >= directory_size) {
        return 0;
    }

    // we can now assume that offset is always smaller than size
    // diff between real and suggested file offset is consumed
    // allowed count = total
    const char* dirent_buffer = this->dirent_cache_bin.data();
    s64 allowed_count = std::min(apparent_end_down - file_offset, nbytes);
    u64 bytes_written = 0;
    u64 read_offset = file_offset;
    u64 write_offset = 0;

    {
        u64 to_copy = std::min(this->suggested_file_offset - this->file_offset, u64(allowed_count));
        memcpy(buf, dirent_buffer + this->file_offset, to_copy);
        read_offset += to_copy;
        bytes_written += to_copy;
    }

    while (bytes_written < allowed_count) {
        const auto* dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(dirent_buffer + read_offset);

        if (validate_dirent(dirent) < 0) {
            // probably OOB
            break;
        }

        // probably redundant, leaving for verbosity
        if ((read_offset + dirent->d_reclen) > apparent_end_down) {
            // can't read further than last full sector
            break;
        }

        if ((bytes_written + dirent->d_reclen) > allowed_count) {
            // last dirent must be complete
            break;
        }

        memcpy(static_cast<char*>(buf) + bytes_written, dirent_buffer + read_offset,
               dirent->d_reclen);
        bytes_written += dirent->d_reclen;
        read_offset += dirent->d_reclen;
    }

    this->file_offset += bytes_written;
    this->suggested_file_offset = file_offset;
    return bytes_written;
}

void NormalDirectory::RebuildDirents() {
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();

    const std::filesystem::file_time_type write_time =
        std::filesystem::last_write_time(mnt->GetHostPath(this->guest_directory.c_str(), nullptr));

    // regenerate only when contents changed
    if (write_time == previous_write_time)
        return;
    previous_write_time = write_time;

    std::vector<std::pair<std::filesystem::path, u8>> file_list{
        {".", std2bsdFileType(std::filesystem::file_type::directory)},
        {"..", std2bsdFileType(std::filesystem::file_type::directory)},
    };

    mnt->IterateDirectory(guest_directory.c_str(),
                          [&file_list, this](const auto& file_path, const auto& file_type) {
                              file_list.emplace_back(file_path, std2bsdFileType(file_type));
                          });

    u64 fcnt = 0; // entry counter, can be removed
    u64 last_reclen_offset = 4;
    u16* last_reclen_data_ptr{};
    dirent_cache_bin.clear();
    dirent_cache_bin.reserve(512);
    dirent_cache_bin.resize(0);

    char sector[512]{0};
    s16 sector_remaining = 512;
    for (const auto& [file_path, file_type] : file_list) {
        if (sector_remaining < 0)
            break;

        NormalDirectoryDirent tmp{};

        // fill the cache only with what we found
        auto [elem, inserted] = dirent_fileno_cache.emplace(file_path, 0);
        if (inserted) {
            elem->second = BaseDirectory::next_fileno();
        }

        const auto file_leaf = elem->first.filename().string();

        // prepare dirent
        tmp.d_fileno = elem->second;
        tmp.d_namlen = file_leaf.size();
        strncpy(tmp.d_name, file_leaf.c_str(), tmp.d_namlen + 1);
        tmp.d_type = file_type;
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

    if (sector_remaining < 512) { // 0 is covered by if statement, 512 sector has been just written
        last_reclen_data_ptr = reinterpret_cast<u16*>(sector + last_reclen_offset);
        *last_reclen_data_ptr += sector_remaining;
        dirent_cache_bin.insert(dirent_cache_bin.end(), sector, sector + 512);
    }
    // i have no idea if this is the case, but lseek returns size aligned to 512
    directory_size = dirent_cache_bin.size();

    LOG_ERROR(Kernel_Fs, "Refreshed directory: {} , {} entries indexed , size {}",
              this->guest_directory.string(), fcnt, this->directory_size);
}

// -1 on not found
// this only used by getdirentries
s64 NormalDirectory::nearest_dirent(const char* buffer, s64 offset) {
    // max size is 272, last 23 bytes are never starting a dirent
    s64 status = -1;
    s64 offset_adj = Common::IsAligned(offset, 4) ? offset : Common::AlignUpAligned(offset, 4);
    s64 max_advance = std::min(s64(directory_size) - offset_adj, s64(256 + dirent_meta_size));

    status = -2;
    if (max_advance < 12)
        return status;

    s64 out_offset = offset_adj;
    status = -3;
    for (; out_offset < offset_adj; out_offset += 1) {
        const auto* tested_dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(buffer + out_offset);

        if (auto vld_status = validate_dirent(tested_dirent); vld_status < 0)
            continue;

        return out_offset;
    }

    status = -4;
    for (; out_offset < (offset + max_advance); out_offset += 4) {
        const auto* tested_dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(buffer + out_offset);

        if (auto vld_status = validate_dirent(tested_dirent); vld_status < 0)
            continue;

        return out_offset;
    }

    return status;
}

} // namespace Core::Directories