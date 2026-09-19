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
    : BaseDirectory::BaseDirectory(4),
      guest_directory(std::move(std::filesystem::path(guest_directory))) {
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
    s64 allowed_count = std::min(apparent_end_down - file_offset, static_cast<s64>(nbytes));
    u64 bytes_written = 0;
    u64 read_offset = file_offset;
    u64 write_offset = 0;

    // check where's the nearest dirent
    // makes most sense here
    this->suggested_file_offset = bmp.ceil(file_offset).value_or(this->directory_size);
    LOG_INFO(Kernel_Fs, "Bitmap hit for offset {}: {}", file_offset, this->suggested_file_offset);

    {
        u64 to_copy = std::min(this->suggested_file_offset - this->file_offset, allowed_count);
        memcpy(buf, dirent_buffer + this->file_offset, to_copy);
        read_offset += to_copy;
        bytes_written += to_copy;
    }

    while (read_offset < directory_size) {
        const auto* dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(dirent_buffer + read_offset);

        if (validate_dirent(dirent) < 0) {
            // probably OOB
            break;
        }

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

    const std::filesystem::file_time_type write_time = std::filesystem::last_write_time(
        mnt->GetHostPath(std::string_view(this->guest_directory.c_str()), nullptr));

    // regenerate only when contents changed
    if (write_time == previous_write_time)
        return;
    previous_write_time = write_time;

    std::vector<std::pair<std::filesystem::path, u8>> file_list{};

    mnt->IterateDirectory(guest_directory.c_str(),
                          [&file_list, this](const auto& file_path, const auto& file_type) {
                              file_list.emplace_back(file_path, std2bsdFileType(file_type));
                          });

    // bad optimization idea:
    // save previous sizes/amounts
    // restore with a small+ if similiar
    // trim everything according to calculated sizes

    // reserve some space in advance, cut down on reallocation
    // assuming avg 24 bytes per entry, converted to n 64-bit slots
    // 24B * x + 24B
    this->bmp.resize(Common::AlignUpAligned(24 * file_list.size() + 24, 4));
    this->bmp.clear();

    // have first sector ready
    dirent_cache_bin.resize(512);
    std::fill(dirent_cache_bin.begin(), dirent_cache_bin.end(), 0);

    s64 bytes_written = 0;
    s64 dirent_offset = 0;
    u64 fcnt = 0; // entry counter, can be removed
    u64 last_reclen_offset = 4;
    u16* last_reclen_data_ptr{};

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
        tmp.d_reclen = Common::AlignUpAligned(base_dirent_meta_size + tmp.d_namlen + 1, 4);

        // next element may break 512 byte alignment
        if (sector_remaining - tmp.d_reclen < 0) {
            // align previous dirent's size to the current ceiling
            last_reclen_data_ptr = reinterpret_cast<u16*>(sector + last_reclen_offset);
            // any other way of updating last reclen??? this seems to be not working :<
            *last_reclen_data_ptr += sector_remaining;
            bytes_written += sector_remaining;
            sector_remaining = 512;

            dirent_cache_bin.insert(dirent_cache_bin.end(), sector, sector + 512);

            memset(sector, 0, 512);
        }

        // current dirent's reclen position
        memcpy(sector + 512 - sector_remaining, &tmp, tmp.d_reclen);
        last_reclen_offset = 512 - sector_remaining + 4;
        sector_remaining -= tmp.d_reclen;
        fcnt++;
        bmp.add(bytes_written, tmp.d_reclen);
        bytes_written += tmp.d_reclen;
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

} // namespace Core::Directories