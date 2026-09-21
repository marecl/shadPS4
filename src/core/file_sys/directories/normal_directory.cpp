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

    auto suggested_file_offset = bmp.ceil(file_offset);
    if (!suggested_file_offset) {
        // LOG_ERROR(Kernel_Fs, "Bitmap miss for offset {}", file_offset);
        this->file_offset = this->directory_size;
        return 0;
    }

    // LOG_INFO(Kernel_Fs, "Bitmap hit for offset {}: {}", file_offset, *suggested_file_offset);

    {
        u64 to_copy = std::min(*suggested_file_offset - this->file_offset, allowed_count);
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

    std::vector<std::pair<std::string, u8>> file_list{};

    mnt->IterateDirectory(
        guest_directory.c_str(), [&file_list, this](const auto& file_path, const auto& file_type) {
            file_list.emplace_back(file_path.filename(), std2bsdFileType(file_type));
        });

    // try to reuse existing space
    this->bmp.clear();
    std::fill(dirent_cache_bin.begin(), dirent_cache_bin.end(), 0);

    // track our position
    s64 bytes_written{0};
    u64 fcnt{0}; // entry counter, can be removed

    char sector[512]{0};
    s16 sector_bw{0};
    u64 last_reclen_offset{0};
    u16* last_reclen_data_ptr{};

    NormalDirectoryDirent tmp{};

    for (auto f_iter = file_list.begin(); f_iter != file_list.end(); ++f_iter) {
        const auto& [file_name, file_type] = *f_iter;

        // for (const auto& [file_name, file_type] : file_list) {
        // fill the cache only with what we found
        auto [elem, inserted] = dirent_fileno_cache.emplace(file_name, 0);
        if (inserted) {
            elem->second = BaseDirectory::next_fileno();
        }

        // prepare dirent
        tmp.d_fileno = elem->second;
        tmp.d_namlen = file_name.size();
        strncpy(tmp.d_name, file_name.c_str(), tmp.d_namlen + 1);
        tmp.d_type = file_type;
        tmp.d_reclen = Common::AlignUpAligned(base_dirent_meta_size + tmp.d_namlen + 1, 4);

        // current dirent breaks sector alignment, save current sector
        // OR if it's the last one (from goto)
        if ((tmp.d_reclen + sector_bw) > 512) {
        sector_dump_lbl:
            // align previous dirent's size to the current ceiling
            last_reclen_data_ptr = reinterpret_cast<u16*>(sector + last_reclen_offset);
            // looking for a reasonable alternative
            *last_reclen_data_ptr += 512 - sector_bw;
            bytes_written += 512 - sector_bw;

            if (dirent_cache_bin.size() < bytes_written) {
                // some extra won't hurt, will get trimmed anyway
                dirent_cache_bin.resize(bytes_written + 512, 0);
            }
            std::memcpy(dirent_cache_bin.data() + bytes_written - 512, sector, 512);

            // last dump, called from the label
            if (std::next(f_iter) == file_list.end()) {
                continue;
            }

            memset(sector, 0, 512);
            sector_bw = 0;
        }

        memcpy(sector + sector_bw, &tmp, tmp.d_reclen);
        last_reclen_offset = sector_bw + 4;
        sector_bw += tmp.d_reclen;
        fcnt++;
        // last-last reclen is irrelevant to the bitmap,
        // so there is no need to adjust it yet
        bmp.add(bytes_written, tmp.d_reclen);
        bytes_written += tmp.d_reclen;

        // awkward, but more effective than duplicate code
        if (std::next(f_iter) == file_list.end()) {
            goto sector_dump_lbl;
        }
    }

    // already aligned to 512 bytes
    directory_size = bytes_written;
    bmp.trim();
    dirent_cache_bin.resize(bytes_written);

    LOG_ERROR(Kernel_Fs, "Refreshed directory: {} , {} entries indexed , size {}",
              this->guest_directory.string(), fcnt, this->directory_size);
}

} // namespace Core::Directories