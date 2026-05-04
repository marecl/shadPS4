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

    if (basep)
        *basep = file_offset;

    // same as others, we just don't need a variable
    if (file_offset >= directory_size)
        return 0;

    s64 bytes_written = 0;
    s64 working_offset = file_offset;
    s64 dirent_buffer_offset = 0;
    s64 aligned_count = Common::AlignDown(nbytes, 512);

    const char* dirent_buffer = this->dirent_cache_bin.data();
    while (dirent_buffer_offset < this->dirent_cache_bin.size()) {
        const char* normal_dirent_ptr = dirent_buffer + dirent_buffer_offset;
        const NormalDirectoryDirent* normal_dirent =
            reinterpret_cast<const NormalDirectoryDirent*>(normal_dirent_ptr);
        auto d_reclen = normal_dirent->d_reclen;

        // bad, incomplete or OOB entry
        if (normal_dirent->d_namlen == 0)
            break;

        if (working_offset >= d_reclen) {
            dirent_buffer_offset += d_reclen;
            working_offset -= d_reclen;
            continue;
        }

        if ((bytes_written + d_reclen) > aligned_count)
            // dirents are aligned to the last full one
            break;

        memcpy(static_cast<u8*>(buf) + bytes_written, normal_dirent_ptr + working_offset,
               d_reclen - working_offset);
        bytes_written += d_reclen - working_offset;
        dirent_buffer_offset += d_reclen;
        working_offset = 0;
    }

    file_offset += bytes_written;
    return bytes_written;
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
    u64 dirent_offset = 0;
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
        if (sector_remaining - tmp.d_reclen < 0) {
            // align previous dirent's size to the current ceiling
            last_reclen_data_ptr =
                reinterpret_cast<u16*>(dirent_cache_bin.data() + last_reclen_offset);
            // set writing pointer to the aligned start position (current ceiling)
            if (*last_reclen_data_ptr > sector_remaining)
                LOG_ERROR(Kernel_Fs,
                          "AAfor some reason reclen is larger than sector remainder :< {} {}",
                          tmp.d_reclen, sector_remaining);
            // any other way of updating last reclen??? this seems to be not working :<
            *last_reclen_data_ptr += sector_remaining;

            sector_remaining = 512;
            // dirent_cache_bin.resize(dirent_cache_bin.size() + 512);
            dirent_cache_bin.insert(dirent_cache_bin.end(), sector, sector + 512);
            memset(sector, 0, 512);
            dirent_offset = Common::IsAligned(dirent_offset, 512)
                                ? dirent_offset
                                : Common::AlignUp(dirent_offset, 512);
        }

        // current dirent's reclen position
        last_reclen_offset = dirent_offset + 4;
        memcpy(sector + 512 - sector_remaining, &tmp, tmp.d_reclen);
        dirent_offset += tmp.d_reclen;
        sector_remaining -= tmp.d_reclen;
        fcnt++;
    }

    if (!Common::IsAligned(dirent_offset, 512)) {
        last_reclen_data_ptr = reinterpret_cast<u16*>(dirent_cache_bin.data() + last_reclen_offset);
        // set writing pointer to the aligned start position (current ceiling)
        if (*last_reclen_data_ptr > sector_remaining)
            LOG_ERROR(Kernel_Fs, "for some reason reclen is larger than sector remainder :< {} {}",
                      *last_reclen_data_ptr, sector_remaining);

        *last_reclen_data_ptr += sector_remaining;
    }
    // i have no idea if this is the case, but lseek returns size aligned to 512
    directory_size = dirent_cache_bin.size();

    // sanity check. can't do memory view in a vector :<
    if (directory_size >= 65536)
        return;
    char _buffer[65536]{'A'};

    LOG_ERROR(Kernel_Fs, "Refreshed directory: {} , {} entries indexed , size {}",
              this->guest_directory, fcnt, this->directory_size);
    memcpy(_buffer, this->dirent_cache_bin.data(), this->directory_size);

    BP();
    return;
}

} // namespace Core::Directories