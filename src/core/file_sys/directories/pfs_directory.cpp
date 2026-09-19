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

/**
 * TODO:
 * on pread remember to fill zeros
 * it uses aligned directory size
 */

namespace Core::Directories {

std::shared_ptr<PfsDirectory> PfsDirectory::Create(std::string_view guest_directory) {
    return std::make_shared<PfsDirectory>(guest_directory);
}

PfsDirectory::PfsDirectory(std::string_view guest_directory) : BaseDirectory::BaseDirectory(8) {
    const std::filesystem::path guest_directory_path = guest_directory;
    directory_size = 0;
    suggested_file_offset = 0;
    dirent_cache_bin.reserve(512);

    /**
     * TODO: Read divides into 64k blocks, so if the last dirent does not fit,
     * it gets moved to the next 64k block.
     * there's a catch though - it does not add remaining space to reclen!
     * what this means, is that there's a random spot of 0's at the end of the block.
     * this changes nothing for read.
     * getdirentries however jump straight to the next dirent i.e. there's no gap
     */

    std::vector<std::pair<std::string, u8>> file_list{};
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();

    mnt->IterateDirectory(
        guest_directory, [&file_list, this](const auto& file_path, const auto& file_type) {
            file_list.emplace_back(file_path.filename(), std2pfsFileType(file_type));
        });

    // reserve some space in advance, cut down on reallocation
    // assuming avg 32 bytes per entry, converted to n 64-bit slots
    // 32B * x + 48B
    this->bmp.resize(Common::AlignUpAligned(32 * file_list.size() + 48, 8));

    // all fields are gonna be populated anyway
    PfsDirectoryDirent tmp{};
    for (const auto& [file_leaf, file_type] : file_list) {

        tmp.d_fileno = PfsDirectory::next_fileno();
        tmp.d_type = file_type;
        tmp.d_namlen = file_leaf.size();
        tmp.d_reclen = Common::AlignUpAligned(dirent_meta_size + tmp.d_namlen + 1, 8);
        strncpy(tmp.d_name, file_leaf.c_str(), tmp.d_namlen + 1);

        bmp.add(dirent_cache_bin.size(), tmp.d_reclen);
        auto dirent_ptr = reinterpret_cast<const u8*>(&tmp);
        dirent_cache_bin.insert(dirent_cache_bin.end(), dirent_ptr, dirent_ptr + tmp.d_reclen);
    }

    directory_size = dirent_cache_bin.size();
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

s32 PfsDirectory::fstat(Libraries::Kernel::OrbisKernelStat* stat) {
    stat->st_mode = 0000777u | 0040000u;
    stat->st_size = directory_size;
    stat->st_blksize = Common::AlignUpAligned(this->directory_size, 0x10000);
    stat->st_blocks = 0x80 * (stat->st_blksize >> 16);
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

    if (this->file_offset >= this->dirent_cache_bin.size()) {
        // oob
        this->file_offset = this->directory_size;
        this->suggested_file_offset = this->directory_size;
        return 0;
    }

    // check where's the nearest dirent
    // makes most sense here
    this->suggested_file_offset = bmp.ceil(file_offset).value_or(this->directory_size);
    LOG_INFO(Kernel_Fs, "Bitmap hit for offset {}: {}", file_offset, this->suggested_file_offset);

    // we can now assume that offset is always smaller than size
    const char* dirent_buffer = this->dirent_cache_bin.data();
    s64 allowed_count = std::min(apparent_end_down - file_offset, static_cast<s64>(nbytes));
    u64 bytes_written = 0;
    u64 read_offset = this->suggested_file_offset;
    u64 write_offset = 0;

    while (read_offset < directory_size) {
        const PfsDirectoryDirent* pfs_dirent =
            reinterpret_cast<const PfsDirectoryDirent*>(dirent_buffer + read_offset);

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
        this->pfs2normal(pfs_dirent, &normal_dirent);

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

s64 PfsDirectory::validate_dirent(const PfsDirectoryDirent* dirent) {
    auto _reclen = dirent_meta_size + dirent->d_namlen + 1;
    _reclen = Common::IsAligned(_reclen, 8) ? _reclen : Common::AlignUpAligned(_reclen, 8);
    if (_reclen != dirent->d_reclen)
        return -10;

    // these don't fail so often
    // known values first
    if (dirent->d_reclen < 24 || dirent->d_reclen > 272)
        return -11;
    if (dirent->d_type > 15)
        return -12;
    // unlikely to trigger anything at this point, left for verbosity
    if (dirent->d_fileno == 0)
        return -13;
    if (dirent->d_namlen == 0)
        return -14;
    if (reinterpret_cast<const u8*>(dirent)[dirent->d_namlen] != 0)
        return -15;
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

void PfsDirectory::pfs2normal(const PfsDirectoryDirent* pfs,
                              NormalDirectory::NormalDirectoryDirent* normal) {
    normal->d_fileno = pfs->d_fileno;
    normal->d_reclen = pfs->d_reclen;
    normal->d_type = pfs2bsdFileType(pfs->d_type);
    normal->d_namlen = pfs->d_namlen;
    memcpy(normal->d_name, pfs->d_name, pfs->d_namlen);
}

} // namespace Core::Directories