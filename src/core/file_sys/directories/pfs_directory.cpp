// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/alignment.h"
#include "common/assert.h"
#include "common/logging/log.h"
#include "common/singleton.h"
#include "core/file_sys/directories/normal_directory.h"
#include "core/file_sys/directories/pfs_directory.h"
#include "core/file_sys/fs.h"
#include "tracker.h"

namespace Core::Directories {

std::shared_ptr<BaseDirectory> PfsDirectory::Create(std::string_view guest_directory) {
    return std::static_pointer_cast<BaseDirectory>(std::make_shared<PfsDirectory>(guest_directory));
}

PfsDirectory::PfsDirectory(std::string_view guest_directory) : BaseDirectory(guest_directory) {
    auto tracker = Common::Singleton<FileSys::FileTracker>::Instance();
    tracker->Add(guest_directory, false);
    update();
}

u32 calcreclen(PfsDirectoryDirent* dirent) {
    return Common::AlignUp(sizeof(dirent->d_fileno) + sizeof(dirent->d_type) +
                               sizeof(dirent->d_namlen) + sizeof(dirent->d_reclen) +
                               (dirent->d_namlen + 1),
                           8);
}

PfsDirectoryDirent makedirent_dir(std::string name, FileSys::Node* node) {
    PfsDirectoryDirent out{};
    out.d_fileno = node->fileno;
    out.d_type = DIRENT_TYPE_DIR;
    out.d_namlen = name.size() + 1;
    strncpy(out.d_name, name.data(), out.d_namlen);
    out.d_reclen = calcreclen(&out);
    return out;
}
PfsDirectoryDirent makedirent_file(std::string name, u32 fileno) {
    PfsDirectoryDirent out{};
    out.d_fileno = fileno;
    out.d_type = DIRENT_TYPE_FILE;
    out.d_namlen = name.size() + 1;
    strncpy(out.d_name, name.data(), out.d_namlen);
    out.d_reclen = calcreclen(&out);
    return out;
}

bool PfsDirectory::update(void) {
    auto* mnt = Common::Singleton<Core::FileSys::MntPoints>::Instance();
    auto tracker = Common::Singleton<FileSys::FileTracker>::Instance();

    // we don't save our node, target directory may get deleted without our knowledge
    FileSys::Node* target = tracker->GetDirectory(this->guest_directory);
    if (target == nullptr) {
        // Error: target doesn't exist!
        return false;
    }

    if (mnt->ReadDirectory(guest_directory) == nonce)
        return true;

    dirents.clear();
    directory_content_size = 0;
    directory_size = 0;

    auto& dirent_curdir = dirents.emplace_back(makedirent_dir(".", target));
    auto& dirent_parent_dir = dirents.emplace_back(makedirent_dir("..", target));
    dirent_parent_dir.d_fileno = target->parent->fileno;

    for (auto dir : target->dirs) {
        std::string subdir_name = dir.first;
        auto& dirent = dirents.emplace_back(makedirent_dir(dir.first, &dir.second));
        directory_content_size += dirent.d_reclen;
    }

    for (auto file : target->files) {
        std::string file_name = file.first;
        auto file_fileno = file.second;
        auto& dirent = dirents.emplace_back(makedirent_file(file.first, file.second));
        directory_content_size += dirent.d_reclen;
    }

    nonce = target->nonce;
    directory_size = Common::AlignUp(directory_content_size, DIRECTORY_PFS_ALIGNMENT);

    return true;
}

s64 PfsDirectory::read(void* buf, u64 nbytes) {
    if (!update())
        return -1;

    if (dirents_index >= dirents.size()) {
        if (dirents_index < directory_content_size) {
            // We need to find the appropriate dirents_index to start from.
            s64 data_to_skip = dirents_index;
            u64 corrected_index = 0;
            while (data_to_skip > 0) {
                const auto dirent = dirents[corrected_index++];
                data_to_skip -= dirent.d_reclen;
            }
            dirents_index = corrected_index;
        } else {
            // Nothing left to read.
            return ORBIS_OK;
        }
    }

    s64 bytes_remaining = nbytes > directory_size ? directory_size : nbytes;
    // read on PfsDirectories will always return the maximum possible value.
    const u64 bytes_written = bytes_remaining;
    memset(buf, 0, bytes_remaining);

    char* current_dirent = static_cast<char*>(buf);
    PfsDirectoryDirent dirent = dirents[dirents_index];
    while (bytes_remaining > dirent.d_reclen) {
        PfsDirectoryDirent* dirent_to_write = reinterpret_cast<PfsDirectoryDirent*>(current_dirent);
        dirent_to_write->d_fileno = dirent.d_fileno;

        // Using size d_namlen + 1 to account for null terminator.
        strncpy(dirent_to_write->d_name, dirent.d_name, dirent.d_namlen + 1);
        dirent_to_write->d_namlen = dirent.d_namlen;
        dirent_to_write->d_reclen = dirent.d_reclen;
        dirent_to_write->d_type = dirent.d_type;

        current_dirent += dirent.d_reclen;
        bytes_remaining -= dirent.d_reclen;

        if (dirents_index == dirents.size() - 1) {
            // Currently at the last dirent, so break out of the loop.
            dirents_index++;
            break;
        }
        dirent = dirents[++dirents_index];
    }

    return bytes_written;
}

s64 PfsDirectory::readv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt) {
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

s64 PfsDirectory::preadv(const Libraries::Kernel::OrbisKernelIovec* iov, s32 iovcnt, s64 offset) {
    const u64 old_dirent_index = dirents_index;
    dirents_index = 0;
    s64 data_to_skip = offset;
    // If offset is part-way through one dirent, that dirent is skipped.
    while (data_to_skip > 0) {
        const auto dirent = dirents[dirents_index++];
        data_to_skip -= dirent.d_reclen;
        if (dirents_index == dirents.size()) {
            // We've reached the end of the dirents, nothing more can be skipped.
            break;
        }
    }

    const s64 bytes_read = readv(iov, iovcnt);
    dirents_index = old_dirent_index;
    return bytes_read;
}

s64 PfsDirectory::lseek(s64 offset, s32 whence) {
    switch (whence) {
    // Seek start
    case 0: {
        dirents_index = 0;
    }
    case 1: {
        // There aren't any dirents left to pass through.
        if (dirents_index >= dirents.size()) {
            dirents_index = dirents_index + offset;
            break;
        }
        s64 data_to_skip = offset;
        while (data_to_skip > 0) {
            const auto dirent = dirents[dirents_index++];
            data_to_skip -= dirent.d_reclen;
            if (dirents_index == dirents.size()) {
                // We've passed through all file dirents.
                // Set dirents_index to directory_size + remaining_offset instead.
                dirents_index = directory_content_size + data_to_skip;
                break;
            }
        }
        break;
    }
    case 2: {
        // Seems like real hardware gives up on tracking dirents_index if you go this route.
        dirents_index = directory_size + offset;
        break;
    }
    default: {
        UNREACHABLE_MSG("lseek with unknown whence {}", whence);
    }
    }

    return dirents_index;
}

s32 PfsDirectory::fstat(Libraries::Kernel::OrbisKernelStat* stat) {
    stat->st_mode = 0000777u | 0040000u;
    stat->st_size = directory_size;
    stat->st_blksize = 0x10000;
    stat->st_blocks = 0x80;
    return ORBIS_OK;
}

s64 PfsDirectory::getdents(void* buf, u64 nbytes, s64* basep) {
    // basep is set at the start of the function.

    if (!update())
        return -1;

    if (basep != nullptr) {
        *basep = dirents_index;
    }

    if (dirents_index >= dirents.size()) {
        if (dirents_index < directory_content_size) {
            // We need to find the appropriate dirents_index to start from.
            s64 data_to_skip = dirents_index;
            u64 corrected_index = 0;
            while (data_to_skip > 0) {
                const auto dirent = dirents[corrected_index++];
                data_to_skip -= dirent.d_reclen;
            }
            dirents_index = corrected_index;
        } else {
            // Nothing left to read.
            return ORBIS_OK;
        }
    }

    s64 bytes_remaining = nbytes > directory_size ? directory_size : nbytes;
    memset(buf, 0, bytes_remaining);

    u64 bytes_written = 0;
    char* current_dirent = static_cast<char*>(buf);
    // getdents has to convert pfs dirents to normal dirents
    PfsDirectoryDirent dirent = dirents[dirents_index];
    while (bytes_remaining > dirent.d_reclen) {
        NormalDirectoryDirent* dirent_to_write =
            reinterpret_cast<NormalDirectoryDirent*>(current_dirent);
        dirent_to_write->d_fileno = dirent.d_fileno;
        strncpy(dirent_to_write->d_name, dirent.d_name, dirent.d_namlen + 1);
        dirent_to_write->d_namlen = dirent.d_namlen;
        dirent_to_write->d_reclen = dirent.d_reclen;
        dirent_to_write->d_type = dirent.d_type;

        current_dirent += dirent.d_reclen;
        bytes_remaining -= dirent.d_reclen;
        bytes_written += dirent.d_reclen;

        if (dirents_index == dirents.size() - 1) {
            // Currently at the last dirent, so set dirents_index appropriately and break.
            dirents_index = directory_size;
            break;
        }
        dirent = dirents[++dirents_index];
    }

    return bytes_written;
}
} // namespace Core::Directories