// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "common/io_file.h"
#include "core/file_sys/devices/base_device.h"
#include "core/libraries/kernel/posix_error.h"

namespace Core::Devices {

using SeekOrigin = Common::FS::SeekOrigin;

BaseDevice::BaseDevice() = default;

BaseDevice::~BaseDevice() = default;

s64 BaseDevice::lseek(s64 offset, int whence) {
    this->file_offset =
        ((static_cast<int>(SeekOrigin::SetOrigin) == whence) * offset) +
        ((static_cast<int>(SeekOrigin::CurrentPosition) == whence) * (this->file_offset + offset)) +
        ((static_cast<int>(SeekOrigin::End) == whence) * ((offset > 0) * offset));
    // ::END is pro-forma
    return this->file_offset >= 0 ? this->file_offset : -POSIX_EINVAL;
}

} // namespace Core::Devices