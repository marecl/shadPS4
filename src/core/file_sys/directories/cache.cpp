// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "cache.h"

namespace Core::Directories {

DirectoryCache::DirectoryCache() = default;
DirectoryCache::~DirectoryCache() = default;

bool DirectoryCache::Drop(const std::string& guest_path) {
    auto ret = this->cache.erase(guest_path);
    return ret == 1;
}

} // namespace Core::Directories