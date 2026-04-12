// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <string>
#include <unordered_map>

#include "base_directory.h"

namespace Core::Directories {

class DirectoryCache {
public:
    explicit DirectoryCache();
    ~DirectoryCache();

    template <typename T>
    std::shared_ptr<BaseDirectory> Get(const std::string& guest_path) {
        static_assert(std::is_base_of<BaseDirectory, T>::value);

        auto found_elem = this->cache.find(guest_path);
        if (this->cache.end() != found_elem) {
            found_elem->second->__reset();
            return found_elem->second;
        }

        auto [new_elem, _] = this->cache.emplace(guest_path, T::Create(guest_path));
        return new_elem->second;
    }

    bool Drop(const std::string& guest_path);

private:
    std::unordered_map<std::string, std::shared_ptr<BaseDirectory>> cache{};
};

} // namespace Core::Directories