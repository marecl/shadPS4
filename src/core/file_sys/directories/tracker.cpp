// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cstring>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "src/common/logging/log.h"
#include "src/common/singleton.h"
#include "src/common/types.h"
#include "src/core/file_sys/fs.h"

#include "tracker.h"

namespace Core::FileSys {
namespace fs = std::filesystem;

FileTracker::FileTracker(void) {
    root.nonce++;
    auto [new_node, _] = root.dirs.emplace("/", Node{});
    Node* fs_root = &new_node->second;
    // hit-or-miss, EXT uses this for root directory
    fs_root->fileno = 2;
    fs_root->parent = fs_root;
    fileno_top = 2;
};

Node* FileTracker::Add(const fs::path& path, bool is_file, Node* location) {
    fs::path norm = path.lexically_normal();

    Node* current = location ? location : &root;

    auto it = norm.begin();
    for (; it != norm.end(); ++it) {
        auto next = it;
        ++next;
        if (next == norm.end())
            break;
        auto [new_node, created] = current->dirs.emplace(it->string(), Node{});
        if (created) {
            current->nonce++;
            new_node->second.fileno = ++fileno_top;
            new_node->second.parent = current;
        }
        current = &new_node->second;
    }

    const std::string last = it->string();
    if (is_file) {
        auto [new_file, created] = current->files.emplace(last, 0);
        if (created) {
            current->nonce++;
            new_file->second = ++fileno_top;
            LOG_INFO(Common_Filesystem, "Added file: {}", path.string());
        }
        return current;
    }

    auto [_new_node, created] = current->dirs.emplace(last, Node{});
    Node* new_node = &_new_node->second;
    if (!created)
        return new_node;

    current->nonce++;
    new_node->nonce++;
    new_node->fileno = ++fileno_top;
    new_node->parent = current;
    LOG_INFO(Common_Filesystem, "Added directory: {}", path.string());

    return new_node;
}

bool FileTracker::Remove(const fs::path& path) {
    fs::path norm = path.lexically_normal();
    return _NodeRemoveImpl(norm, norm.begin());
}

Node*  FileTracker::GetDirectory(const fs::path& prefix) {
    fs::path norm = prefix.lexically_normal();

    Node* current = &root;
    for (auto it = norm.begin(); it != norm.end(); ++it) {
        std::string wwww = it->string();
        auto d = current->dirs.find(wwww);
        if (d == current->dirs.end())
            return  nullptr;
        current = &d->second;
    }

    return current;
}

bool FileTracker::_NodeRemoveImpl(const fs::path& full, fs::path::const_iterator it) {
    Node* current = &root;

    for (auto cur = it; cur != full.end(); ++cur) {
        auto& map = current->dirs;
        auto found = map.find(cur->string());

        auto next = cur;
        ++next;
        if (next == full.end()) {
            // ostatni element
            if (current->files.erase(cur->string()))
                return true;
            if (current->dirs.erase(cur->string()))
                return true;
            return false;
        }
        if (found == map.end())
            return false;
        current = &found->second;
    }
    return false;
}

void FileTracker::NodeCollect(Node* node, const fs::path& base, std::vector<fs::path>& out) {
    // pliki
    for (auto& [fname, _] : node->files) {
        out.push_back(base / fname);
    }
    // katalogi
    for (auto& [dname, child] : node->dirs) {
        fs::path subpath = base / dname;
        out.push_back(subpath);
        NodeCollect(&child, subpath, out);
    }
}
} // namespace Core::FileSys