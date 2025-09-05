// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <filesystem>
#include <unordered_map>
#include <vector>

#include "src/common/types.h"

#include "base_directory.h"

namespace Core::FileSys {

namespace fs = std::filesystem;

typedef struct Node {
    Node* parent{};
    u32 fileno{0};
    u64 nonce{1};
    // dir name, next node
    std::unordered_map<std::string, Node> dirs{};
    // file name, fileno
    std::unordered_map<std::string, u32> files{};
} Node;

class FileTracker {
public:
    FileTracker(void);
    ~FileTracker(void) = default;

    // returns last node. if `location` is provided, creates nodes there
    // may throw FS around, so use this to create relative paths/files
    Node* Add(const fs::path& path, bool is_file, Node* location = nullptr);
    bool Remove(const fs::path& path);
    Node* GetDirectory(const fs::path& prefix);
    void NodeCollect(Node* node, const fs::path& base, std::vector<fs::path>& out);

private:
    bool _NodeRemoveImpl(const fs::path& full, fs::path::const_iterator it);

    Node root;
    u32 fileno_top = 0;
};

}; // namespace Core::FileSys