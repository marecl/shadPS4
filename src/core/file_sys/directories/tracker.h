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
    u64 fileno{0};
    bool modified{false};
    // dir name, next node
    std::unordered_map<std::string, Node> dirs{};
    // file name, fileno
    std::unordered_map<std::string, u64> files{};
} Node;

class FileTracker {
public:
    FileTracker(void);
    ~FileTracker(void) = default;

    void NodeAdd(const fs::path& path);
    bool NodeRemove(const fs::path& path);
    Node* NodeGet(const fs::path& prefix);
    std::pair<u64, Node*> NodeGetDirectory(const fs::path& prefix);
    void NodeCollect(Node* node, const fs::path& base, std::vector<fs::path>& out);

private:
    bool _NodeRemoveImpl(const fs::path& full, fs::path::const_iterator it);

    Node root;
    u64 fileno_top = 0;
};

}; // namespace Core::FileSys