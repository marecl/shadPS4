// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

namespace Core::Directories::Bitmap {

#include <cassert>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/types.h"

/**
 * All values in bytes, must be aligned at all times
 */

class DirectoryBitmap {
public:
    DirectoryBitmap(u32 alignment);

    void add(s64 off, u32 reclen);
    void resize(u32 data_size);
    void trim(u32 allowance = 0);
    void clear(void);

    // looks up for the next entry
    [[nodiscard]] std::optional<s64> ceil(s64 off) const;

    [[nodiscard]] u32 packed_size() const {
        return data_size;
    }

private:
    const u32 alignment{};
    std::vector<u64> bmp{};
    u32 data_size{0};
};

} // namespace Core::Directories::Bitmap