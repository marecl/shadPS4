// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cassert>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/alignment.h"
#include "common/assert.h"
#include "core/file_sys/directories/bitmap.h"

namespace Core::Directories::Bitmap {

DirectoryBitmap::DirectoryBitmap(u32 alignment) : alignment(alignment) {
    ASSERT_MSG(1 == __builtin_popcount(alignment), "Alignment must be a power of 2");
}

void DirectoryBitmap::add(s64 off, u32 reclen) {
    ASSERT_MSG(Common::IsAligned(off, alignment), "Offset {}B not aligned to {}B", data_size,
               alignment);
    ASSERT_MSG(Common::IsAligned(reclen, alignment), "Reclen {}B not aligned to {}B", data_size,
               alignment);

    const u32 end = off + reclen;
    if (end > data_size)
        resize(end);
    // static_assert(off < data_size);
    const u32 slot = off / alignment;
    bmp[slot >> 6] |= 1ull << (slot & 63u);
}

void DirectoryBitmap::resize(u32 data_size) {
    // assert(data_size % alignment == 0);
    ASSERT_MSG(Common::IsAligned(data_size, alignment), "Data size {}B not aligned to {}B",
               data_size, alignment);
    this->data_size = data_size;
    // 64bits, 1 unit of allocation per bit
    // so one slot can hold 64*8 = 512, 64*4 = 256
    // calculate total slots and align up to the full 64bit
    auto slots = Common::AlignUpAligned(data_size / alignment, 64);
    bmp.resize(slots / 64, 0);
}

void DirectoryBitmap::trim(u32 allowance) {
    // how many ull's are taken by data
    auto units_taken = Common::AlignUpAligned(data_size / alignment, 64) >> 6;
    // how many unused ull's we can have
    auto units_reserved = Common::AlignUpAligned(allowance / alignment, 64) >> 6;

    // it's guaranteed that alots available are equal to or greater than slots taken
    // so we'll always be >=0
    if ((bmp.size() - units_taken) > units_reserved)
        bmp.resize(units_taken + units_reserved);
}

void DirectoryBitmap::clear(void) {
    this->data_size = 0;
    std::fill(bmp.begin(), bmp.end(), 0);
}

std::optional<s64> DirectoryBitmap::ceil(s64 off) const {
    if (off >= data_size || bmp.empty())
        return std::nullopt;

    if (off == 0)
        return 0;

    s64 s = (off + alignment - 1u) / alignment;
    const s64 slot_end = data_size / alignment;
    if (s >= slot_end)
        return std::nullopt;

    u32 wi = s >> 6;
    u64 word = bmp[wi] & (~0ull << (s & 63u));

    for (;;) {
        if (word != 0) {
            const u32 found = (wi << 6) + static_cast<u32>(__builtin_ctzll(word));
            if (found >= slot_end)
                return std::nullopt;
            return found * alignment;
        }
        if (++wi >= bmp.size())
            return std::nullopt;
        word = bmp[wi];
    }

    UNREACHABLE_MSG("XD");
}

} // namespace Core::Directories::Bitmap