// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <sstream>
#include <string>
#include <vector>

#include <fmt/xchar.h>

#include "stubtools.h"

static std::string byteSwapString(std::string data, u8 width);

u8 CalculateChecksum(const std::string& command) {
    u8 sum = 0;
    for (const char c : command) {
        sum += static_cast<uint8_t>(c);
    }
    return sum & 0xFF;
}

std::string MakeResponseImpl(const std::string msg) {
    // compressed response
    // std::string cpr{};
    // cpr = std::regex_replace(msg, std::regex("0000"), "0* ");
    // return "+$" + cpr + "#" + fmt::format("{:02X}", CalculateChecksum(cpr));

    // regular response
    return "+$" + msg + "#" + fmt::format("{:02X}", CalculateChecksum(msg));
}

// <3
// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
std::vector<std::string> Split(const std::string& din, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(din);
    std::string item;

    while (getline(ss, item, delim)) {
        out.push_back(item);
    }

    return out;
}

// width in individual digits
// 64-bits are aligned to 16, 32 to 8 etc.
std::string ByteSwap(u64 regval, u8 width) {
    std::string fstr = std::format("{{:0{}x}}", width);
    std::string regValStr = std::vformat(fstr, std::make_format_args((regval)));
    return byteSwapString(regValStr, width);
}

std::string byteSwapString(std::string data, u8 width) {
    std::string out = "";
    for (u8 i = 0; i < width; i += 2) {
        out += data[width - i - 2];
        out += data[width - i - 1];
    }
    return out;
}
