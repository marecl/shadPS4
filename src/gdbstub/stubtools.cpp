// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <sstream>
#include <string>
#include <vector>

#include <fmt/xchar.h>

#include "gdb_command.h"
#include "stubtools.h"

static std::string byteSwapString(std::string data, u8 width);

s8 Preprocess(std::string& data) {
    if (data.empty())
        return -1;

    const char cc = data.front();

    switch (cc) {
    case static_cast<char>(ControlCode::Ack):
        if (data.length() == 1)
            return 0;
        data = data.substr(1);
        return 1;
    case static_cast<char>(ControlCode::Interrupt):
        return 1;
    case static_cast<char>(ControlCode::Nack):
        return 2;
    }

    return 1;
}

GdbCommand ParsePacket(const std::string data) {

    if (data.front() == char(ControlCode::Interrupt)) {
        return GdbCommand{"\03", "\03", "\03"};
    }

    const auto end_pos = data.find(char(ControlCode::PacketEnd));

    if (data[0] != char(ControlCode::PacketStart) || end_pos == std::string::npos) {
        return GdbCommand{};
    }

    const std::string_view cmd_view = std::string_view(data).substr(1, end_pos - 1);

    GdbCommand out{data, std::string(cmd_view), ""};

    if (cmd_view.length() == 1)
        return out;

    auto septoken = cmd_view.find_first_of(":;");
    auto maybeNumber = cmd_view.find_first_of("-0123456789");
    if (const size_t pos = std::min(septoken, maybeNumber); pos != std::string::npos) {
        out.cmd = cmd_view.substr(0, pos);
        out.arg = cmd_view.substr(pos + (pos == septoken ? 1 : 0));
    }

    return out;
}

u8 CalculateChecksum(const std::string& command) {
    u8 sum = 0;
    for (const char c : command) {
        sum += static_cast<uint8_t>(c);
    }
    return sum & 0xFF;
}

std::string MakeResponse(const std::string msg) {
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
