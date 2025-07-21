#include <string>
#include <sys/types.h>
#include "threadinfo.h"

static u8 CalculateChecksum(const std::string& command) {
    u8 sum = 0;
    for (const char c : command) {
        sum += static_cast<uint8_t>(c);
    }
    return sum & 0xFF;
}

std::string MakeResponse(const std::string& response) {
    return "+$" + response + "#" + fmt::format("{:02X}", CalculateChecksum(response));
}
std::string NIMPL(std::string c) {
    LOG_WARNING(Debug, "Not implemented: {}", c);
    return "";
}

// <3
// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
std::vector<std::string> split(const std::string& din, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(din);
    std::string item;

    while (getline(ss, item, delim)) {
        out.push_back(item);
    }

    return out;
}

std::string byteSwapString(std::string data, u8 width) {
    std::string out = "";
    for (u8 i = 0; i < width; i += 2) {
        out += data[width - i - 2];
        out += data[width - i - 1];
    }
    return out;
}

// width in individual digits
// 64-bits are aligned to 16, 32 to 8 etc.
std::string byteSwap(u64 regval, u8 width = 16) {
    // format string to format string specifying output amount of bytes
    std::string fstr = std::format("{{:0{}x}}", width);
    std::string regValStr = std::vformat(fstr, std::make_format_args((regval)));
    return byteSwapString(regValStr, width);
}