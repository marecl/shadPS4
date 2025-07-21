#include <string>
#include "common/types.h"

u8 CalculateChecksum(const std::string& command);
std::string MakeResponse(const std::string& response);
std::vector<std::string> split(const std::string& din, char delim);
std::string byteSwapString(std::string data, u8 width);
std::string byteSwap(u64 regval, u8 width = 16);