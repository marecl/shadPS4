#ifndef STUBTOOLS_H
#define STUBTOOLS_H

#include <string>

#include "common/types.h"

// Checksum for GDB
u8 CalculateChecksum(const std::string& command);
// Put our data (from stub) into GDB format
std::string MakeResponseImpl(const std::string msg);
// Split string into smaller strings
std::vector<std::string> Split(const std::string& din, char delim);
// Regular byte swap
std::string ByteSwap(u64 regval, u8 width = 16);

#endif // STUBTOOLS_H