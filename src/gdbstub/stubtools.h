// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef STUBTOOLS_H
#define STUBTOOLS_H

#include <string>

#include "common/types.h"
#include "gdb_command.h"

/**
 * Misc functions for GdbStub
 * These aren't in need of attention, so they are moved here
 */


enum class ControlCode : char {
    Ack = '+',
    Nack = '-',
    PacketStart = '$',
    PacketEnd = '#',
    Interrupt = '\03',
};

/**
 * Decide what to do with packet from client
 * -1 error
 * 0 return input directly to sender
 * 1 pass on for processing
 * 2 repeat last response
 */
s8 Preprocess(std::string& data);
// Extract command and args from packet
GdbCommand ParsePacket(const std::string data);
// Checksum for GDB
u8 CalculateChecksum(const std::string& command);
// Put our data (from stub) into GDB format
std::string MakeResponse(const std::string msg);
// Split string into smaller strings
std::vector<std::string> Split(const std::string& din, char delim);
// Regular byte swap
std::string ByteSwap(u64 regval, u8 width = 16);

#endif // STUBTOOLS_H