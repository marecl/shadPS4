// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDB_COMMAND_H
#define GDB_COMMAND_H

#include <iostream>

typedef struct _GdbCommand {
    std::string raw{};
    std::string cmd{};
    std::string arg{};
} GdbCommand;

#endif // GDB_COMMAND_H