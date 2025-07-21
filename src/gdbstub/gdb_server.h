// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDBSTUB_SERVER_H
#define GDBSTUB_SERVER_H

#include <atomic>
#include <mutex>
#include <thread>
#include <queue>
#include "common/types.h"

class StubServer {
public:
    StubServer(const u16 port) : _port(port), _running(false), _socket_server(-1) {};
    ~StubServer() {
        Stop();
    }

    void Start(void);
    void Stop(void);
    bool ClientConnected(void);

    bool GetMessage(std::string& out);
    bool SendMessage(std::string in);

private:
    void Loop(void);

    int _port;
    std::atomic<bool> _running;
    int _socket_server;
    std::atomic<int> _socket_client;
    std::thread _thread;

    std::mutex _inbound_queue_mutex;
    std::queue<std::string> _inbound_queue;
};

#endif // GDBSTUB_SERVER_H