// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef GDBSTUB_SERVER_H
#define GDBSTUB_SERVER_H

#include <atomic>
#include <mutex>
#include <thread>
#include <queue>

class StubServer {
public:
    StubServer(const int port) : _port(port), _running(false),_running_client(false), _socket_server(-1) {};
    ~StubServer(void) {
        Stop();
    }

    // ...
    void Start(void);
    // ...
    void Stop(void);
    // ...
    bool ClientConnected(void);
    // Pick up message from the queue
    bool GetMessage(std::string& out);
    // Place a message on the outbound queue
    bool SendMessage(std::string in);

    void RestartSession(void);

private:
    void Loop(void);

    int _port{};
    std::atomic<bool> _running{};
    std::atomic<bool> _running_client{};
    int _socket_server{};
    std::atomic<int> _socket_client{};
    std::thread _thread{};

    std::mutex _inbound_queue_mutex{};
    std::queue<std::string> _inbound_queue{};
};

#endif // GDBSTUB_SERVER_H