// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <iostream>

#include <netinet/in.h>
#include <sys/socket.h>

#include "gdb_server.h"

void StubServer::Start(void) {
    _socket_server = -1;
    _socket_client.store(-1);
    _running.store(true);
    _thread = std::thread(&StubServer::Loop, this);
}

void StubServer::Stop(void) {
    if (!_running.exchange(false))
        return;

    int socket_client = _socket_client.load();
    if (socket_client != -1) {
        close(socket_client);
    }

    shutdown(_socket_server, SHUT_RDWR);
    close(_socket_server);
    if (_thread.joinable())
        _thread.join();
}

bool StubServer::ClientConnected(void) {
    return _socket_client.load() != -1;
}

bool StubServer::GetMessage(std::string& out) {
    std::lock_guard<std::mutex> lock(_inbound_queue_mutex);
    if (_inbound_queue.empty())
        return false;

    out = _inbound_queue.front();
    _inbound_queue.pop();
    return true;
}

bool StubServer::SendMessage(std::string in) {
    ssize_t sent = send(_socket_client.load(), in.c_str(), in.size(), 0);
    if (sent == -1) {
        std::cout << "Error while sending message" << std::endl;
        return false;
    }

    return true;
}

void StubServer::RestartSession(void) {
    _running_client.store(false);
    shutdown(this->_socket_client.load(), SHUT_RDWR);
    std::lock_guard<std::mutex> lock(_inbound_queue_mutex);
    this->_inbound_queue = {};
}

void StubServer::Loop(void) {
    pthread_setname_np(pthread_self(), "GDB Listener");

    _socket_server = socket(AF_INET, SOCK_STREAM, 0);
    if (_socket_server < 0) {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(_socket_server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(_port);

    if (bind(_socket_server, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        perror("bind");
        return;
    }

    if (listen(_socket_server, 5) < 0) {
        perror("listen");
        return;
    }

    std::cout << "[*] GDB Server listening on port: " << _port << std::endl;

    while (_running.load()) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client = accept(_socket_server, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client < 0) {
            if (!_running)
                break;
            perror("accept");
            continue;
        }

        _socket_client.store(client);
        _running_client.store(true);

        char inboundBuffer[1024] = {0};

        while (_running_client.load()) {
            ssize_t bytes = read(_socket_client.load(), inboundBuffer, sizeof(inboundBuffer) - 1);
            if (bytes > 0) {
                std::lock_guard<std::mutex> lock(_inbound_queue_mutex);

                std::string msg(inboundBuffer, bytes);
                _inbound_queue.push(msg);
            }
            if (bytes == -1) {
                std::cout << "Client error or disconnected" << std::endl;
                break;
            }
        }

        close(_socket_client);
    }
}