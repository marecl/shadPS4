#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include "gdb_server.h"

void StubServer::Start(void) {
    _running = true;
    _thread = std::thread(&StubServer::Loop, this);
}

void StubServer::Stop(void) {
    if (!_running)
        return;

    _running = false;
    shutdown(_socket_server, SHUT_RDWR); // przerywa accept()
    close(_socket_server);
    if (_thread.joinable())
        _thread.join();
}

bool StubServer::GetMessage(std::string& out) {
    std::lock_guard<std::mutex> lock(_message_queue_mutex);
    if (_message_queue.empty())
        return false;

    out = std::move(_message_queue.front());
    _message_queue.pop();
    return true;
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

    while (_running) {
        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(_socket_server, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client_sock < 0) {
            if (!_running)
                break;
            perror("accept");
            continue;
        }

        char buffer[1024] = {0};
        ssize_t bytes = read(client_sock, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            std::lock_guard<std::mutex> lock(_message_queue_mutex);
            _message_queue.emplace(buffer);
        }

        close(client_sock);
    }
}