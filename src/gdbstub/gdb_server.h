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

    bool GetMessage(std::string& out);

private:
    void Loop(void);

    int _port;
    std::atomic<bool> _running;
    int _socket_server;
    std::thread _thread;

    std::queue<std::string> _message_queue;
    std::mutex _message_queue_mutex;
};

#endif // GDBSTUB_SERVER_H