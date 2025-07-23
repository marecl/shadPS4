#ifndef PTRACE_LISTENER_H
#define PTRACE_LISTENER_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <queue>

#include <unistd.h>

#include "threadinfo.h"

typedef struct _thread_event_t {
    ThreadID tid;
    int status;
} thread_event_t;

class PtraceListener {
public:
    PtraceListener(void) : _running(true) {
        _listener_thread = std::thread(&PtraceListener::Loop, this);
    }

    ~PtraceListener(void) {
        Stop();
    }

    // Pick up element from the queue
    bool Poll(thread_event_t& event);
    // Place an event at the end of the queue
    void Place(thread_event_t event);
    // Blocking wait
    thread_event_t Wait();
    // ...
    void Stop(void);

private:
    void Loop();
    std::thread _listener_thread;
    std::mutex _event_queue_mutex;
    std::condition_variable _cv;
    std::queue<thread_event_t> _event_queue;
    std::atomic<bool> _running;
};

#endif // PTRACE_LISTENER_H