// SPDX-FileCopyrightText: Copyright 2025 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <mutex>
#include <thread>
#include <queue>

#include <sys/wait.h>
#include <unistd.h>

#include "ptrace_listener.h"

bool PtraceListener::Poll(thread_event_t& event) {
    std::unique_lock<std::mutex> lock(_event_queue_mutex);
    if (_event_queue.empty())
        return false;
    event = _event_queue.front();
    _event_queue.pop();
    return true;
}
void PtraceListener::Place(thread_event_t event) {
    std::lock_guard<std::mutex> lock(_event_queue_mutex);
    _event_queue.push(event);
    _cv.notify_one();
}

thread_event_t PtraceListener::Wait() {
    std::unique_lock<std::mutex> lock(_event_queue_mutex);
    _cv.wait(lock, [&] { return !_event_queue.empty() || !_running.load(); });
    if (_event_queue.empty())
        return thread_event_t{static_cast<ThreadID>(-1), -1};
    thread_event_t evt = _event_queue.front();
    _event_queue.pop();
    return evt;
}

void PtraceListener::Stop() {
    if (!_running.load())
        return;
    _running.store(false);
    _cv.notify_all();
    if (_listener_thread.joinable())
        _listener_thread.join();
}

void PtraceListener::Loop() {
    pthread_setname_np(pthread_self(), "ptrace listener");

    while (_running.load()) {
        int status = 0;
        ThreadID tid = waitpid(-1, &status, __WALL);
        if (tid > 0) {
            std::lock_guard<std::mutex> lock(_event_queue_mutex);
            _event_queue.push(thread_event_t{tid, status});
            _cv.notify_one();
        } else {
            if (errno == ECHILD) {
                break;
            }
            if (errno != EINTR)
                perror("waitpid");
        }
    }
}
