#include <cstring>
#include "threadinfo.h"

struct ThreadInfo* getThreadByID(struct SharedVector* threads, ThreadID id) {
    for (u16 idx = 0; idx < threads->size; idx++) {
        ThreadInfo* thread = &threads->threads[idx];
        if (id == thread->tid)
            return thread;
    }
    return nullptr;
}
struct ThreadInfo* getThreadByName(struct SharedVector* threads, std::string name) {
    for (u16 idx = 0; idx < threads->size; idx++) {
        ThreadInfo* thread = &threads->threads[idx];
        if (strncmp(thread->name, name.c_str(), 16) == 0)
            return thread;
    }
    return nullptr;
}

struct ThreadInfo* getThreadByEncodedID(struct SharedVector* threads, u32 tid_enc) {
    for (u16 idx = 0; idx < threads->size; idx++) {
        ThreadInfo* thread = &threads->threads[idx];
        if (thread->tid_enc == tid_enc)
            return thread;
    }
    return nullptr;
}

ThreadID string2tid(std::string str) {
    return std::stoi(str, NULL, 16);
}

struct ThreadInfo* selectThread(struct SharedVector* threads, std::string id) {
    if (id == "0" || id == "-1")
        return getThreadByName(threads, GAME_MAIN_THREAD_NAME);
    return getThreadByID(threads, string2tid(id));
}