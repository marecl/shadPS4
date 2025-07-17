#include "gdb_data.h"

using namespace GdbDataType;

ThreadInfo* getThreadByID(SharedVector* threads, ThreadID id) {
    for (u16 idx = 0; idx < threads->size; idx++) {
        ThreadInfo* thread = &threads->threads[idx];
        if (id == thread->tid)
            return thread;
    }
    return nullptr;
}
ThreadInfo* getThreadByName(SharedVector* threads, std::string name) {
    for (u16 idx = 0; idx < threads->size; idx++) {
        ThreadInfo* thread = &threads->threads[idx];
        if (strncmp(thread->name, name.c_str(), 16) == 0)
            return thread;
    }
    return nullptr;
}

ThreadInfo* getThreadByEncodedID(SharedVector* threads, u32 tid_enc) {
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