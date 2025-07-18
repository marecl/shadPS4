#ifndef THREAD_META_H
#define THREAD_META_H

#include <iostream>
#include <string>
#include "src/common/types.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>
using ThreadID = DWORD;
#else
#include <pthread.h>
#include <signal.h>
using ThreadID = pthread_t;
#endif

#define GAME_MAIN_THREAD_NAME (const char*)"GAME_MainThread"
#define MAX_REGISTERED_THREADS 2137

struct ThreadInfo {
    ThreadID tid;
    u32 tid_enc;
    char name[16];
};

struct SharedVector {
    u16 size;
    ThreadInfo threads[MAX_REGISTERED_THREADS];
};

struct ThreadInfo* getThreadByID(struct SharedVector* threads, ThreadID id);
struct ThreadInfo* getThreadByName(struct SharedVector* threads, std::string name);
struct ThreadInfo* getThreadByEncodedID(struct SharedVector* threads, u32 tid_enc);
ThreadID string2tid(std::string str);

#endif // THREAD_META_H