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

#endif // THREAD_META_H