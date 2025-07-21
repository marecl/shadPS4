#ifndef THREADINFO_H
#define THREADINFO_H

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

#endif // THREADINFO_H