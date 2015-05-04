/*
 * Header used to adapt pthread-based POSIX code to Windows API threads.
 *
 * Copyright (C) 2009 Andrzej K. Haczewski <ahaczewski@gmail.com>
 */

#ifndef PTHREAD_H
#define PTHREAD_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

/*
 * Defines that adapt Windows API threads to pthreads API
 */
typedef struct {
	CRITICAL_SECTION cs;
	LONG volatile autoinit;
} pthread_mutex_t;

#define PTHREAD_MUTEX_INITIALIZER { { 0 }, 1 }

typedef int pthread_mutexattr_t;

int pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
#define pthread_mutex_destroy(a) DeleteCriticalSection(&(a)->cs)
int pthread_mutex_lock(pthread_mutex_t *);
#define pthread_mutex_unlock(a) LeaveCriticalSection(&(a)->cs)

#define pthread_mutexattr_init(a) (*(a) = 0)
#define pthread_mutexattr_destroy(a) do {} while (0)
#define pthread_mutexattr_settype(a, t) 0
#define PTHREAD_MUTEX_RECURSIVE 0

/*
 * Implement simple condition variable for Windows threads, based on ACE
 * implementation.
 *
 * See original implementation: http://bit.ly/1vkDjo
 * ACE homepage: http://www.cse.wustl.edu/~schmidt/ACE.html
 * See also: http://www.cse.wustl.edu/~schmidt/win32-cv-1.html
 */
typedef struct {
	LONG waiters;
	int was_broadcast;
	CRITICAL_SECTION waiters_lock;
	HANDLE sema;
	HANDLE continue_broadcast;
} pthread_cond_t;

extern int pthread_cond_init(pthread_cond_t *cond, const void *unused);
extern int pthread_cond_destroy(pthread_cond_t *cond);
extern int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
extern int pthread_cond_signal(pthread_cond_t *cond);
extern int pthread_cond_broadcast(pthread_cond_t *cond);

/*
 * Simple thread creation implementation using pthread API
 */
typedef struct {
	HANDLE handle;
	HANDLE cancel_event;
	void *(*start_routine)(void*);
	void *arg;
	DWORD tid;
} pthread_t;

extern int pthread_create(pthread_t *thread, const void *unused,
			  void *(*start_routine)(void*), void *arg);

/*
 * To avoid the need of copying a struct, we use small macro wrapper to pass
 * pointer to win32_pthread_join instead.
 */
#define pthread_join(a, b) win32_pthread_join(&(a), (b))

extern int win32_pthread_join(pthread_t *thread, void **value_ptr);

#define pthread_equal(t1, t2) ((t1).tid == (t2).tid)
extern pthread_t pthread_self(void);

static inline int pthread_exit(void *ret)
{
	ExitThread((DWORD)ret);
}

typedef DWORD pthread_key_t;
static inline int pthread_key_create(pthread_key_t *keyp, void (*destructor)(void *value))
{
	return (*keyp = TlsAlloc()) == TLS_OUT_OF_INDEXES ? EAGAIN : 0;
}

static inline int pthread_key_delete(pthread_key_t key)
{
	return TlsFree(key) ? 0 : EINVAL;
}

static inline int pthread_setspecific(pthread_key_t key, const void *value)
{
	return TlsSetValue(key, (void *)value) ? 0 : EINVAL;
}

static inline void *pthread_getspecific(pthread_key_t key)
{
	return TlsGetValue(key);
}

static inline int pthread_cancel(pthread_t thread)
{
	SetEvent(thread.cancel_event);
	CancelSynchronousIo(thread.handle);
}

static inline void pthread_testcancel(void)
{
	pthread_t thread = pthread_self();
	if (WaitForSingleObject(thread.cancel_event, 0) == WAIT_OBJECT_0)
		pthread_exit(NULL);
}

#endif /* PTHREAD_H */
