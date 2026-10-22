// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>

static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_changed = PTHREAD_COND_INITIALIZER;
static bool barrier_armed = true;
static bool barrier_blocked;
static bool barrier_released;
static pthread_once_t real_once = PTHREAD_ONCE_INIT;
static int (*real_getsockopt)(int, int, int, void *, socklen_t *);

static void resolve_getsockopt(void)
{
	*(void **)&real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
}

int test_socket_barrier_wait_until_blocked(void)
{
	int ret;

	ret = pthread_mutex_lock(&barrier_lock);
	if (ret)
		return ret;
	while (!barrier_blocked) {
		ret = pthread_cond_wait(&barrier_changed, &barrier_lock);
		if (ret)
			break;
	}
	pthread_mutex_unlock(&barrier_lock);
	return ret;
}

int test_socket_barrier_release(void)
{
	int ret;

	ret = pthread_mutex_lock(&barrier_lock);
	if (ret)
		return ret;
	barrier_released = true;
	ret = pthread_cond_broadcast(&barrier_changed);
	pthread_mutex_unlock(&barrier_lock);
	return ret;
}

int getsockopt(int fd, int level, int option_name, void *option_value,
	       socklen_t *option_length)
{
	bool block = false;

	pthread_once(&real_once, resolve_getsockopt);
	if (level == SOL_SOCKET && option_name == SO_TYPE) {
		pthread_mutex_lock(&barrier_lock);
		if (barrier_armed) {
			barrier_armed = false;
			barrier_blocked = true;
			block = true;
			pthread_cond_broadcast(&barrier_changed);
		}
		while (block && !barrier_released)
			pthread_cond_wait(&barrier_changed, &barrier_lock);
		pthread_mutex_unlock(&barrier_lock);
	}
	return real_getsockopt(fd, level, option_name, option_value,
			       option_length);
}
