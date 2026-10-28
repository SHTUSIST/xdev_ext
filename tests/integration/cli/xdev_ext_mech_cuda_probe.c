/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xdev_ext_mech_cuda.h"

void *__real_dlopen(const char *name, int flags);
void *__wrap_dlopen(const char *name, int flags)
{
	/* Deterministically simulate a missing driver, even on CUDA hosts. */
	if (getenv("CUDA_TEST_NO_LIBRARY") && name &&
	    !strcmp(name, "libcuda.so.1"))
		return NULL;
	return __real_dlopen(name, flags);
}

static void mark(const char *s)
{
	FILE *f = fopen(getenv("CUDA_TEST_TRACE"), "a");
	if (f) {
		fprintf(f, "%s\n", s);
		fclose(f);
	}
}

int main(int argc, char **argv)
{
	struct xdev_ext_mech_cuda cuda = {0};
	void *lib, *current = NULL;
	int (*get_current)(void **);
	int (*set_current)(void *);
	int rc;
	int retry = getenv("CUDA_TEST_FAIL") &&
		!strcmp(getenv("CUDA_TEST_FAIL"), "close_restore");
	const char *bdf = argc > 1 ? argv[1] : "0000:65:00.0";
	uint64_t bytes = argc > 2 ? strtoull(argv[2], NULL, 0) : 8192;

	printf("zero_close=%d\n", xdev_ext_mech_cuda_close(&cuda));
	mark("before_open");
	rc = xdev_ext_mech_cuda_open(&cuda, !strcmp(bdf, "NULL") ? NULL : bdf,
				bytes);
	mark("after_open");
	printf("open=%d\nva=%llu\n", rc, (unsigned long long)cuda.va);
	lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_NOLOAD);
	printf("loaded_after_open=%d\n", lib != NULL);
	if (!rc && lib) {
		get_current = (int (*)(void **))dlsym(lib, "cuCtxGetCurrent");
		set_current = (int (*)(void *))dlsym(lib, "cuCtxSetCurrent");
		if (!get_current || !set_current)
			return 3;
		get_current(&current);
		printf("current_after_open=%llu\n",
		       (unsigned long long)(uintptr_t)current);
		/* close must restore the caller's context at close time. */
		set_current((void *)(uintptr_t)0x333);
	}
	if (lib && !retry)
		dlclose(lib);
	mark("before_close");
	printf("close=%d\n", xdev_ext_mech_cuda_close(&cuda));
	mark("after_close");
	if (retry && !rc && lib) {
		/* A failed close does not own the next caller's current context. */
		set_current((void *)(uintptr_t)0x444);
		mark("before_retry_close");
		printf("retry_close=%d\n", xdev_ext_mech_cuda_close(&cuda));
		get_current(&current);
		printf("current_after_retry=%llu\n",
		       (unsigned long long)(uintptr_t)current);
		dlclose(lib);
	}
	printf("va_after_close=%llu\n", (unsigned long long)cuda.va);
	printf("again_close=%d\n", xdev_ext_mech_cuda_close(&cuda));
	lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_NOLOAD);
	printf("loaded_after_close=%d\n", lib != NULL);
	if (lib)
		dlclose(lib);
	return 0;
}
