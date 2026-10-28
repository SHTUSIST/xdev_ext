/* SPDX-License-Identifier: MIT */
/*
 * Ordinary host-C definitions shared by the actual-body lifecycle fixtures.
 * Values of the NV status codes are copied from nvstatuscodes.h. Nothing here
 * models a device: fixtures stub only allocation, locking and RM/OS calls.
 */
#ifndef NV_XDEV_EXT_HOST_ENV_H
#define NV_XDEV_EXT_HOST_ENV_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t NvU8;
typedef uint16_t NvU16;
typedef uint32_t NvU32;
typedef int32_t NvS32;
typedef uint64_t NvU64;
typedef int64_t NvS64;
typedef NvU8 NvBool;
typedef NvU32 NV_STATUS;
typedef NvU32 NvHandle;
typedef NvU64 NvLength;
typedef NvU64 RmPhysAddr;
#define NV_TRUE ((NvBool)1)
#define NV_FALSE ((NvBool)0)
#define NV_API_CALL
#define NV_U32_MAX UINT32_MAX
#define NV_U64_MAX UINT64_MAX
#define NV_S32_MAX INT32_MAX

#define NV_OK 0x00000000
#define NV_ERR_GENERIC 0x0000FFFF
#define NV_ERR_BUSY_RETRY 0x00000003
#define NV_ERR_GPU_IS_LOST 0x0000000F
#define NV_ERR_GPU_UUID_NOT_FOUND 0x00000012
#define NV_ERR_IN_USE 0x00000017
#define NV_ERR_INSUFFICIENT_RESOURCES 0x0000001A
#define NV_ERR_INSUFFICIENT_PERMISSIONS 0x0000001B
#define NV_ERR_INVALID_ADDRESS 0x0000001E
#define NV_ERR_INVALID_ARGUMENT 0x0000001F
#define NV_ERR_INVALID_DEVICE 0x00000026
#define NV_ERR_INVALID_LOCK_STATE 0x0000002F
#define NV_ERR_INVALID_OBJECT 0x00000031
#define NV_ERR_INVALID_OBJECT_HANDLE 0x00000033
#define NV_ERR_INVALID_OBJECT_PARENT 0x00000036
#define NV_ERR_INVALID_STATE 0x00000040
#define NV_ERR_NO_MEMORY 0x00000051
#define NV_ERR_NOT_SUPPORTED 0x00000056
#define NV_ERR_OBJECT_NOT_FOUND 0x00000057
#define NV_ERR_STATE_IN_USE 0x00000063
#define NV_ERR_TIMEOUT 0x00000065

/* Test reporting shared by the fixtures. */
static unsigned int env_checks, env_failures;
#define CHECK(cond, ...) do { \
	env_checks++; \
	if (!(cond)) { \
		env_failures++; \
		fprintf(stdout, "FAIL %s:%d: %s: ", __func__, __LINE__, #cond); \
		fprintf(stdout, __VA_ARGS__); \
		fputc('\n', stdout); \
	} \
} while (0)
#define REQUIRE(cond, ...) do { \
	env_checks++; \
	if (!(cond)) { \
		env_failures++; \
		fprintf(stdout, "FAIL %s:%d: %s: ", __func__, __LINE__, #cond); \
		fprintf(stdout, __VA_ARGS__); \
		fputc('\n', stdout); \
		return; \
	} \
} while (0)

static int env_report(const char *what)
{
	printf("%s checks=%u failures=%u\n", what, env_checks, env_failures);
	return env_failures ? 1 : 0;
}

#endif
