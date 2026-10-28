/* SPDX-License-Identifier: GPL-2.0 */
/* Host test declarations only. This is not an SDK or CUDA ABI certificate. */
#ifndef TP_TEST_DRIVER_BOUNDARY_H
#define TP_TEST_DRIVER_BOUNDARY_H
#include <stddef.h>
#include <stdint.h>
#define CUDA_CB
typedef unsigned long long CUdeviceptr;
typedef unsigned long long cuuint64_t;
typedef void *CUcontext;
typedef void *CUstream;
typedef void *CUmodule;
typedef void *CUfunction;
typedef void *CUevent;
typedef void *CUgraph;
typedef void *CUgraphNode;
typedef void *CUuserObject;
typedef int CUresult;
typedef int CUmemorytype;
typedef int CUdevice;
typedef int CUstreamCaptureStatus;
enum {CUDA_SUCCESS=0,CUDA_ERROR_NOT_READY=600,CUDA_ERROR_NOT_SUPPORTED=801,
 CUDA_ERROR_NO_DEVICE=100,CUDA_ERROR_STUB_LIBRARY=34,CUDA_ERROR_UNKNOWN=999,
 CU_MEMORYTYPE_HOST=1,CU_MEMORYTYPE_DEVICE=2,CU_STREAM_CAPTURE_STATUS_NONE=0,
 CU_STREAM_CAPTURE_STATUS_ACTIVE=1,CU_POINTER_ATTRIBUTE_CONTEXT=1,
 CU_POINTER_ATTRIBUTE_MEMORY_TYPE=2,CU_POINTER_ATTRIBUTE_IS_MANAGED=3,
 CU_EVENT_DISABLE_TIMING=2,CU_USER_OBJECT_NO_DESTRUCTOR_SYNC=1,
 CU_GRAPH_USER_OBJECT_MOVE=1};
enum {CU_POINTER_ATTRIBUTE_SYNC_MEMOPS=6,CU_STREAM_NON_BLOCKING=1};
CUresult cuInit(unsigned);
CUresult cuDeviceGet(CUdevice *,int);
CUresult cuCtxCreate(CUcontext *,void *,unsigned,CUdevice);
CUresult cuCtxDestroy(CUcontext);
CUresult cuCtxGetDevice(CUdevice *);
CUresult cuStreamCreate(CUstream *,unsigned);
CUresult cuStreamDestroy(CUstream);
CUresult cuStreamQuery(CUstream);
CUresult cuPointerSetAttribute(const void *,int,CUdeviceptr);
CUresult cuEventSynchronize(CUevent);
CUresult cuCtxGetCurrent(CUcontext *);
CUresult cuStreamGetCtx(CUstream,CUcontext *);
CUresult cuStreamIsCapturing(CUstream,CUstreamCaptureStatus *);
CUresult cuStreamGetId(CUstream,unsigned long long *);
CUresult cuPointerGetAttribute(void *,int,CUdeviceptr);
CUresult cuMemGetAddressRange(CUdeviceptr *,size_t *,CUdeviceptr);
CUresult cuEventQuery(CUevent);
CUresult cuLaunchKernel(CUfunction,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,CUstream,void **,void **);
CUresult cuMemcpyHtoDAsync(CUdeviceptr,const void *,size_t,CUstream);
CUresult cuEventRecord(CUevent,CUstream);
CUresult cuMemcpyDtoH(void *,CUdeviceptr,size_t);
CUresult cuStreamGetCaptureInfo(CUstream,CUstreamCaptureStatus *,cuuint64_t *,CUgraph *,const CUgraphNode **,size_t *,const void **);
CUresult cuUserObjectCreate(CUuserObject *,void *,void (*)(void *),unsigned,unsigned);
CUresult cuGraphRetainUserObject(CUgraph,CUuserObject,unsigned,unsigned);
CUresult cuUserObjectRelease(CUuserObject,unsigned);
CUresult cuModuleLoad(CUmodule *,const char *);
CUresult cuModuleGetFunction(CUfunction *,CUmodule,const char *);
CUresult cuMemAlloc(CUdeviceptr *,size_t);
CUresult cuMemcpyHtoD(CUdeviceptr,const void *,size_t);
CUresult cuMemsetD8(CUdeviceptr,unsigned char,size_t);
CUresult cuMemFree(CUdeviceptr);
CUresult cuModuleUnload(CUmodule);
CUresult cuEventCreate(CUevent *,unsigned);
CUresult cuEventDestroy(CUevent);
#endif
