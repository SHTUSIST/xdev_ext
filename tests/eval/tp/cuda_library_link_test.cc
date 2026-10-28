// SPDX-License-Identifier: GPL-2.0
/* Official Driver header plus the real library symbols; never executed with
 * the link stub. This is a link/build test, not GPU correctness evidence. */
#include <cuda.h>
struct xdev_ext_user_stage;
struct xdev_ext_cuda_user;
struct xdev_ext_cuda_message;
extern "C" int xdev_ext_cuda_user_open(xdev_ext_user_stage *, CUcontext,
    CUdeviceptr, unsigned long long, unsigned int, xdev_ext_cuda_user **);
extern "C" int xdev_ext_cuda_user_wait(xdev_ext_cuda_user *, CUstream,
    xdev_ext_cuda_message *);
extern "C" int xdev_ext_cuda_user_done(xdev_ext_cuda_user *, CUstream,
    xdev_ext_cuda_message *);
extern "C" int xdev_ext_cuda_user_close(xdev_ext_cuda_user *, CUstream);
int main()
{
    xdev_ext_cuda_user *u = nullptr;
    int rc = xdev_ext_cuda_user_open(nullptr, nullptr, 0, 0, 0, &u);
    rc += xdev_ext_cuda_user_wait(u, nullptr, nullptr);
    rc += xdev_ext_cuda_user_done(u, nullptr, nullptr);
    rc += xdev_ext_cuda_user_close(u, nullptr);
    return rc == 0;
}
