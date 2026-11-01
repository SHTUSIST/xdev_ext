/* SPDX-License-Identifier: GPL-2.0 */
/* Execute actual staged GPU production functions. CUDA driver calls alone are
 * boundary callbacks; no chain scheduler/completion algorithm is reimplemented.
 */
#define _GNU_SOURCE
#ifndef UC_STAGED_SOURCE
#error "build supplies the snapshotted actual production staged source"
#endif
#include UC_STAGED_SOURCE

static unsigned int h2d_calls, d2h_calls, queries;
static unsigned char device_bytes[4096];
static int driver_h2d(uint64_t dst, const void *src, size_t len, void *stream)
{
    if (dst != 0x10000 || len != 4096 || stream != (void *)0xabc) return 1;
    memcpy(device_bytes, src, len);
    h2d_calls++;
    return 0;
}
static int driver_d2h(void *dst, uint64_t src, size_t len, void *stream)
{
    if (src != 0x10000 || len != 4096 || stream != (void *)0xabc) return 1;
    memcpy(dst, device_bytes, len);
    d2h_calls++;
    return 0;
}
static int driver_query(void *stream)
{
    if (stream != (void *)0xabc) return 1;
    return queries++ ? 0 : CHAIN_CUDA_NOT_READY;
}
int main(int argc, char **argv)
{
    struct chain_spec s = { .arm = CH_STAGED, .gpu = CH_GPU_CUDA, .depth = 1,
                            .group_bytes = 4096, .nr_stages = 2 };
    struct chain_result result = { 0 };
    unsigned char source[4096], returned[4096];
    struct sg_slot slot = { .state = SL_IO };
    struct sg x = { .s = &s, .r = &result, .a = source, .b = returned,
                    .stride = 4096, .slot = &slot, .gpu = true };
    bool busy;
    if (argc != 2) return 2;
    snprintf(s.chain, sizeof(s.chain), "%s", argv[1]);
    s.st[0].cls = CH_NVME; s.st[0].dir = CH_FROM;
    s.st[1].cls = CH_CE; s.st[1].dir = CH_TO;
    if (!strcmp(argv[1], "nvme-gpu-nic")) {
        s.nr_stages = 4; s.st[2].cls = CH_CE; s.st[2].dir = CH_FROM;
        s.st[3].cls = CH_AFXDP; s.st[3].dir = CH_TO;
    }
    memset(source, 0x5d, sizeof(source)); memset(returned, 0xc9, sizeof(returned));
    x.cuda.nr_streams = 1; x.cuda.dbuf = 0x10000; x.cuda.dlen = 4096;
    x.cuda.streams[0] = (void *)0xabc;
    x.cuda.h2d = driver_h2d; x.cuda.d2h = driver_d2h; x.cuda.stream_query = driver_query;
    if (sg_gpu_start(&x, 0)) return 3;
    if (slot.state != SL_GPU) return 4; /* H2D submission alone is not completion. */
    if (sg_gpu_poll(&x, &busy) || !busy || slot.state != SL_GPU) return 5;
    if (sg_gpu_poll(&x, &busy) || busy || slot.state != SL_READY) return 6;
    printf("{\"h2d_calls\":%u,\"d2h_calls\":%u,\"queries\":%u,\"device_matches\":%s,\"return_untouched\":%s}\n",
        h2d_calls, d2h_calls, queries, !memcmp(source, device_bytes, sizeof(source)) ? "true" : "false",
        returned[0] == 0xc9 && returned[4095] == 0xc9 ? "true" : "false");
    return 0;
}
