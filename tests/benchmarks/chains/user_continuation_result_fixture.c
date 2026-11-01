/* SPDX-License-Identifier: GPL-2.0 */
/* Exercise the production serializer; no devices or runtime are replaced. */
#define _GNU_SOURCE
#define main unused_production_main
#include UC_BENCH_SOURCE
#undef main
int main(int argc, char **argv)
{
    struct chain_spec s = { .arm = CH_SESSION, .mode = CH_CORRECTNESS,
        .group_bytes = 4096, .nr_stages = 2, .xsk_mode = CH_XSK_ZC,
        .load = CH_LOAD_CLOSED, .oracle = CH_ORACLE_NONE };
    struct chain_result r = { .syscalls = 9, .oracle_verdict = "not-checked" };
    if (argc != 2) return 2;
    snprintf(s.chain, sizeof(s.chain), "nvme-nic");
    if (!strcmp(argv[1], "staged")) s.arm = CH_STAGED;
    cb_emit(stdout, &s, &r);
    return 0;
}
