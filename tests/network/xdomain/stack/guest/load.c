// SPDX-License-Identifier: GPL-2.0
/* Keep full verifier diagnostics. Open/BTF/attach failures are setup (3). */
#include <stdio.h>
#include <stdarg.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
static int logger(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}
int main(int argc, char **argv)
{
    struct bpf_object *object;
    struct bpf_map *map;
    struct bpf_link *link;
    struct btf *btf;
    const char *types[] = {"xdev_ext_xdomain_mech_ops", "xdev_ext_nvme_mech_ops",
        "xdev_ext_net_mech_ops", "xdev_ext_afxdp_mech_ops", "xdev_ext_socket_mech_ops"};
    const char *funcs[] = {"bpf_xdev_ext_xdomain_info", "bpf_xdev_ext_xdomain_verdict",
        "bpf_xdev_ext_net_rel_tx_state"};
    int ret;
    if (argc != 3) return 3;
    libbpf_set_print(logger);
    btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf)) return 3;
    for (unsigned int i = 0; i < sizeof(types)/sizeof(types[0]); i++)
        if (btf__find_by_name_kind(btf, types[i], BTF_KIND_STRUCT) < 0) {
            fprintf(stderr, "XDOMAIN_SETUP_FAIL missing BTF type %s\n", types[i]); return 3;
        }
    for (unsigned int i = 0; i < sizeof(funcs)/sizeof(funcs[0]); i++)
        if (btf__find_by_name_kind(btf, funcs[i], BTF_KIND_FUNC) < 0) {
            fprintf(stderr, "XDOMAIN_SETUP_FAIL missing BTF kfunc %s\n", funcs[i]); return 3;
        }
    btf__free(btf);
    object = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(object)) return 3;
    ret = bpf_object__load(object);
    if (ret) { bpf_object__close(object); return 1; }
    map = bpf_object__find_map_by_name(object, argv[2]);
    if (!map) { bpf_object__close(object); return 3; }
    link = bpf_map__attach_struct_ops(map);
    ret = libbpf_get_error(link);
    if (ret) { bpf_object__close(object); return 3; }
    bpf_link__destroy(link);
    bpf_object__close(object);
    puts("XDOMAIN_LOAD_ALLOW");
    return 0;
}
