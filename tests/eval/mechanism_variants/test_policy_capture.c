// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <assert.h>
#include <bpf/libbpf.h>
#include "mv_policy_capture.h"
int main(int argc,char **argv) {
 assert(argc==3);
 struct bpf_object *object=bpf_object__open_file(argv[1],NULL);
 assert(!libbpf_get_error(object));
 assert(!mv_policy_capture(object,argv[2]));
 bpf_object__close(object);return 0;
}
