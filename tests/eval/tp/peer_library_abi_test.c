// SPDX-License-Identifier: GPL-2.0
/* The runnable ABI gate catches absent message operations in the real library.
 * Behavioral syscall/custody tests live in the independent lib selftest suite. */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	const char *symbols[] = {
		"xdev_ext_session_open_peer", "xdev_ext_session_start_frames",
		"xdev_ext_user_batch_peer_span", "xdev_ext_user_stage_control",
		"xdev_ext_user_stage_ctl_attach", "xdev_ext_user_stage_ctl_detach",
		"xdev_ext_peer_endpoint_open", "xdev_ext_peer_endpoint_start",
		"xdev_ext_peer_endpoint_next", "xdev_ext_peer_endpoint_complete",
		"xdev_ext_peer_endpoint_stop", "xdev_ext_peer_endpoint_close",
	};
	unsigned int i, failed = 0;
	void *lib;
	if (argc != 2) return 2;
	lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
	printf("TAP version 13\n1..%zu\n", sizeof(symbols)/sizeof(symbols[0]));
	for (i = 0; i < sizeof(symbols)/sizeof(symbols[0]); i++) {
		int present = dlsym(lib, symbols[i]) != NULL;
		printf("%s %u - real library exports %s\n", present ? "ok" : "not ok", i+1, symbols[i]);
		failed += !present;
	}
	dlclose(lib);
	return failed ? 1 : 0;
}
