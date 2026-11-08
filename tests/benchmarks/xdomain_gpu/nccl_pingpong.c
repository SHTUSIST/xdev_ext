// SPDX-License-Identifier: GPL-2.0
/*
 * nccl_pingpong - E4 baseline 2 latency: ncclSend/ncclRecv ping-pong, VRAM to VRAM.
 *
 *   rank 1: nccl_pingpong --rank 1 --listen ADDR:PORT [options]
 *   rank 0: nccl_pingpong --rank 0 --peer   ADDR:PORT [options]
 *
 * nccl-tests sendrecv_perf sends in both directions at once, so it is not a
 * ping-pong; this program is (plan E4, baseline 2, TODO.77).  A TCP control
 * connection checks that both ranks use the same options and carries the
 * ncclUniqueId; then each rank runs ncclCommInitRank(2) on one GPU.  Rank 0
 * enqueues ncclSend then ncclRecv of SIZE int8 elements on one stream and
 * waits for the stream; rank 1 enqueues ncclRecv then ncclSend, so its send
 * starts only after the receive completed.  Rank 0 times each round trip
 * with CLOCK_MONOTONIC after --warmup rounds (RTT/2 is a symmetric estimate).
 * Both ranks check the received VRAM after the timed loop.
 *
 * NCCL runs with its defaults; the operator sets only NCCL_SOCKET_IFNAME
 * (thunderbolt0) and NCCL_DEBUG=INFO, and the runner confirms NET/Socket
 * from that log.  The NCCL environment and version are recorded.  NCCL and
 * CUDA are opened at run time (libnccl.so.2, libcuda.so.1); a missing
 * library exits 4.  Exit: 0 pass, 1 failure, 2 usage, 4 unavailable.
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>

#include "xdg_core.h"
#include "xdg_net.h"
#include "xdg_gpu.h"

#define NCCL_UNIQUE_ID_BYTES	128
typedef struct { char internal[NCCL_UNIQUE_ID_BYTES]; } nccl_unique_id;
enum { NCCL_INT8 = 0 };	/* ncclInt8 */

struct nccl {
	void *lib, *comm;
	int version;
	int (*get_version)(int *);
	int (*get_unique_id)(nccl_unique_id *);
	int (*comm_init_rank)(void **, int, nccl_unique_id, int);
	int (*comm_destroy)(void *);
	int (*send)(const void *, size_t, int, int, void *, void *);
	int (*recv)(void *, size_t, int, int, void *, void *);
	const char *(*error_string)(int);
};

struct opts {
	int rank, gpu, timeout_s;
	const char *peer, *listen, *sizes_arg;
	uint64_t sizes[XDG_MAX_SIZES], iters, warmup, seed;
	int nsizes;
	bool dry_run;
};

static void usage(void)
{
	fprintf(stderr,
		"usage: nccl_pingpong --rank 0 --peer HOST:PORT | --rank 1 --listen HOST:PORT\n"
		"       [--sizes LIST] [--iters N] [--warmup N] [--seed N] [--gpu N]\n"
		"       [--timeout-s S] [--dry-run]\n");
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct option lo[] = {
		{ "rank", required_argument, NULL, 'r' }, { "peer", required_argument, NULL, 'p' },
		{ "listen", required_argument, NULL, 'l' }, { "sizes", required_argument, NULL, 's' },
		{ "iters", required_argument, NULL, 'i' }, { "warmup", required_argument, NULL, 'w' },
		{ "seed", required_argument, NULL, 'S' }, { "gpu", required_argument, NULL, 'g' },
		{ "timeout-s", required_argument, NULL, 't' }, { "dry-run", no_argument, NULL, 'd' },
		{ 0 }
	};
	uint64_t v;
	int c;

	*o = (struct opts){ .rank = -1, .timeout_s = 120, .iters = 1000, .warmup = 100, .seed = 1 };
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		const char *a = optarg;
		size_t n = a ? strlen(a) : 0;

		switch (c) {
		case 'r': if (xdg_parse_u64(a, n, 1, &v)) return -EINVAL; o->rank = (int)v; break;
		case 'p': o->peer = a; break;
		case 'l': o->listen = a; break;
		case 's': o->sizes_arg = a; break;
		case 'i': if (xdg_parse_u64(a, n, 100000000, &o->iters) || !o->iters) return -EINVAL; break;
		case 'w': if (xdg_parse_u64(a, n, 100000000, &o->warmup)) return -EINVAL; break;
		case 'S': if (xdg_parse_u64(a, n, UINT32_MAX, &o->seed)) return -EINVAL; break;
		case 'g': if (xdg_parse_u64(a, n, 64, &v)) return -EINVAL; o->gpu = (int)v; break;
		case 't': if (xdg_parse_u64(a, n, 3600, &v) || !v) return -EINVAL; o->timeout_s = (int)v; break;
		case 'd': o->dry_run = true; break;
		default: return -EINVAL;
		}
	}
	if (optind != argc || o->rank < 0 || (o->rank == 0) != !!o->peer ||
	    (o->rank == 1) != !!o->listen)
		return -EINVAL;
	o->nsizes = xdg_parse_sizes(o->sizes_arg, o->sizes);
	return o->nsizes < 0 ? -EINVAL : 0;
}

static int nccl_sym(struct nccl *n, void *slot, const char *name)
{
	void *f = dlsym(n->lib, name);

	if (!f) {
		fprintf(stderr, "NCCL lacks %s\n", name);
		return -ENOSYS;
	}
	memcpy(slot, &f, sizeof(f));
	return 0;
}

static int nccl_open(struct nccl *n)
{
	memset(n, 0, sizeof(*n));
	n->lib = dlopen("libnccl.so.2", RTLD_NOW | RTLD_LOCAL);
	if (!n->lib)
		return -ENOSYS;
	if (nccl_sym(n, &n->get_version, "ncclGetVersion") ||
	    nccl_sym(n, &n->get_unique_id, "ncclGetUniqueId") ||
	    nccl_sym(n, &n->comm_init_rank, "ncclCommInitRank") ||
	    nccl_sym(n, &n->comm_destroy, "ncclCommDestroy") ||
	    nccl_sym(n, &n->send, "ncclSend") || nccl_sym(n, &n->recv, "ncclRecv") ||
	    nccl_sym(n, &n->error_string, "ncclGetErrorString"))
		return -ENOSYS;
	return n->get_version(&n->version) ? -EIO : 0;
}

static int nccl_check(struct nccl *n, int r, const char *what)
{
	if (!r)
		return 0;
	fprintf(stderr, "nccl_pingpong: %s: %s\n", what, n->error_string(r));
	return -EIO;
}

static void env_json(const char *name, bool first)
{
	const char *v = getenv(name);

	printf("%s\"%s\": ", first ? "" : ", ", name);
	if (!v) {
		printf("null");
		return;
	}
	putchar('"');
	for (; *v; v++)
		if (*v >= 0x20 && *v != '"' && *v != '\\')
			putchar(*v);
	putchar('"');
}

int main(int argc, char **argv)
{
	static const char *const env[] = { "NCCL_SOCKET_IFNAME", "NCCL_DEBUG", "NCCL_NET",
					   "NCCL_IB_DISABLE", "NCCL_P2P_DISABLE", "NCCL_PROTO",
					   "NCCL_ALGO", "NCCL_SOCKET_NTHREADS", "NCCL_NSOCKS_PERTHREAD" };
	struct opts o;
	struct xdg_gpu g = { 0 };
	struct nccl n = { 0 };
	nccl_unique_id id;
	uint64_t max, tx = 0, rx = 0, *rtt = NULL;
	void *stream = NULL, *scratch = NULL;
	char config[512];
	int fd = -1, ret, i;

	if (parse(argc, argv, &o)) {
		usage();
		return XDG_EXIT_USAGE;
	}
	if (o.dry_run) {
		printf("{\"tool\": \"nccl_pingpong\", \"arm\": \"nccl-sendrecv\", \"dry_run\": true, "
		       "\"rank\": %d, \"iters\": %" PRIu64 ", \"warmup\": %" PRIu64 ", \"sizes\": [",
		       o.rank, o.iters, o.warmup);
		for (i = 0; i < o.nsizes; i++)
			printf("%s%" PRIu64, i ? ", " : "", o.sizes[i]);
		printf("]}\n");
		return XDG_EXIT_PASS;
	}
	max = o.sizes[o.nsizes - 1];
	ret = nccl_open(&n);
	if (!ret)
		ret = xdg_gpu_open(&g, o.gpu, 0);
	if (ret == -ENOSYS) {
		fprintf(stderr, "nccl_pingpong: libnccl.so.2 or libcuda.so.1 unavailable\n");
		return XDG_EXIT_UNAVAILABLE;
	}
	if (!ret)
		ret = xdg_gpu_alloc(&g, max, &tx);
	if (!ret)
		ret = xdg_gpu_alloc(&g, max, &rx);
	if (!ret && (g.stream_create(&stream, 0) || !(scratch = malloc(max)) ||
		     !(rtt = calloc(o.iters, sizeof(*rtt)))))
		ret = -ENOMEM;
	if (!ret) {
		fd = xdg_tcp_open(o.rank ? o.listen : o.peer, o.rank, o.timeout_s);
		ret = fd < 0 ? fd : 0;
	}
	snprintf(config, sizeof(config), "nccl_pingpong v1 sizes=%s iters=%" PRIu64 " warmup=%"
		 PRIu64 " seed=%" PRIu64 " nccl=%d", o.sizes_arg ? o.sizes_arg : "default",
		 o.iters, o.warmup, o.seed, n.version);
	if (!ret)
		ret = xdg_exchange_config(fd, config);
	if (!ret && o.rank == 0)
		ret = nccl_check(&n, n.get_unique_id(&id), "ncclGetUniqueId");
	if (!ret)
		ret = o.rank == 0 ? xdg_send_all(fd, &id, sizeof(id)) : xdg_recv_all(fd, &id, sizeof(id));
	if (!ret)
		ret = nccl_check(&n, n.comm_init_rank(&n.comm, 2, id, o.rank), "ncclCommInitRank");
	for (i = 0; i < o.nsizes && !ret; i++) {
		uint64_t size = o.sizes[i], bad, total = o.warmup + o.iters;
		uint64_t mine = o.seed + (uint64_t)o.rank, theirs = o.seed + (uint64_t)(1 - o.rank);
		uint8_t ok = 0, peer_ok = 0;
		struct xdg_stats st = { 0 };

		ret = xdg_gpu_seed(&g, tx, size, mine, 0, scratch);
		if (!ret)
			ret = xdg_barrier(fd, 'N');
		for (uint64_t k = 0; k < total && !ret; k++) {
			uint64_t t0 = xdg_now_ns();

			if (o.rank == 0) {
				ret = nccl_check(&n, n.send((void *)(uintptr_t)tx, size, NCCL_INT8, 1,
							    n.comm, stream), "ncclSend");
				if (!ret)
					ret = nccl_check(&n, n.recv((void *)(uintptr_t)rx, size, NCCL_INT8,
								    1, n.comm, stream), "ncclRecv");
			} else {
				ret = nccl_check(&n, n.recv((void *)(uintptr_t)rx, size, NCCL_INT8, 0,
							    n.comm, stream), "ncclRecv");
				if (!ret)
					ret = nccl_check(&n, n.send((void *)(uintptr_t)tx, size, NCCL_INT8,
								    0, n.comm, stream), "ncclSend");
			}
			if (!ret && g.stream_sync(stream))
				ret = -EIO;
			if (!ret && o.rank == 0 && k >= o.warmup)
				rtt[k - o.warmup] = xdg_now_ns() - t0;
		}
		if (!ret)
			ret = xdg_gpu_dtoh(&g, scratch, rx, size);
		ok = !ret && !xdg_check(scratch, size, theirs, 0, &bad);
		if (!ret)
			ret = xdg_send_all(fd, &ok, 1);
		if (!ret)
			ret = xdg_recv_all(fd, &peer_ok, 1);
		if (ret)
			break;
		if (o.rank == 0)
			xdg_stats(rtt, o.iters, &st);
		printf("{\"tool\": \"nccl_pingpong\", \"arm\": \"nccl-sendrecv\", \"rank\": %d, "
		       "\"mode\": \"pingpong\", \"size\": %" PRIu64 ", \"nccl_version\": %d, "
		       "\"cuda_driver_version\": %d, \"execution\": \"cuda\", "
		       "\"performance_claim\": \"e4-vram-to-vram\", \"env\": {",
		       o.rank, size, n.version, g.driver_version);
		for (unsigned e = 0; e < sizeof(env) / sizeof(env[0]); e++)
			env_json(env[e], !e);
		printf("}");
		if (o.rank == 0)
			printf(", \"warmup\": %" PRIu64 ", \"clock\": \"CLOCK_MONOTONIC rank 0\", "
			       "\"rtt_ns\": {\"n\": %" PRIu64 ", \"min\": %" PRIu64 ", \"median\": %"
			       PRIu64 ", \"p99\": %" PRIu64 ", \"max\": %" PRIu64
			       "}, \"half_rtt_ns_median\": %" PRIu64, o.warmup, st.n, st.min, st.median,
			       st.p99, st.max, st.median / 2);
		printf(", \"verified\": %s, \"peer_verified\": %s}\n", ok ? "true" : "false",
		       peer_ok ? "true" : "false");
		fflush(stdout);
		if (!ok || !peer_ok)
			ret = -EIO;
	}
	if (ret)
		fprintf(stderr, "nccl_pingpong: rank %d: %s\n", o.rank, strerror(-ret));
	if (n.comm)
		n.comm_destroy(n.comm);
	if (fd >= 0)
		close(fd);
	if (stream)
		g.stream_destroy(stream);
	xdg_gpu_free(&g, tx);
	xdg_gpu_free(&g, rx);
	free(scratch);
	free(rtt);
	xdg_gpu_close(&g);
	return ret ? XDG_EXIT_FAIL : XDG_EXIT_PASS;
}
