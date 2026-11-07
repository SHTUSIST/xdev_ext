// SPDX-License-Identifier: GPL-2.0
/* Real kernel/libbpf map/link controls only. Never CREATE/START or fake DMA. */
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "private_loader.h"
#include "nvme_ce_request.h"
int main(int argc,char **argv)
{
	struct rr_private p;
	const struct rr_request rows[4]={
		{100,2097152,1,1048576,0},{101,0,1048577,1048576,0},
		{102,1048576,1,1048576,1},{103,2097152,2097153,1048576,1}};
	if (argc!=3) return 2;
	int ret=rr_private_open(&p,argv[1],4,argv[2]);
	if (ret) {fprintf(stderr,"SETUP actual BPF/private load return=%d\n",ret);return 2;}
	unsigned failures=0;
	struct bpf_link_info nvme={0},ce={0};
	uint32_t n=sizeof(nvme);
	if (bpf_obj_get_info_by_fd(p.nvme_fd,&nvme,&n)) {rr_private_close(&p);return 2;}
	n=sizeof(ce);
	if (bpf_obj_get_info_by_fd(p.ce_fd,&ce,&n)) {rr_private_close(&p);return 2;}
	if (nvme.type!=BPF_LINK_TYPE_STRUCT_OPS || ce.type!=BPF_LINK_TYPE_STRUCT_OPS || nvme.id==ce.id) failures++;
	/* Session42 is map input only: no authority or kernel session is created. */
	ret=rr_private_fill_freeze(&p,42,rows,4,argv[2]);
	if (ret || !p.frozen) failures++;
	struct nvme_ce_request_key key={42,100};
	struct nvme_ce_request_value got={0};
	if (bpf_map_lookup_elem(p.map_fd,&key,&got) || got.nvme_byte_offset!=2097152 ||
	    got.gpu_byte_offset!=1 || got.byte_length!=1048576 || got.reserved) failures++;
	key.session_id=43;errno=0;
	if (!bpf_map_lookup_elem(p.map_fd,&key,&got) || errno!=ENOENT) failures++;
	key.session_id=42;key.request_key=99;errno=0;
	if (!bpf_map_lookup_elem(p.map_fd,&key,&got) || errno!=ENOENT) failures++;
	if (rr_private_fill_freeze(&p,42,rows,4,argv[2])!=-EINVAL) failures++;
	rr_private_close(&p);
	printf("actual-private-map: failures=%u DMA_executed=false\n",failures);
	return failures ? 1 : 0;
}
