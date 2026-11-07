// SPDX-License-Identifier: GPL-2.0
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "private_loader.h"
#include "nvme_ce_request.h"

static int evidence_write(const char *dir, const char *name, const void *data, size_t n)
{
	char path[4096];
	FILE *f;
	int ret = 0;
	if (snprintf(path,sizeof(path),"%s/%s",dir,name) >= (int)sizeof(path)) return -ENAMETOOLONG;
	f = fopen(path,"wx");
	if (!f) return -errno;
	if (fwrite(data,1,n,f) != n) ret = -EIO;
	if (fclose(f) && !ret) ret = -errno;
	return ret;
}
/* Inspect actual object's typed initial struct_ops data. Never patch flags
 * or use guessed offsets; the checked-in pair already declares PRIVATE. */
static int private_ops(struct bpf_object *object, struct bpf_map *map,
		const char *type, uint32_t abi)
{
	struct btf *btf = bpf_object__btf(object);
	const struct btf_type *t;
	const void *value;
	size_t size = 0;
	unsigned i, found = 0;
	int id;
	if (!btf || !map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS) return -EINVAL;
	id = btf__find_by_name_kind(btf,type,BTF_KIND_STRUCT);
	if (id <= 0) return -EINVAL;
	t = btf__type_by_id(btf,id);
	value = bpf_map__initial_value(map,&size);
	if (!t || !value || size != t->size) return -EINVAL;
	for (i=0; i<btf_vlen(t); i++) {
		const struct btf_member *m = btf_members(t)+i;
		const char *name = btf__name_by_offset(btf,m->name_off);
		uint32_t got, want;
		size_t off;
		if (!name) return -EINVAL;
		if (!strcmp(name,"abi_version")) { want=abi; found|=1; }
		else if (!strcmp(name,"flags")) { want=XDEV_EXT_MECH_OPS_F_PRIVATE; found|=2; }
		else continue;
		if (btf_member_bitfield_size(t,i) || (btf_member_bit_offset(t,i)&7)) return -EINVAL;
		off = btf_member_bit_offset(t,i)/8;
		if (off > size || sizeof(got) > size-off) return -EINVAL;
		memcpy(&got,(const char *)value+off,sizeof(got));
		if (got != want) return -EINVAL;
	}
	return found == 3 ? 0 : -EINVAL;
}
void rr_private_close(struct rr_private *p)
{
	if (!p) return;
	if (p->ce) bpf_link__destroy(p->ce);
	if (p->nvme) bpf_link__destroy(p->nvme);
	if (p->object) bpf_object__close(p->object);
	memset(p,0,sizeof(*p));
	p->map_fd=p->nvme_fd=p->ce_fd=-1;
}
int rr_private_open(struct rr_private *p, const char *path, size_t records,
		const char *evidence)
{
	struct bpf_map *map, *nvme, *ce, *request;
	struct bpf_program *program;
	struct bpf_map_info info = {0};
	uint32_t size = sizeof(info);
	char *log;
	struct { char *buffer; const char *name; } logs[6] = {0};
	unsigned ops = 0, nr_logs = 0, i;
	int ret;
	const size_t log_bytes = 8U*1024U*1024U;
	if (!p || !path || !evidence || !records || records > UINT32_MAX) return -EINVAL;
	memset(p,0,sizeof(*p)); p->map_fd=p->nvme_fd=p->ce_fd=-1;
	log = calloc(1,log_bytes);
	if (!log) return -ENOMEM;
	struct bpf_object_open_opts options = {.sz=sizeof(options),
		.kernel_log_buf=log,.kernel_log_size=log_bytes,.kernel_log_level=1};
	p->object = bpf_object__open_file(path,&options);
	ret = (int)libbpf_get_error(p->object);
	if (ret) { p->object=NULL; goto done; }
	nvme = bpf_object__find_map_by_name(p->object,"request_nvme_ops");
	ce = bpf_object__find_map_by_name(p->object,"request_ce_ops");
	request = bpf_object__find_map_by_name(p->object,"request_map");
	ret = private_ops(p->object,nvme,"xdev_ext_nvme_mech_ops",1);
	if (!ret) ret=private_ops(p->object,ce,"xdev_ext_ce_mech_ops",2);
	if (ret) goto done;
	bpf_object__for_each_map(map,p->object)
		if (bpf_map__type(map)==BPF_MAP_TYPE_STRUCT_OPS) ops++;
	if (ops != 2 || !request || bpf_map__type(request)!=BPF_MAP_TYPE_HASH ||
	    bpf_map__key_size(request)!=sizeof(struct nvme_ce_request_key) ||
	    bpf_map__value_size(request)!=sizeof(struct nvme_ce_request_value) ||
	    bpf_map__map_flags(request)!=BPF_F_RDONLY_PROG) { ret=-EINVAL; goto done; }
	ret=bpf_map__set_max_entries(request,(uint32_t)records);
	if (ret) goto done;
	/* Save separate verifier logs for each actual callback, not just BTF. */
	bpf_object__for_each_program(program,p->object) {
		if (nr_logs == 6) { ret=-E2BIG; goto done; }
		logs[nr_logs].buffer=calloc(1,log_bytes);
		logs[nr_logs].name=bpf_program__name(program);
		if (!logs[nr_logs].buffer) {ret=-ENOMEM;goto done;}
		nr_logs++;
		ret=bpf_program__set_log_buf(program,logs[nr_logs-1].buffer,log_bytes);
		if (!ret) ret=bpf_program__set_log_level(program,1);
		if (ret) goto done;
	}
	if (nr_logs!=6) {ret=-EINVAL;goto done;}
	ret=bpf_object__load(p->object);
	{
		int saved=evidence_write(evidence,"loader-verifier.log",log,strnlen(log,log_bytes));
		if (!ret) ret=saved;
	}
	for (i=0;i<nr_logs;i++) {
		char name[256];
		if (snprintf(name,sizeof(name),"%s-verifier.log",logs[i].name)>=(int)sizeof(name)) {
			if (!ret) ret=-ENAMETOOLONG;
			continue;
		}
		int saved=evidence_write(evidence,name,logs[i].buffer,strnlen(logs[i].buffer,log_bytes));
		if (!ret) ret=saved;
	}
	if (ret) goto done;
	p->nvme=bpf_map__attach_struct_ops(nvme);
	ret=(int)libbpf_get_error(p->nvme);
	if (ret) {p->nvme=NULL;goto done;}
	p->ce=bpf_map__attach_struct_ops(ce);
	ret=(int)libbpf_get_error(p->ce);
	if (ret) {p->ce=NULL;goto done;}
	p->map_fd=bpf_map__fd(request); p->nvme_fd=bpf_link__fd(p->nvme); p->ce_fd=bpf_link__fd(p->ce);
	if (p->map_fd<0 || p->nvme_fd<0 || p->ce_fd<0 || p->nvme_fd==p->ce_fd) {ret=-EBADF;goto done;}
	if (bpf_obj_get_info_by_fd(p->map_fd,&info,&size)) {ret=-errno;goto done;}
	if (info.type!=BPF_MAP_TYPE_HASH || info.key_size!=16 || info.value_size!=24 ||
	    info.max_entries!=records || info.map_flags!=BPF_F_RDONLY_PROG) {ret=-EINVAL;goto done;}
	ret=evidence_write(evidence,"request-map-info.bin",&info,size);
	if (ret) goto done;
	/* Both actual BUILD programs must reference this exact kernel map ID. */
	unsigned builders=0;
	bpf_object__for_each_program(program,p->object) {
		const char *name=bpf_program__name(program);
		if (!strcmp(name,"request_nvme_build") || !strcmp(name,"request_ce_build")) {
			uint32_t ids[8]={0}, bytes=sizeof(struct bpf_prog_info);
			struct bpf_prog_info pi={.nr_map_ids=8,.map_ids=(uintptr_t)ids};
			bool found=false;
			if (bpf_obj_get_info_by_fd(bpf_program__fd(program),&pi,&bytes)) {ret=-errno;goto done;}
			if (pi.nr_map_ids>8) {ret=-E2BIG;goto done;}
			for (i=0;i<pi.nr_map_ids;i++) if (ids[i]==info.id) found=true;
			if (!found) {ret=-EPROTO;goto done;}
			char record[256];
			if (snprintf(record,sizeof(record),"%s-map-ids.bin",name)>=(int)sizeof(record)) {ret=-ENAMETOOLONG;goto done;}
			ret=evidence_write(evidence,record,ids,pi.nr_map_ids*sizeof(ids[0]));
			if (ret) goto done;
			builders++;
		}
	}
	if (builders!=2) ret=-EPROTO;
done:
	for (i=0;i<nr_logs;i++) free(logs[i].buffer);
	free(log);
	if (ret) rr_private_close(p);
	return ret;
}
int rr_private_fill_freeze(struct rr_private *p, uint64_t session,
		const struct rr_request *rows, size_t count, const char *evidence)
{
	size_t i;
	int ret;
	char path[4096];
	FILE *readback;
	if (!p || p->map_fd<0 || p->frozen || !session || !rows || !count) return -EINVAL;
	if (snprintf(path,sizeof(path),"%s/map-readback.bin",evidence)>=(int)sizeof(path)) return -ENAMETOOLONG;
	readback=fopen(path,"wx");
	if (!readback) return -errno;
	ret=0;
	for (i=0;i<count;i++) {
		struct nvme_ce_request_key key={session,rows[i].key};
		struct nvme_ce_request_value value={rows[i].nvme_offset,rows[i].gpu_offset,rows[i].bytes,0}, got={0};
		if (bpf_map_update_elem(p->map_fd,&key,&value,BPF_NOEXIST) ||
		    bpf_map_lookup_elem(p->map_fd,&key,&got)) {ret=-errno;break;}
		if (memcmp(&value,&got,sizeof(value))) {ret=-EPROTO;break;}
		if (fwrite(&key,1,sizeof(key),readback)!=sizeof(key) ||
		    fwrite(&got,1,sizeof(got),readback)!=sizeof(got)) {ret=-EIO;break;}
	}
	if (fclose(readback) && !ret) ret=-errno;
	if (ret) return ret;
	if (bpf_map_freeze(p->map_fd)) return -errno;
	p->frozen=true;
	/* A read-only-to-program declaration alone cannot freeze user updates. */
	struct nvme_ce_request_key key={session,rows[0].key};
	struct nvme_ce_request_value value={rows[0].nvme_offset,rows[0].gpu_offset,rows[0].bytes,1};
	errno=0; ret=bpf_map_update_elem(p->map_fd,&key,&value,BPF_EXIST);
	int frozen_errno=errno;
	if (!ret || frozen_errno!=EPERM) return -EPROTO;
	return evidence_write(evidence,"map-freeze-errno.bin",&frozen_errno,sizeof(frozen_errno));
}
