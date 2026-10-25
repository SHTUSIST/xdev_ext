// SPDX-License-Identifier: GPL-2.0
/*
 * libxdev_ext class programs: SPEC.md section 2.  The attach sequence is
 * that of `xdev_ext_mech_ctl attach`: only the requested struct_ops map
 * is created, globals are patched into the section images before load.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "../xdev_ext_mech_ctl_core.h"
#include "libxdev_ext.h"
#include "libxdev_ext_internal.h"

struct xdev_ext_prog {
	struct bpf_object *obj;
	struct bpf_link *link;
	char *pin_path;
};

/* The internal map holding section @sec (".bss" or ".data"). */
static struct bpf_map *section_map(struct bpf_object *obj, const char *sec)
{
	size_t n = strlen(sec);
	struct bpf_map *map;

	bpf_object__for_each_map(map, obj) {
		const char *name = bpf_map__name(map);
		size_t len = strlen(name);

		if (bpf_map__is_internal(map) && len >= n && !strcmp(name + len - n, sec))
			return map;
	}
	return NULL;
}

/* Before load: patch global @name in the initial image of its section. */
static int set_global(struct bpf_object *obj, const char *name, __u64 value)
{
	static const char *const sections[] = { ".bss", ".data" };
	struct btf *btf = bpf_object__btf(obj);
	unsigned int i;

	if (!btf)
		return -ENOENT;
	for (i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
		int id = btf__find_by_name_kind(btf, sections[i], BTF_KIND_DATASEC);
		const struct btf_var_secinfo *vsi;
		const struct btf_type *sec;
		__u16 v;

		if (id < 0)
			continue;
		sec = btf__type_by_id(btf, id);
		vsi = btf_var_secinfos(sec);
		for (v = 0; v < btf_vlen(sec); v++, vsi++) {
			const struct btf_type *var = btf__type_by_id(btf, vsi->type);
			struct bpf_map *map;
			const void *image;
			size_t size;
			void *copy;
			int ret;

			if (strcmp(btf__name_by_offset(btf, var->name_off), name))
				continue;
			map = section_map(obj, sections[i]);
			image = map ? bpf_map__initial_value(map, &size) : NULL;
			if (!image)
				return -ENOENT;
			copy = malloc(size);
			if (!copy)
				return -ENOMEM;
			memcpy(copy, image, size);
			ret = xdev_ext_mech_ctl_set_value(copy, size, vsi->offset,
							  vsi->size, value);
			if (!ret)
				ret = bpf_map__set_initial_value(map, copy, size);
			free(copy);
			return ret;
		}
	}
	return -ENOENT;
}

int xdev_ext_prog_attach(const struct xdev_ext_prog_opts *o, struct xdev_ext_prog **out)
{
	struct xdev_ext_prog *p;
	struct bpf_map *map;
	__u32 i;
	int ret;

	if (!o || !out)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags)
		return -EOPNOTSUPP;
	if (!o->obj_path || !o->map_name || o->nr_globals > XDEV_EXT_PROG_MAX_GLOBALS ||
	    (o->nr_globals && !o->globals))
		return -EINVAL;
	for (i = 0; i < o->nr_globals; i++)
		if (!o->globals[i].name || !o->globals[i].name[0])
			return -EINVAL;
	p = calloc(1, sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->obj = bpf_object__open_file(o->obj_path, NULL);
	ret = (int)libbpf_get_error(p->obj);
	if (ret) {
		p->obj = NULL;
		goto fail;
	}
	/* Another class's programs in the same object must not decide this one. */
	bpf_object__for_each_map(map, p->obj)
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS &&
		    strcmp(bpf_map__name(map), o->map_name))
			bpf_map__set_autocreate(map, false);
	for (i = 0; i < o->nr_globals; i++) {
		ret = set_global(p->obj, o->globals[i].name, o->globals[i].value);
		if (ret)
			goto fail;
	}
	map = bpf_object__find_map_by_name(p->obj, o->map_name);
	if (!map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS) {
		ret = -ENOENT;
		goto fail;
	}
	ret = bpf_object__load(p->obj);
	if (ret)
		goto fail;
	p->link = bpf_map__attach_struct_ops(map);
	ret = (int)libbpf_get_error(p->link);
	if (ret) {
		p->link = NULL;
		goto fail;
	}
	if (o->pin_path) {
		p->pin_path = strdup(o->pin_path);
		ret = p->pin_path ? bpf_link__pin(p->link, o->pin_path) : -ENOMEM;
		if (ret) {
			free(p->pin_path);
			p->pin_path = NULL;
			goto fail;
		}
	}
	*out = p;
	return 0;
fail:
	if (p->link)
		bpf_link__destroy(p->link);
	if (p->obj)
		bpf_object__close(p->obj);
	free(p);
	return ret < 0 ? ret : -EINVAL;
}

int xdev_ext_prog_detach(struct xdev_ext_prog *p)
{
	int ret = 0;

	if (!p)
		return -EINVAL;
	if (p->pin_path) {
		ret = bpf_link__unpin(p->link);
		free(p->pin_path);
	}
	/* Destroying the last link reference unregisters the struct_ops. */
	bpf_link__destroy(p->link);
	bpf_object__close(p->obj);
	free(p);
	return ret;
}
