// SPDX-License-Identifier: GPL-2.0
/* Dedicated acceptance loader for xdev_ext_binding_helpers.bpf.o.
 * No attachment: the contract under test is verifier acceptance/rejection.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define LOG_SIZE (8U * 1024U * 1024U)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define DENY(helper) "program of this type cannot use helper " helper
struct test_case { const char *name, *phase, *message; };
static const struct test_case cases[] = {
	{"lookup_dispatch", "dispatch", NULL},
	{"lookup_complete", "complete", NULL},
	{"loop_dispatch", "dispatch", NULL},
	{"loop_complete", "complete", NULL},
	{"read_dispatch", "dispatch", DENY("bpf_probe_read_kernel#113")},
	{"read_complete", "complete", DENY("bpf_probe_read_kernel#113")},
	{"task_dispatch", "dispatch", DENY("bpf_get_current_task#35")},
	{"task_complete", "complete", DENY("bpf_get_current_task#35")},
	{"trace_dispatch", "dispatch", DENY("bpf_trace_printk#6")},
	{"trace_complete", "complete", DENY("bpf_trace_printk#6")},
	{"time_dispatch", "dispatch", DENY("bpf_ktime_get_ns#5")},
	{"time_complete", "complete", DENY("bpf_ktime_get_ns#5")},
};
static FILE *libbpf_log;

static int print_libbpf(enum libbpf_print_level level, const char *format,
			va_list args)
{
	(void)level;
	return vfprintf(libbpf_log ? libbpf_log : stderr, format, args);
}

/* Metadata must match the unmodified fixture, including its complete __msg. */
static int check_tags(struct bpf_object *obj, const struct test_case *test)
{
	struct btf *btf = bpf_object__btf(obj);
	unsigned int i, success = 0, failure = 0, messages = 0;
	int func_id;

	if (!btf)
		return -EINVAL;
	func_id = btf__find_by_name_kind(btf, test->name, BTF_KIND_FUNC);
	if (func_id < 0)
		return func_id;
	for (i = 1; i < btf__type_cnt(btf); i++) {
		const struct btf_type *type = btf__type_by_id(btf, i);
		const char *tag, *value;
		char *end;

		if (!btf_is_decl_tag(type) || type->type != (unsigned int)func_id ||
		    btf_decl_tag(type)->component_idx != -1)
			continue;
		tag = btf__str_by_offset(btf, type->name_off);
		if (!strcmp(tag, "comment:test_expect_success"))
			success++;
		else if (!strcmp(tag, "comment:test_expect_failure"))
			failure++;
		else if (!strncmp(tag, "comment:test_expect_msg=", 24)) {
			/* Native bpf_misc.h encodes __COUNTER__ before the message. */
			value = tag + 24;
			errno = 0;
			(void)strtoul(value, &end, 10);
			if (errno || end == value || *end != '=' || !test->message ||
			    strcmp(end + 1, test->message))
				return -EINVAL;
			messages++;
		}
	}
	return success == !test->message && failure == !!test->message &&
	       messages == !!test->message ? 0 : -EINVAL;
}

/* libbpf replaces each struct_ops function relocation with its bpf_program *
 * in this public initial-value shadow. Derive every offset from actual BTF;
 * do not assume the host C struct or fixture ELF section layout.
 */
static int check_policy(struct bpf_object *obj, struct bpf_map *map,
			struct bpf_program *prog, const struct test_case *test)
{
	static const char *const names[] = {
		"abi_version", "backend", "flags", "reserved", "dispatch", "complete",
	};
	static const __u32 values[] = {2, 1, 0, 0};
	struct btf *btf = bpf_object__btf(obj);
	const struct btf_type *type, *member_type, *pointee;
	const struct btf_member *members;
	const unsigned char *data;
	unsigned char *covered;
	unsigned int i, j, seen = 0;
	size_t size, offset, width;
	int member_id, pointee_id, err = -EINVAL;

	type = btf__type_by_id(btf, bpf_map__btf_value_type_id(map));
	data = bpf_map__initial_value(map, &size);
	if (!type || !btf_is_struct(type) || btf_vlen(type) != ARRAY_SIZE(names) ||
	    strcmp(btf__name_by_offset(btf, type->name_off), "xdev_ext_binding_ops") ||
	    !data || !size || type->size != size ||
	    btf__pointer_size(btf) != sizeof(struct bpf_program *))
		return -EINVAL;
	covered = calloc(size, 1);
	if (!covered)
		return -ENOMEM;
	members = btf_members(type);
	for (i = 0; i < btf_vlen(type); i++) {
		const char *name = btf__name_by_offset(btf, members[i].name_off);

		for (j = 0; j < ARRAY_SIZE(names); j++)
			if (!strcmp(name, names[j]))
				break;
		if (j == ARRAY_SIZE(names) || (seen & (1U << j)) ||
		    btf_member_bitfield_size(type, i) || btf_member_bit_offset(type, i) % 8)
			goto out;
		seen |= 1U << j;
		offset = btf_member_bit_offset(type, i) / 8;
		member_id = btf__resolve_type(btf, members[i].type);
		member_type = member_id > 0 ? btf__type_by_id(btf, member_id) : NULL;
		width = j < ARRAY_SIZE(values) ? sizeof(__u32) : sizeof(struct bpf_program *);
		if (!member_type || offset > size || width > size - offset)
			goto out;
		if (j < ARRAY_SIZE(values)) {
			__u32 value;

			if (!btf_is_int(member_type) || member_type->size != width ||
			    btf_int_encoding(member_type) || btf_int_offset(member_type) ||
			    btf_int_bits(member_type) != 32)
				goto out;
			memcpy(&value, data + offset, sizeof(value));
			if (value != values[j])
				goto out;
		} else {
			struct bpf_program *actual;
			struct bpf_program *expected = !strcmp(name, test->phase) ? prog : NULL;

			if (!btf_is_ptr(member_type))
				goto out;
			pointee_id = btf__resolve_type(btf, member_type->type);
			pointee = pointee_id > 0 ? btf__type_by_id(btf, pointee_id) : NULL;
			if (!pointee || !btf_is_func_proto(pointee))
				goto out;
			memcpy(&actual, data + offset, sizeof(actual));
			if (actual != expected)
				goto out;
		}
		while (width--) {
			if (covered[offset])
				goto out;
			covered[offset++] = 1;
		}
	}
	if (seen != (1U << ARRAY_SIZE(names)) - 1)
		goto out;
	/* Unnamed padding is allowed only when it contains no policy data. */
	for (offset = 0; offset < size; offset++)
		if (!covered[offset] && data[offset])
			goto out;
	err = 0;
out:
	free(covered);
	return err;
}

static int validate_manifest(struct bpf_object *obj)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	size_t i, programs = 0, policies = 0;

	bpf_object__for_each_program(prog, obj)
		programs++;
	bpf_object__for_each_map(map, obj)
		if (bpf_map__type(map) == BPF_MAP_TYPE_STRUCT_OPS)
			policies++;
	if (programs != ARRAY_SIZE(cases) || policies != ARRAY_SIZE(cases)) {
		fprintf(stderr, "manifest counts programs=%zu struct_ops=%zu expected=12/12\n",
			programs, policies);
		return -EINVAL;
	}
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		char policy[128], section[128];

		snprintf(policy, sizeof(policy), "%s_policy", cases[i].name);
		snprintf(section, sizeof(section), "struct_ops/%s", cases[i].phase);
		prog = bpf_object__find_program_by_name(obj, cases[i].name);
		map = bpf_object__find_map_by_name(obj, policy);
		if (!prog || !map || bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS ||
		    bpf_program__type(prog) != BPF_PROG_TYPE_STRUCT_OPS ||
		    strcmp(bpf_program__section_name(prog), section) ||
		    check_tags(obj, &cases[i])) {
			fprintf(stderr, "manifest/tag mismatch: %s\n", cases[i].name);
			return -EINVAL;
		}
		if (check_policy(obj, map, prog, &cases[i])) {
			fprintf(stderr, "policy content/relocation mismatch: %s\n", policy);
			return -EINVAL;
		}
	}
	return 0;
}

static FILE *open_log(const char *directory, const char *name, const char *suffix)
{
	char path[PATH_MAX];
	int length = snprintf(path, sizeof(path), "%s/%s.%s", directory, name, suffix);
	FILE *file;

	if (length < 0 || (size_t)length >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	file = fopen(path, "wx");
	if (!file)
		perror(path);
	return file;
}

static int save_log(const char *directory, const char *name, const char *suffix,
		    const char *content)
{
	FILE *file = open_log(directory, name, suffix);
	int err;

	if (!file)
		return -1;
	err = fputs(content, file) == EOF;
	if (fclose(file))
		err = 1;
	return err ? -1 : 0;
}

static int run_case(const char *object, const char *directory,
		    const struct test_case *test, FILE *summary)
{
	char *program_log = calloc(1, LOG_SIZE), *btf_log = calloc(1, LOG_SIZE);
	struct bpf_object *obj = NULL;
	struct bpf_program *prog, *selected = NULL;
	struct bpf_map *map;
	char policy[128];
	const char *reason = "setup_failure";
	int err = -EINVAL, fd = -1, result = 1;
	bool matched = false;
	LIBBPF_OPTS(bpf_object_open_opts, opts);

	libbpf_log = open_log(directory, test->name, "libbpf.log");
	if (!libbpf_log || !program_log || !btf_log)
		goto out;
	opts.kernel_log_buf = btf_log;
	opts.kernel_log_size = LOG_SIZE;
	opts.kernel_log_level = 1;
	obj = bpf_object__open_file(object, &opts);
	if (libbpf_get_error(obj)) {
		err = (int)libbpf_get_error(obj);
		obj = NULL;
		goto out;
	}
	if (validate_manifest(obj))
		goto out;
	snprintf(policy, sizeof(policy), "%s_policy", test->name);
	bpf_object__for_each_program(prog, obj) {
		bool enable = !strcmp(bpf_program__name(prog), test->name);

		err = bpf_program__set_autoload(prog, enable);
		if (err)
			goto out;
		if (enable)
			selected = prog;
	}
	/* Every inactive policy refers to an inactive program. Do not create it. */
	bpf_object__for_each_map(map, obj) {
		bool enable = bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS ||
			      !strcmp(bpf_map__name(map), policy);

		err = bpf_map__set_autocreate(map, enable);
		if (err)
			goto out;
		fprintf(libbpf_log, "selection map=%s autocreate=%d\n",
			bpf_map__name(map), enable);
	}
	if (!selected)
		goto out;
	err = bpf_program__set_log_buf(selected, program_log, LOG_SIZE);
	if (!err)
		err = bpf_program__set_log_level(selected, 1);
	if (err)
		goto out;
	err = bpf_object__load(obj);
	fd = bpf_program__fd(selected);
	matched = test->message && strstr(program_log, test->message);
	if (err == -ENOSPC || strnlen(program_log, LOG_SIZE) >= LOG_SIZE - 1) {
		reason = "verifier_log_truncated";
	} else if (test->message) {
		if (err < 0 && fd < 0 && matched) {
			result = 0;
			reason = "exact_expected_helper_denial";
		} else {
			reason = !err ? "unexpected_load_success" : "missing_expected_helper_denial";
		}
	} else if (!err && fd >= 0) {
		struct bpf_prog_info info = {};
		__u32 length = sizeof(info);
		unsigned int loaded = 0;

		bpf_object__for_each_program(prog, obj)
			loaded += bpf_program__fd(prog) >= 0;
		if (!bpf_prog_get_info_by_fd(fd, &info, &length) &&
		    info.type == BPF_PROG_TYPE_STRUCT_OPS && info.id && loaded == 1) {
			result = 0;
			reason = "loaded_struct_ops_program";
		} else {
			reason = "loaded_program_info_failed";
		}
	} else {
		reason = "unexpected_load_failure";
	}
out:
	if (program_log && save_log(directory, test->name, "verifier.log", program_log))
		result = 1;
	if (btf_log && save_log(directory, test->name, "btf.log", btf_log))
		result = 1;
	if (libbpf_log && fclose(libbpf_log))
		result = 1;
	libbpf_log = NULL;
	fprintf(summary, "%s\t%s\t%s\t%d\t%d\t%d\t%s\n", test->name,
		result ? "FAIL" : "PASS", test->message ? "reject" : "accept",
		err, fd, matched, reason);
	printf("%s %s load_err=%d fd=%d %s\n", result ? "FAIL" : "PASS",
	       test->name, err, fd, reason);
	bpf_object__close(obj);
	free(program_log);
	free(btf_log);
	return result;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct utsname uts;
	FILE *summary, *environment;
	bool inspect = argc == 3 && !strcmp(argv[1], "--inspect");
	const char *object = inspect ? argv[2] : argc == 3 ? argv[1] : NULL;
	unsigned int failures = 0;
	size_t i;
	int err;

	if (!object) {
		fprintf(stderr, "usage: %s OBJECT FRESH_LOG_DIR | --inspect OBJECT\n", argv[0]);
		return 2;
	}
	libbpf_set_print(print_libbpf);
	obj = bpf_object__open_file(object, NULL);
	err = (int)libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "object open failed: %d\n", err);
		return 2;
	}
	err = validate_manifest(obj);
	bpf_object__close(obj);
	if (err)
		return 2;
	if (inspect) {
		puts("INSPECT-ONLY cases=12: ELF/BTF manifest valid; no kernel load performed");
		return 0;
	}
	if (mkdir(argv[2], 0700)) {
		perror("fresh log directory required");
		return 2;
	}
	summary = open_log(argv[2], "summary", "tsv");
	environment = open_log(argv[2], "environment", "txt");
	if (!summary || !environment) {
		if (summary)
			fclose(summary);
		if (environment)
			fclose(environment);
		return 2;
	}
	if (!uname(&uts))
		fprintf(environment, "sysname=%s\nrelease=%s\nversion=%s\nmachine=%s\n",
			uts.sysname, uts.release, uts.version, uts.machine);
	fprintf(environment, "object=%s\nlibbpf=%s\nmode=privileged verifier load only; no attachment\n",
		object, libbpf_version_string());
	if (fclose(environment)) {
		fclose(summary);
		return 2;
	}
	fputs("case\tstatus\texpected\tload_err\tprogram_fd\tmessage_match\treason\n", summary);
	for (i = 0; i < ARRAY_SIZE(cases); i++)
		failures += run_case(object, argv[2], &cases[i], summary);
	if (fclose(summary))
		return 2;
	printf("NATIVE-VERIFIER cases=12 pass=%u fail=%u\n", 12 - failures, failures);
	return failures ? 1 : 0;
}
