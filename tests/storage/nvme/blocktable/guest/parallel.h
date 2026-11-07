/* SPDX-License-Identifier: GPL-2.0 */
/* Included only by the opt-in driver; uses original actual-kernel helpers. */
#include <dirent.h>

static unsigned parallel_fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd"); SETUP(dir);
    unsigned nr = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) nr++;
    SETUP(!errno); SETUP(!closedir(dir));
    return nr;
}

/* Exclusive fixed capture names in original load() must belong to each object. */
static struct program parallel_load(const char *name)
{
    const char *root = opt.output;
    char directory[4096];
    SETUP(snprintf(directory, sizeof(directory), "%s/%s", root, name) < (int)sizeof(directory));
    SETUP(!mkdir(directory, 0700));
    opt.output = directory;
    struct program p = load();
    opt.output = root;
    return p;
}

static void parallel_distinct(struct program *a, struct program *b)
{
    struct bpf_map_info am = {}, bm = {};
    struct bpf_link_info al = {}, bl = {};
    uint32_t size = sizeof(am);
    ASSERT(!bpf_obj_get_info_by_fd(a->blocks, &am, &size));
    size = sizeof(bm); ASSERT(!bpf_obj_get_info_by_fd(b->blocks, &bm, &size));
    ASSERT(am.id && bm.id && am.id != bm.id);
    struct bpf_map *ao = bpf_object__find_map_by_name(a->object, "blocktable_ops");
    struct bpf_map *bo = bpf_object__find_map_by_name(b->object, "blocktable_ops");
    ASSERT(ao && bo);
    size = sizeof(am); ASSERT(!bpf_obj_get_info_by_fd(bpf_map__fd(ao), &am, &size));
    size = sizeof(bm); ASSERT(!bpf_obj_get_info_by_fd(bpf_map__fd(bo), &bm, &size));
    ASSERT(am.id && bm.id && am.id != bm.id);
    size = sizeof(al); ASSERT(!bpf_obj_get_info_by_fd(bpf_link__fd(a->link), &al, &size));
    size = sizeof(bl); ASSERT(!bpf_obj_get_info_by_fd(bpf_link__fd(b->link), &bl, &size));
    ASSERT(al.id && bl.id && al.id != bl.id);
    const char *names[] = {"blocktable_build", "blocktable_complete"};
    for (unsigned i = 0; i < 2; i++) {
        struct bpf_program *ap = bpf_object__find_program_by_name(a->object, names[i]);
        struct bpf_program *bp = bpf_object__find_program_by_name(b->object, names[i]);
        struct bpf_prog_info ai = {}, bi = {};
        ASSERT(ap && bp);
        size = sizeof(ai); ASSERT(!bpf_obj_get_info_by_fd(bpf_program__fd(ap), &ai, &size));
        size = sizeof(bi); ASSERT(!bpf_obj_get_info_by_fd(bpf_program__fd(bp), &bi, &size));
        ASSERT(ai.id && bi.id && ai.id != bi.id);
        fprintf(events, "parallel distinct_program name=%s A=%u B=%u\n", names[i], ai.id, bi.id);
    }
}

static void parallel_runtime(void)
{
    unsigned fd_before = parallel_fd_count();
    struct stat namespace_before, namespace_after;
    SETUP(!stat(opt.device, &namespace_before) && S_ISCHR(namespace_before.st_mode));
    struct program a = parallel_load("program-A"), b = parallel_load("program-B");
    parallel_distinct(&a, &b);
    struct session sa = create(&a, "parallel-A"), sb = create(&b, "parallel-B");
    ASSERT(sa.id != sb.id && sa.ring != sb.ring && sa.memory != sb.memory);
    ASSERT(sa.device_rdev == sb.device_rdev &&
           sa.device_rdev == (uint64_t)namespace_before.st_rdev);
    SETUP(!stat(opt.device, &namespace_after));
    ASSERT(namespace_before.st_rdev == namespace_after.st_rdev &&
           namespace_before.st_ino == namespace_after.st_ino &&
           namespace_before.st_dev == namespace_after.st_dev);
    /* Both sessions exist before native work. Same logical key, independent
     * real maps; decoys turn an incorrect instance lookup into wrong bytes. */
    put(&a, &sa, sa.id, 100, 2 * BT_GROUP, BT_GROUP);
    put(&a, &sa, sa.id, 101, 4 * BT_GROUP, BT_GROUP);
    put(&b, &sb, sb.id, 100, 5 * BT_GROUP, BT_GROUP);
    put(&b, &sb, sb.id, 101, 7 * BT_GROUP, BT_GROUP);
    put(&a, &sa, sb.id, 100, 3 * BT_GROUP, BT_GROUP);
    put(&b, &sb, sa.id, 100, 6 * BT_GROUP, BT_GROUP);
    memset(sa.memory, BT_POISON, BT_REGISTERED);
    memset(sb.memory, BT_POISON, BT_REGISTERED);
    batch(&sa, 100, expected + 2 * BT_GROUP, false);
    ASSERT(bt_verify(sb.memory, NULL, 0) == SIZE_MAX);
    batch(&sb, 100, expected + 5 * BT_GROUP, false);
    ASSERT(bt_verify(sa.memory, expected + 2 * BT_GROUP, 0) == SIZE_MAX);

    struct xdev_ext_mech_stats before, after;
    ASSERT(!stats(&sa, &before));
    save("parallel-A-before-detach-stats.bin", &before, sizeof(before));
    ASSERT(!bpf_link__detach(a.link));
    ASSERT(start(&sa, 101) == -ESHUTDOWN);
    ASSERT(!stats(&sa, &after));
    save("parallel-A-after-detach-stats.bin", &after, sizeof(after));
    withdraw_stats(&before, &after);
    ASSERT(bt_verify(sa.memory, expected + 2 * BT_GROUP, 0) == SIZE_MAX);
    ASSERT(bt_verify(sb.memory, expected + 5 * BT_GROUP, 0) == SIZE_MAX);
    batch(&sb, 101, expected + 7 * BT_GROUP, false);
    ASSERT(bt_verify(sa.memory, expected + 2 * BT_GROUP, 0) == SIZE_MAX);
    stop(&sa, -ECANCELED);
    stop(&sb, 0);
    ASSERT(!bpf_link__destroy(a.link)); ASSERT(!bpf_link__destroy(b.link));
    bpf_object__close(a.object); bpf_object__close(b.object);
    unsigned fd_after = parallel_fd_count();
    fprintf(events, "parallel fd_before=%u fd_after=%u\n", fd_before, fd_after);
    ASSERT(fd_before == fd_after);
    cases++;
    verdict(0, "same-namespace-two-private-program-instances");
}
