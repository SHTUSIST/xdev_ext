#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

source_file="$(dirname "$0")/../../../../io_uring/unified_ops.c"
preload_file="$(dirname "$0")/../../../io_uring_unified_preload.c"

grep -q 'vfs_iocb_iter_read(op->file, &ar->kiocb, &ar->iter)' "$source_file"
grep -q 'vfs_iocb_iter_read(op->file, &kiocb, &iter)' "$source_file"
grep -q 'vfs_iocb_iter_write(op->file, &kiocb, &iter)' "$source_file"
grep -q 'fsnotify_access(ar->kiocb.ki_filp)' "$source_file"
grep -q 'request_fd = xdev_ext_duplicate_validated_fd(fd, &meta)' "$preload_file"
grep -q 'xdev_ext_preload_fd_identity_matches(&expected, &observed' "$preload_file"
grep -q 'xdev_ext_path_is_allowed(duplicate, &st)' "$preload_file"
grep -q '__atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE)' "$preload_file"
grep -q 'xdev_ext_preload_snapshot_report(' "$preload_file"
grep -q 'ssize_t preadv2(' "$preload_file"
grep -q 'ssize_t pwritev64v2(' "$preload_file"
grep -q 'int fcntl64(' "$preload_file"
grep -q 'xdev_ext_recursive_iov_v2(' "$preload_file"
if grep -Eq 'return xdev_ext_real\.(preadv2|preadv64v2|pwritev2|pwritev64v2)_fn' "$preload_file"; then
	echo "recursive v2 wrapper can call a missing libc symbol" >&2
	exit 1
fi
grep -q 'xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd)' "$preload_file"
grep -q 'xdev_ext_preload_fd_lock_all(&xdev_ext_fd_locks)' "$preload_file"
if grep -q 'static pthread_mutex_t xdev_ext_fd_lock' "$preload_file"; then
	echo "global fd registry lock remains on the positional-I/O hot path" >&2
	exit 1
fi

echo "PASS: unified UMEM file I/O retains VFS checks, stable fd, vector ABI, and DMA backing"
