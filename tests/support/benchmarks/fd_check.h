/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_FD_CHECK_H
#define XDEV_EVAL_FD_CHECK_H
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Outside measurement: detect descriptor leaks before process exit hides them. */
static inline int eval_fd_count(void)
{
 DIR *dir = opendir("/proc/self/fd");
 struct dirent *entry;
 int count = -1; /* exclude the directory's own descriptor */
 if (!dir)
  return -1;
 errno = 0;
 while ((entry = readdir(dir)))
  if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
   count++;
 if (errno)
  count = -1;
 if (closedir(dir))
  count = -1;
 return count;
}
static inline int eval_fd_check(int before)
{
 int after = eval_fd_count();
 int bad = before < 0 || after != before;
 fprintf(stderr, "EVAL_FD_CHECK=%s before=%d after=%d\n", bad ? "FAIL" : "PASS", before, after);
 return bad;
}
#endif
