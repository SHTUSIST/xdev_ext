// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "../common/fd_check.h"
int main(void)
{
 int before = eval_fd_count();
 int fd;
 assert(before >= 0);
 fd = open("/dev/null", O_RDONLY);
 assert(fd >= 0);
 assert(eval_fd_check(before) != 0);
 assert(close(fd) == 0);
 assert(eval_fd_check(before) == 0);
 return 0;
}
