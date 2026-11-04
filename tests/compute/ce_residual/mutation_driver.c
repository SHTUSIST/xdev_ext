/* SPDX-License-Identifier: GPL-2.0 */
/* Run one unchanged frozen scenario per mutant. Later scenarios assume their
 * prerequisites succeeded; their crashes must not mask the decisive assertion. */
#define main frozen_main
#include "harness.c"
#undef main

int main(int argc, char **argv)
{
 setvbuf(stdout, NULL, _IONBF, 0);
 if (argc != 2)
  return 2;
 if (!strcmp(argv[1], "residual"))
  residual();
 else if (!strcmp(argv[1], "host"))
  cleanup(false, false);
 else if (!strcmp(argv[1], "region"))
  cleanup(true, false);
 else if (!strcmp(argv[1], "later-stage"))
  cleanup(false, true);
 else if (!strcmp(argv[1], "identity"))
  identity(1);
 else if (!strcmp(argv[1], "multistage"))
  multistage();
 else if (!strcmp(argv[1], "positive"))
  positive(false, false);
 else if (!strcmp(argv[1], "atomic"))
  atomic_cleanup();
 else
  return 2;
 printf("checks=%d failures=%d\n", checks, failures);
 return failures ? 1 : 0;
}
