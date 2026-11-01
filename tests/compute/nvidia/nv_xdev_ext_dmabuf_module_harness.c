/* SPDX-License-Identifier: MIT */
#define TEST_DIRECT 0
#define TEST_PHYS 0
#define main descriptor_behavior_main
#include "nv_xdev_ext_dmabuf_harness.c"
#undef main
#define __init
#define __exit
#define NV_DBG_ERRORS 0
#define NV_DBG_WARNINGS 0
#define NV_MAJOR_DEVICE_NUMBER 195
#define NV_MINOR_DEVICE_NUMBER_REGULAR_MAX 254
#define NV_MINOR_DEVICE_NUMBER_CONTROL_DEVICE 255
#define NV_SUPPORTS_PLATFORM_DISPLAY_DEVICE 1
#define MKDEV(major, minor) (((major) << 16) | (minor))
#define NV_FALSE false
#define NV_TRUE true
static const char *pNVRM_ID = "host-fixture";
typedef struct { unsigned tag; } nvidia_stack_t;
static nvidia_stack_t stack, *__nv_init_sp;
static unsigned num_probed_nv_devices = 1, num_nv_devices = 1;
static int nv_linux_devices_cdev, nv_linux_control_device_cdev, nvidia_fops;
static unsigned chars, dead_chars, uvm_calls, uvm_exits, peer_inits, peer_exits;
static unsigned backend_inits, backend_exits;
static int char_failure;
static bool descriptor_at_publish;
static void nv_memdbg_init(void) {}
static void nv_memdbg_exit(void) {}
static int nv_procfs_init(void) { return 0; }
static void nv_procfs_exit(void) {}
static int nv_caps_root_init(void) { return 0; }
static void nv_caps_root_exit(void) {}
static int nv_caps_imex_init(void) { return 0; }
static void nv_caps_imex_exit(void) {}
static bool os_is_nvswitch_present(void) { return false; }
static int nv_module_init(nvidia_stack_t **out) { *out = &stack; return 0; }
static void nv_module_exit(nvidia_stack_t *sp) {}
static unsigned nvos_count_devices(int *pci, int *platform) { *pci = 1; *platform = 0; return 1; }
static int nv_drivers_init(void) { return 0; }
static void nv_drivers_exit(void) {}
#define nv_printf(...) ((void)0)
static void nv_registry_keys_init(nvidia_stack_t *sp) {}
static void nv_report_applied_patches(void) {}
static int nv_uvm_init(void) { uvm_calls++; return 0; }
static void nv_uvm_exit(void) { uvm_exits++; }
static int nv_register_chrdev(unsigned minor, unsigned count, int *cdev,
                             const char *name, int *fops)
{
 (void)minor; (void)count; (void)cdev; (void)name; (void)fops;
 chars++;
 if (chars == 1) descriptor_at_publish = descriptor != NULL;
 return (int)chars == char_failure ? -ENOSPC : 0;
}
static void nv_unregister_chrdev(unsigned minor, unsigned count, int *cdev) { dead_chars++; }
static void nv_xdev_ext_peer_init(int *fops) { peer_inits++; }
static void nv_xdev_ext_peer_exit(void) { peer_exits++; }
static void nv_xdev_ext_ce_backend_init(int *fops) { backend_inits++; }
static void nv_xdev_ext_ce_backend_exit(void) { backend_exits++; }
#include "actual_module.inc"
int main(void)
{
 checks = 0;
#ifndef TEST_IMPORTER_DISABLED
 registration_error = -ENOMEM;
 CHECK(nvidia_init_module() == -ENOMEM);
 CHECK(chars == 0 && !descriptor && !peer_inits && !backend_inits);
 registration_error = 0;
#endif
 for (int fail = 1; fail <= 2; fail++) {
  chars = dead_chars = 0; char_failure = fail;
  CHECK(nvidia_init_module() == -ENOSPC);
  CHECK(chars == (unsigned)fail);
  CHECK(dead_chars == (unsigned)(fail - 1));
  CHECK(!descriptor && !peer_inits && !backend_inits);
#ifndef TEST_IMPORTER_DISABLED
  CHECK(descriptor_at_publish);
#else
  CHECK(!descriptor_at_publish);
#endif
 }
 chars = dead_chars = 0; char_failure = 0;
 CHECK(nvidia_init_module() == 0);
#ifndef TEST_IMPORTER_DISABLED
 CHECK(descriptor && descriptor_at_publish);
#else
 CHECK(!descriptor && !descriptor_at_publish);
#endif
 CHECK(chars == 2 && peer_inits == 1 && backend_inits == 1);
 nvidia_exit_module();
 CHECK(!descriptor && dead_chars == 2);
 CHECK(peer_exits == 1 && backend_exits == 1);
 CHECK(uvm_calls == uvm_exits);
 printf("PASS %u module publication/unwind/unload assertions\n", checks);
 return 0;
}
