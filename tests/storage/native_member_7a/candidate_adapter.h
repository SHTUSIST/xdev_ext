/* Root mechanical adapter: actual embedded objects and registered ops only. */
#define TEST_COMMON_STAGE(st) (&((struct nvme_xdev_ext_mech_stage *)(st)->priv)->family)
#define TEST_COMMON_BATCH(b) (&((struct nvme_xdev_ext_mech_batch *)(b)->priv)->family)
#define TEST_POLL_VIEWS(ss) ((ss)->poll_views)
#define TEST_NATIVE_DEV_OPS nvme_xdev_ext_member_ops
#define TEST_NATIVE_CLASS_OPS nvme_xdev_ext_mech_class
