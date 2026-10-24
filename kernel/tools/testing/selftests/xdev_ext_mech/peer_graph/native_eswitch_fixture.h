/* SPDX-License-Identifier: GPL-2.0-only */
/* Host boundaries for actual eswitch close callers, not a hardware emulator. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
typedef uint16_t u16;
#define READ_ONCE(x) (x)
#define MLX5_ESWITCH_LEGACY 0
#define MLX5_ESWITCH_OFFLOADS 1
#define DEVLINK_ESWITCH_MODE_LEGACY 0
#define DEVLINK_ESWITCH_MODE_SWITCHDEV 1
#define MLX5_PRIV_FLAGS_SWITCH_LEGACY 1
#define MLX5_ESW_FDB_CREATED 1
#define MLX5_VPORT_UPLINK 1
#define IS_ERR(x) false
#define PTR_ERR(x) (-EINVAL)
#define NL_SET_ERR_MSG_MOD(...) ((void)0)
#define esw_info(...) ((void)0)
struct netlink_ext_ack {int unused;};
struct mlx5_core_dev {struct {unsigned flags;}priv;};
struct mlx5_eswitch_rep {int vport;};
struct mlx5_eswitch {bool peer_quarantined;struct mlx5_core_dev *dev;int mode,mode_lock;
 bool eswitch_operation_in_progress;
 struct {unsigned flags;}fdb_table;
 struct {int num_block_mode,reg_c0_obj_pool,termtbl_mutex,vport_reps;}offloads;
};
struct devlink {struct mlx5_eswitch *esw;};
static int lag_disables,lag_enables,mode_locks,notifies,event_unregs,vport_disables,rep_unloads;
static int metadata_changes,steering_cleanups,mapping_frees,metadata_frees,roce_disables,mutex_destroys;
static int acl_frees,rate_frees,legacy_starts,offload_starts,rep_frees,rep_erases;
static bool fresh_unknown;
static struct mlx5_eswitch *mlx5_devlink_eswitch_get(struct devlink *d){return d->esw;}
static struct devlink *priv_to_devlink(struct mlx5_core_dev *m){static struct devlink d;(void)m;return &d;}
static int esw_mode_from_devlink(u16 m,u16 *v){*v=m;return 0;}
static void *mlx5_get_sd(struct mlx5_core_dev *d){(void)d;return NULL;}
static void mlx5_lag_disable_change(struct mlx5_core_dev *d){(void)d;lag_disables++;}
static void mlx5_lag_enable_change(struct mlx5_core_dev *d){(void)d;lag_enables++;}
static int mlx5_esw_try_lock(struct mlx5_eswitch *e){mode_locks++;return e->mode;}
static void mlx5_esw_unlock(struct mlx5_eswitch *e){(void)e;mode_locks--;}
static void up_write(int *p){(void)p;}
static void down_write(int *p){(void)p;}
static void mlx5_esw_mode_change_notify(struct mlx5_eswitch *e,int m){(void)e;(void)m;notifies++;}
static void mlx5_eq_notifier_unregister(struct mlx5_core_dev *d,void *p){(void)d;(void)p;event_unregs++;}
/* nb is only an address passed to this kernel boundary. */
#define nb mode_lock
static void mlx5_eswitch_event_handler_unregister(struct mlx5_eswitch *e){(void)e;event_unregs++;}
static void mlx5_eswitch_disable_pf_vf_vports(struct mlx5_eswitch *e){(void)e;vport_disables++;}
static void mlx5_esw_offloads_rep_unload(struct mlx5_eswitch *e,int v){assert(v==MLX5_VPORT_UPLINK);rep_unloads++;if(fresh_unknown)e->peer_quarantined=true;}
static void esw_set_passing_vport_metadata(struct mlx5_eswitch *e,bool on){(void)e;(void)on;metadata_changes++;}
static void esw_offloads_steering_cleanup(struct mlx5_eswitch *e){(void)e;steering_cleanups++;}
static void mapping_destroy(int p){(void)p;mapping_frees++;}
static void esw_offloads_metadata_uninit(struct mlx5_eswitch *e){(void)e;metadata_frees++;}
static void mlx5_rdma_disable_roce(struct mlx5_core_dev *d){(void)d;roce_disables++;}
static void mutex_destroy(int *p){(void)p;mutex_destroys++;}
static void esw_legacy_disable(struct mlx5_eswitch *e){(void)e;}
static void mlx5_esw_acls_ns_cleanup(struct mlx5_eswitch *e){(void)e;acl_frees++;}
static void devl_rate_nodes_destroy(struct devlink *d){(void)d;rate_frees++;}
static int mlx5_devlink_trap_get_num_active(struct mlx5_core_dev *d){(void)d;return 0;}
static int esw_offloads_start(struct mlx5_eswitch *e,struct netlink_ext_ack *a){(void)e;(void)a;offload_starts++;return 0;}
static int esw_offloads_stop(struct mlx5_eswitch *e,struct netlink_ext_ack *a){(void)a;legacy_starts++;e->mode=MLX5_ESWITCH_LEGACY;return 0;}
static void xa_erase(int *p,int v){(void)p;(void)v;rep_erases++;}
static void kfree(void *p){(void)p;rep_frees++;}
