/* SPDX-License-Identifier: GPL-2.0-only */
int main(int argc,char **argv)
{
 struct mlx5_core_dev m={};struct mlx5_eswitch e={.dev=&m,.mode=MLX5_ESWITCH_OFFLOADS,.fdb_table.flags=MLX5_ESW_FDB_CREATED};
 struct devlink d={.esw=&e};struct netlink_ext_ack a={};struct mlx5_eswitch_rep rep={.vport=1};
 assert(argc==2);int mode=atoi(argv[1]);e.peer_quarantined=mode==1;fresh_unknown=mode==2;
 int ret=mlx5_devlink_eswitch_mode_set(&d,DEVLINK_ESWITCH_MODE_LEGACY,&a);
 if(mode==0){
  assert(!ret&&!e.peer_quarantined&&rep_unloads==1&&legacy_starts==1);
  assert(steering_cleanups==1&&mapping_frees==1&&metadata_frees==1&&roce_disables==1&&mutex_destroys==1);
  assert(acl_frees==1&&rate_frees==1&&lag_disables==1&&lag_enables==1&&!mode_locks);
  mlx5_esw_offloads_rep_cleanup(&e,&rep);assert(rep_frees==1&&rep_erases==1);return 0;
 }
 assert(ret==-EIO&&e.peer_quarantined&&!e.eswitch_operation_in_progress&&!mode_locks);
 assert(!steering_cleanups&&!mapping_frees&&!metadata_frees&&!roce_disables&&!mutex_destroys);
 assert(!acl_frees&&!rate_frees&&!legacy_starts&&!offload_starts);
 assert(e.fdb_table.flags==MLX5_ESW_FDB_CREATED);
 mlx5_esw_offloads_rep_cleanup(&e,&rep);assert(!rep_frees&&!rep_erases);
 if(mode==1)assert(!notifies&&!event_unregs&&!vport_disables&&!rep_unloads&&!lag_disables&&!lag_enables);
 else assert(rep_unloads==1&&vport_disables==1&&lag_disables==1&&lag_enables==1);
 return 0;
}
