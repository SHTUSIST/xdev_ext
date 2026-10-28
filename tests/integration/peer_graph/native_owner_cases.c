/* SPDX-License-Identifier: GPL-2.0-only */
int main(int argc,char **argv)
{
 struct device device={.refs=1};struct devlink devlink={.refs=1};struct net_device netdev={.refs=1};
 struct mlx5_eswitch esw={};
 struct mlx5_core_dev mdev={.device=&device,.devlink=&devlink,.priv.eswitch=&esw};struct mlx5e_priv priv={};
 struct mlx5e_channel *c=calloc(1,sizeof(*c));assert(c&&argc==2);active_channel=c;
 c->mdev=&mdev;c->priv=&priv;c->netdev=&netdev;c->num_tc=2;
 priv.channels.c=&c;priv.channels.params.num_channels=1;
 int mode=atoi(argv[1]);
 if(mode==4)deny_module=1;
 if(mode==5)deny_devlink=1;
 int ret=mlx5e_peer_channel_get(c);
 if(mode==4||mode==5){assert(ret==-ENODEV&&!module_refs&&devlink.refs==1&&device.refs==1&&netdev.refs==1);free(c);return 0;}
 assert(!ret);assert(!mlx5e_peer_channel_get(c));
 assert(module_refs==1&&devlink.refs==2&&device.refs==2&&netdev.refs==2);
 if(mode==1)c->rq.result=-EIO;
 if(mode==2)c->sq[1].result=-ETIMEDOUT;
 if(mode==3||mode==6||mode==7){
  active_qos=calloc(1,sizeof(*active_qos));assert(active_qos);active_qos->result=mode==7?0:-EIO;
  active_qos->channel=c;INIT_LIST_HEAD(&active_qos->peer_quarantine_node);
  c->qos_sqs=calloc(1,sizeof(*c->qos_sqs));assert(c->qos_sqs);c->qos_sqs[0]=active_qos;c->qos_sqs_size=1;
 }
 if(mode==6||mode==7)mlx5e_close_qos_sq(&priv,0);
 mlx5e_close_channel(c);
 if(mode==0||mode==7){
  assert(channel_frees==1&&napi_deletes==1&&cq_closes==(mode==7?6:5));
  if(mode==7)assert(qos_frees==1);
  assert(!module_refs&&devlink.refs==1&&device.refs==1&&netdev.refs==1);
  assert(mlx5e_peer_quarantine.next==&mlx5e_peer_quarantine);return 0;
 }
 assert(channel_frees==0);
 assert(c->peer_quarantined&&priv.peer_quarantined&&esw.peer_quarantined&&napi_deletes==1);
 assert(module_refs==1&&devlink.refs==2&&device.refs==2&&netdev.refs==2);
 assert(mlx5e_peer_quarantine.next==&c->peer_quarantine_node);
 if(mode==1){assert(rq_closes==1&&sq_closes==0&&cq_closes==0);}
 if(mode==2){assert(rq_closes==1&&sq_closes==2&&cq_closes==0);}
 if(mode==3||mode==6){assert(qos_frees==0);assert(c->peer_quarantine_sqs.next==&active_qos->peer_quarantine_node);}
 int old_rq=rq_closes,old_sq=sq_closes,old_cq=cq_closes;
 assert(mlx5e_peer_channel_get(c)==-EIO);
 mlx5e_close_channel(c);
 assert(rq_closes==old_rq&&sq_closes==old_sq&&cq_closes==old_cq&&napi_deletes==1&&channel_frees==0);
 /* This process contains only host fixture allocations; no DMA resources. */
 return 0;
}
