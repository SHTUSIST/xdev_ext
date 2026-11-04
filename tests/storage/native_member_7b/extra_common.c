/* Requirement CONTRACT5/6: callback-generated legal bytes and list changes must
 * reach the real PDU/storage; expected values below are literal, not encoded. */
static int extra_encode(void *member,const struct xdev_ext_stor_rw *rw,const u8 sqe64[64],u32 bytes,bool peer,struct xdev_ext_stor_rw *posting,struct xdev_ext_stor_command *cmd)
{
 int ret=original_ops->encode(member,rw,sqe64,bytes,peer,posting,cmd);
 if(!ret){cmd->bytes[4]=13;cmd->bytes[40]=103;}
 return ret;
}
static int extra_dptr(void *member,struct xdev_ext_stor_command *cmd,const struct xdev_ext_stor_extent *spans,u32 nr,struct xdev_ext_stor_extent *work,u32 capacity,void *cpu,u64 dma,u32 bytes)
{
 int ret=original_ops->encode_dptr(member,cmd,spans,nr,work,capacity,cpu,dma,bytes);
 if(!ret){u8 *list=cpu;list[2]=0x50;list[18]=0x60;}
 return ret;
}
static void test_extra_hooks(void)
{
 gfixture(false);go.encode=extra_encode;gbind();gadmit();
 GE("extra_custom_encode_submit0",nvme_xdev_ext_mech_class.submit(&gst,&gb),0);
 const u8 encoded64[64]={[0]=2,[4]=13,[40]=103,[48]=7};
 GE("extra_custom_NSID13_SLBA103_full_PDU64",memcmp(req.pdu.cmd,encoded64,64),0);
 GE("extra_custom_pinned_command_nsid13",gbp.family.command.bytes[4],13);
 GE("extra_custom_pinned_command_slba103",gbp.family.command.bytes[40],103);
 req.residual=4096;req.end_io(&req,0);gfinish();
 gfixture(true);go.encode_dptr=extra_dptr;go.retire_peer=original_ops->retire_peer;
 gb.nr=2;gb.frames[0]=(struct xdev_ext_mech_frame){.index=0,.data_len=2048};gb.frames[1]=(struct xdev_ext_mech_frame){.index=1,.umem_addr=4096,.data_len=2048};lease_dma[0]=0x100000;lease_dma[1]=0x300000;
 gbind();gadmit();GE("extra_custom_list_submit0",nvme_xdev_ext_mech_class.submit(&gst,&gb),0);
 const u8 list32[32]={[2]=0x50,[9]=8,[18]=0x60,[25]=8};
 GE("extra_custom_coherent_list32",memcmp(gbp.family.peer_io->list_cpu,list32,32),0);
 const u8 listcmd64[64]={[0]=2,[1]=0x40,[4]=7,[25]=0x10,[26]=0x20,[32]=0x20,[39]=0x30,[40]=100,[48]=7};
 GE("extra_custom_list_PDU64",memcmp(req.pdu.cmd,listcmd64,64),0);
 GE("extra_custom_two_real_handles",gbp.family.peer_io->nr_leases,2);
 req.residual=0;req.end_io(&req,0);gfinish();
}
int main(void){frozen_common_main();unsigned before=common_checks;test_extra_hooks();printf("PASS STOR7B additional custom hook assertions %u\n",common_checks-before);return 0;}
