/* SPDX-License-Identifier: GPL-2.0 */
/* Decode event executes production ring.c; only public stats are read. */
static struct xdev_ext_xd_link *review_stats_link;
static struct tb_service *tb_to_service(struct device *dev)
{ return (struct tb_service *)dev; }
static void *tb_service_get_drvdata(struct tb_service *svc)
{ (void)svc; return review_stats_link; }
static int sysfs_emit(char *buf,const char *format,...)
{va_list ap;va_start(ap,format);int n=vsnprintf(buf,4096,format,ap);va_end(ap);return n;}
/* @PRODUCTION_STATS_SHOW@ */
static long long review_ring_value(const char *text,const char *key)
{
    char pattern[80];snprintf(pattern,sizeof(pattern),"%s=",key);const char *p=strstr(text,pattern);
    assert(p);return strtoll(p+strlen(pattern),NULL,10);
}
static long long review_crc_errors(void)
{
    assert(review_stats_show && "required production stats attribute missing");
    char buf[4096];struct device_attribute *attr=NULL;
    assert(review_stats_show((struct device *)&fixture_xd.dev,attr,buf)>0);
    return review_ring_value(buf,"crc_errors");
}
int main(void)
{
    review_init();review_start();review_stats_link=&review_link;
    review_link.remote_inc=0x2222;review_link.local_inc=0x1111;
    struct xdev_ext_xd_msg m={.type=XDEV_EXT_XD_CTS,.src_inc=0x2222,.dst_inc=0x1111,.channel=0,.stream=1,.group=1,.credit=1};
    u8 bytes[XDEV_EXT_XD_MSG_LEN];assert(!xdev_ext_xd_msg_encode(bytes,&m,crc32c));
    bytes[sizeof(bytes)-1]^=1;
    xdev_ext_xd_ctl_dispatch(&review_link,bytes,sizeof(bytes));
    fprintf(stderr,"# actual production corrupt-CRC dispatch executed; dropped=%llu\n",(unsigned long long)review_link.ctl_dropped);
    assert(review_link.ctl_dropped==1);
    assert(review_crc_errors()==1);
    /* Valid-CRC stale identity is a drop, not another CRC error. */
    m.src_inc=0x9999;assert(!xdev_ext_xd_msg_encode(bytes,&m,crc32c));
    xdev_ext_xd_ctl_dispatch(&review_link,bytes,sizeof(bytes));
    assert(review_crc_errors()==1);
    return 0;
}
