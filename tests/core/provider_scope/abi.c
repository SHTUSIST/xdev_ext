/* SPDX-License-Identifier: GPL-2.0 */
/* Literal x86-64 baseline ABI expectations from the unchanged public API. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint32_t u32;typedef uint64_t u64;
#include XDEV_DMA_UAPI_HEADER
struct module;struct file;struct file_operations;struct page;
struct xdev_ext_dma_cookie;struct xdev_ext_dma_region;struct xdev_ext_dma_xfer;
#include "actual_public_dma_types.h"
#define OFFSET(type,field,value) _Static_assert(offsetof(struct type,field)==value,"ABI offset: " #type "." #field)
#define TYPE(type,field,want) _Static_assert(__builtin_types_compatible_p(__typeof__(((struct type *)0)->field),want),"ABI type: " #type "." #field)
_Static_assert(sizeof(void *)==8,"cohort targets project x86-64 ABI");
_Static_assert(XDEV_EXT_DMA_MECH_ABI_VERSION==2,"DMA/BPF ABI2 remains frozen");
_Static_assert(sizeof(struct xdev_ext_dma_provider_ops)==64,"provider ops ABI size");
OFFSET(xdev_ext_dma_provider_ops,owner,0);OFFSET(xdev_ext_dma_provider_ops,fops,8);
OFFSET(xdev_ext_dma_provider_ops,bind_region,16);OFFSET(xdev_ext_dma_provider_ops,unbind_region,24);
OFFSET(xdev_ext_dma_provider_ops,bind_host,32);OFFSET(xdev_ext_dma_provider_ops,unbind_host,40);
OFFSET(xdev_ext_dma_provider_ops,submit,48);OFFSET(xdev_ext_dma_provider_ops,poll,56);
TYPE(xdev_ext_dma_provider_ops,owner,struct module *);TYPE(xdev_ext_dma_provider_ops,fops,const struct file_operations *);
TYPE(xdev_ext_dma_provider_ops,bind_region,int (*)(struct file *,u64,u64,struct xdev_ext_dma_region *));
TYPE(xdev_ext_dma_provider_ops,unbind_region,int (*)(struct xdev_ext_dma_region *));
TYPE(xdev_ext_dma_provider_ops,bind_host,int (*)(struct xdev_ext_dma_region *,struct page **,u32,void **));
TYPE(xdev_ext_dma_provider_ops,unbind_host,int (*)(void *));
TYPE(xdev_ext_dma_provider_ops,submit,int (*)(struct xdev_ext_dma_region *,void *,u32,const struct xdev_ext_dma_xfer *,u32,struct xdev_ext_dma_cookie *,u64));
TYPE(xdev_ext_dma_provider_ops,poll,int (*)(struct xdev_ext_dma_region *));
_Static_assert(sizeof(struct xdev_ext_dma_region)==48,"region ABI size");
OFFSET(xdev_ext_dma_region,ops,0);OFFSET(xdev_ext_dma_region,priv,8);OFFSET(xdev_ext_dma_region,len,16);
OFFSET(xdev_ext_dma_region,segment_size,24);OFFSET(xdev_ext_dma_region,max_entry_len,28);
OFFSET(xdev_ext_dma_region,alignment,32);OFFSET(xdev_ext_dma_region,directions,36);OFFSET(xdev_ext_dma_region,polled,40);
TYPE(xdev_ext_dma_region,ops,const struct xdev_ext_dma_provider_ops *);TYPE(xdev_ext_dma_region,priv,void *);
TYPE(xdev_ext_dma_region,polled,bool);TYPE(xdev_ext_dma_region,len,u64);
TYPE(xdev_ext_dma_region,segment_size,u32);TYPE(xdev_ext_dma_region,max_entry_len,u32);
TYPE(xdev_ext_dma_region,alignment,u32);TYPE(xdev_ext_dma_region,directions,u32);
_Static_assert(sizeof(struct xdev_ext_dma_xfer)==40,"transfer ABI size");
OFFSET(xdev_ext_dma_xfer,owner,0);OFFSET(xdev_ext_dma_xfer,generation,8);OFFSET(xdev_ext_dma_xfer,host_byte_off,16);
OFFSET(xdev_ext_dma_xfer,device_off,24);OFFSET(xdev_ext_dma_xfer,len,32);OFFSET(xdev_ext_dma_xfer,flags,36);
TYPE(xdev_ext_dma_xfer,owner,u64);TYPE(xdev_ext_dma_xfer,generation,u64);TYPE(xdev_ext_dma_xfer,host_byte_off,u64);
TYPE(xdev_ext_dma_xfer,device_off,u64);TYPE(xdev_ext_dma_xfer,len,u32);TYPE(xdev_ext_dma_xfer,flags,u32);
int main(void){return 0;}
