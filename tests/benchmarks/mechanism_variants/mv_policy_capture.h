// SPDX-License-Identifier: GPL-2.0
#ifndef MV_POLICY_CAPTURE_H
#define MV_POLICY_CAPTURE_H
#include <bpf/libbpf.h>
#include "mv_create_capture.h"
static inline int mv_policy_capture(struct bpf_object *object,const char *prefix)
{
    struct bpf_map *map;
    char *json=NULL;
    size_t bytes=0;
    FILE *stream=open_memstream(&json,&bytes);
    int comma=0,ret;
    if (!stream) return -1;
    fputc('[',stream);
    bpf_object__for_each_map(map,object) {
        const unsigned char *value;
        size_t size,i;
        if (!bpf_map__is_internal(map)) continue;
        value=bpf_map__initial_value(map,&size);
        if (!value || !size) continue;
        const char *name=bpf_map__name(map);
        for (i=0;name[i];i++) if (!((name[i]>='a'&&name[i]<='z')||(name[i]>='A'&&name[i]<='Z')||(name[i]>='0'&&name[i]<='9')||name[i]=='_'||name[i]=='.')) {
            fclose(stream);free(json);errno=EINVAL;return -1;
        }
        fprintf(stream,"%s{\"name\":\"%s\",\"map_type\":%u,\"map_flags\":%u,\"initial_hex\":\"",comma?",":"",name,bpf_map__type(map),bpf_map__map_flags(map));
        for (i=0;i<size;i++) fprintf(stream,"%02x",value[i]);
        fputs("\"}",stream);comma=1;
    }
    fputs("]\n",stream);ret=fclose(stream);
    if (!ret) ret=mv_blob(prefix,"initial.json",json,bytes);
    free(json);return ret;
}
#endif
