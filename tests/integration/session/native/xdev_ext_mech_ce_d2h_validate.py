#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Strict raw-evidence contract for four isolated software D2H diagnostics."""
CASES=('a-none','d-none','a-skip_d2h','d-skip_d2h')
SUMMARY=('XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=PASS cases=4 groups=1 depth=1 '
         'group_bytes=8192 backend=CPU-memcpy-standin')
PREFIX='XDEV_EXT_ZC_D2H_'

def require(ok,message):
    if not ok:raise ValueError('D2H: '+message)

def fields(line):
    result={}
    for token in line.split()[1:]:
        require('=' in token,'non-field token')
        key,value=token.split('=',1)
        require(key not in result,'duplicate field '+key)
        result[key]=value
    return result

def integer(data,key):
    try:return int(data[key],0)
    except (KeyError,ValueError) as error:raise ValueError('D2H: invalid '+key) from error

def one(lines,prefix):
    found=[line for line in lines if line.startswith(prefix)]
    require(len(found)==1,'expected one '+prefix)
    return found[0],fields(found[0])

def validate_d2h_console(text, *, delay_us=0):
    lines=text.splitlines()
    summaries=[i for i,line in enumerate(lines) if line.startswith('XDEV_EXT_ZC_CE_D2H_DIAGNOSTIC=')]
    require(len(summaries)==1 and lines[summaries[0]]==SUMMARY,'missing/invalid summary')
    selected=[(i,line) for i,line in enumerate(lines) if line.startswith(PREFIX)]
    blocks=[];current=None
    for index,line in selected:
        tag=line.split()[0]
        if tag==PREFIX+'BEGIN':
            require(current is None,'nested case')
            data=fields(line);case=data.get('case')
            require(data=={'case':case} and case in CASES,'unknown case')
            current={'case':case,'start':index,'lines':[]}
        elif tag==PREFIX+'END':
            require(current is not None and fields(line)=={'case':current['case']},'wrong end')
            current['end']=index;blocks.append(current);current=None
        else:
            require(current is not None,'record outside case')
            require(tag in (PREFIX+'MODULE',PREFIX+'RAW',PREFIX+'EXIT',PREFIX+'UNLOAD'),'unknown record')
            current['lines'].append((index,line))
    require(current is None and [b['case'] for b in blocks]==list(CASES),'missing/duplicate/reordered cases')
    require(blocks[-1]['end']<summaries[0],'summary precedes completed unload')
    for block in blocks:
        case=block['case'];chain,mode=case.split('-',1);bad=8192 if mode=='skip_d2h' else 0
        records=block['lines'];raw={'cli':[],'verify':[]};before=after=None
        for index,line in records:
            if line.startswith(PREFIX+'RAW '):
                pieces=line.split(' ',3)
                require(len(pieces)==4 and pieces[1]=='case='+case and pieces[2] in
                        ('stream=cli','stream=verify'),'wrong raw label')
                raw[pieces[2][7:]].append(pieces[3])
            else:
                data=fields(line);require(data.get('case')==case,'wrong case label')
        plain=[line for _,line in records if not line.startswith(PREFIX+'RAW ')]
        module=[(i,fields(line)) for i,line in records if line.startswith(PREFIX+'MODULE ')]
        require(len(module)==2,'expected before/after module records')
        for (index,data),phase,count in zip(module,('before','after'),(0,2)):
            require(set(data)=={'case','phase','accepted','completed','pending','refcnt','mode','poison','delay_us'},'module fields')
            require(data.get('phase')==phase and data.get('mode')==mode and data.get('poison')=='Y','module mode/poison')
            require(integer(data,'delay_us')==delay_us,'module delay')
            require(integer(data,'accepted')==integer(data,'completed')==count,'module exact counts')
            require(integer(data,'pending')==integer(data,'refcnt')==0,'module not drained')
        _,exits=one(plain,PREFIX+'EXIT ')
        expected_cli=int(chain=='d' and bad!=0);expected_verify=int(bad!=0) if chain=='a' else -1
        require(exits=={'case':case,'cli':str(expected_cli),'verify':str(expected_verify)},'wrong exit status')
        _,unload=one(plain,PREFIX+'UNLOAD ')
        require(unload=={'case':case,'status':'0'},'module unload failed')
        positions={kind:[i for i,line in records if line.startswith(PREFIX+kind+' ')] for kind in ('EXIT','UNLOAD','RAW')}
        require(module[0][0]<min(positions['RAW'])<=max(positions['RAW'])<positions['EXIT'][0]<module[1][0]<positions['UNLOAD'][0],
                'evidence/accounting/unload order')
        cli=raw['cli']
        _,ready=one(cli,'XDEV_EXT_MECH_READY ')
        require(ready.get('mode')=='source' and ready.get('xsk')=='none','wrong source mode')
        frames,seg=integer(ready,'frames'),integer(ready,'seg_len')
        require(0<seg<=4096 and frames==(8192+seg-1)//seg,'wrong single group geometry')
        _,notify=one(cli,'XDEV_EXT_MECH_NOTIFY ')
        require(notify=={'mode':'terminal','eventfd_reads':'1','stats_reads':'1'},'completion notification')
        _,stats=one(cli,'XDEV_EXT_MECH_STATS ')
        require(integer(stats,'session')==integer(ready,'session')>0 and stats.get('state')=='ACTIVE','session mismatch')
        for key in ('last_err','batches_abort','rejects','sequestered','timeouts','inflight','native_publish','protocol_err'):
            require(integer(stats,key)==0,'unclean stats '+key)
        require(integer(stats,'batches_done')==1,'wrong batch count')
        vector='1,1,1,1' if chain=='a' else '1,1,0,0'
        require(stats.get('submitted')==stats.get('completed')==vector,'wrong exact stage counts')
        window_line,window=one(cli,'XDEV_EXT_MECH_CE_WINDOW=')
        require(window_line.startswith('XDEV_EXT_MECH_CE_WINDOW=PASS ') and
                window=={'chain':chain,'written':'1','depth':'1','poison':'0xc3',
                         'reference':'none' if chain=='a' else 'frames','error':'0'},'H2D window evidence')
        verdict_line,verdict=one(cli,'XDEV_EXT_MECH_CE_SIM=')
        require(verdict=={'chain':chain} and verdict_line.split()[0]==
                'XDEV_EXT_MECH_CE_SIM='+('FAIL' if expected_cli else 'PASS'),'contradictory CLI verdict')
        if chain=='a':
            require(not any(line.startswith('XDEV_EXT_MECH_CE_HOST_DATA ') for line in cli),'unexpected Host pattern')
            verify_line,verify=one(raw['verify'],'XDEV_EXT_MECH_VERIFY_XFORM=')
            require(len(raw['verify'])==1 and verify=={'xform':'none','bytes':'8192','mismatches':str(bad)} and
                    verify_line.split()[0]=='XDEV_EXT_MECH_VERIFY_XFORM='+('FAIL' if bad else 'PASS'),'sink byte evidence')
        else:
            require(not raw['verify'],'unexpected verifier')
            _,host=one(cli,'XDEV_EXT_MECH_CE_HOST_DATA ')
            require(host=={'chain':'d','payload_bytes':'8192','checked_bytes':str(frames*4096),
                           'mismatches':str(bad),'guard_mismatches':'0'},'Host byte evidence')
    return {'cases':4,'group_bytes':8192}
