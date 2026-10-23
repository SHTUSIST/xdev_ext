# SPDX-License-Identifier: GPL-2.0
"""One final full byte comparison. Independent of producer encoder and NXP CRC."""
import struct

POLICY='benchmark-policy-v1'


def require(test,message):
    if not test:raise ValueError(message)


def integer(value,minimum=0,maximum=2**64-1):
    require(type(value) is int and minimum<=value<=maximum,'integer range')
    return value


def profile(p):
    require(type(p) is dict,'profile')
    require(set(p)==set('schema record_bytes payload_bytes burst_packets depth bursts actors seed session_base'.split()),'profile fields')
    require(p['schema']==1 and type(p['schema']) is int and p['actors']==1,'single-actor HFT profile')
    require(p['record_bytes'] in (64,128,256) and p['payload_bytes'] in (512,1024) and p['payload_bytes']%p['record_bytes']==0,'profile geometry')
    for k,limit in (('burst_packets',32),('depth',8),('bursts',32)):integer(p[k],1,limit)
    integer(p['seed']);integer(p['session_base'],1)
    return p['burst_packets']*p['bursts']


def header(session,generation,size):
    return struct.pack('!IBBBBQIHHIIII',0x48465431,1,40,2,0,session,generation,0,1,size,0,size,0)


def source_bytes(p):
    """Specification bytes, not producer serialization or a checksum oracle."""
    out=bytearray()
    for group in range(p['burst_packets']*p['bursts']):
        for record in range(p['payload_bytes']//p['record_bytes']):
            out.extend(struct.pack('!IHHIHH',0x4846544d,0,p['record_bytes'],group,record,0))
            out.extend((p['seed']+17*group+11*record+7*j)&255 for j in range(16,p['record_bytes']))
    return bytes(out)


def verify_campaign(manifest,captures,guards,source_reference):
    try:return _verify_campaign(manifest,captures,guards,source_reference)
    except (KeyError,TypeError,IndexError,OverflowError,struct.error) as error:raise ValueError('malformed campaign') from error


def _verify_campaign(manifest,captures,guards,source_reference):
    require(type(manifest) is dict and manifest.get('schema')==1 and manifest.get('measurement_policy')==POLICY,'campaign policy/schema')
    require(manifest.get('workload_complete') is True and manifest.get('local_release_complete') is True,'campaign is not drained')
    trials=manifest['trials'];require(type(trials) is list and len(trials)>0,'trial set')
    require(type(captures) is list and type(guards) is list and type(source_reference) is bytes,'raw campaign bytes')
    index={};sessions=set();geometry=None;expected={};total_bytes=0
    for t in trials:
        require(type(t) is dict and type(t['trial_id']) is str and bool(t['trial_id']) and t['trial_id'] not in index,'trial identity')
        p=t['profile'];count=profile(p);shape={k:v for k,v in p.items() if k!='session_base'}
        require(geometry is None or geometry==shape,'source/profile changed between trials');geometry=shape
        require(p['session_base'] not in sessions,'stale trial identity');sessions.add(p['session_base'])
        require(t['backend'] in ('posix','uring-fixed-zc','session'),'backend')
        require((type(t['stop_ret']) is int and t['stop_ret']==0) if t['backend']=='session' else t['stop_ret'] is None,'STOP evidence')
        slots=t['frame_slots'];require(type(slots) is list and len(slots)==p['depth'],'frame slots')
        require(all(type(s) is int and s>0 for s in slots) and len(set(slots))==len(slots),'unique frame slots')
        require(source_reference==source_bytes(p),'complete source reference bytes')
        index[t['trial_id']]=t
        for g in range(1,count+1):expected[(t['trial_id'],g)]=p
        total_bytes+=count*p['payload_bytes']
    require(len(captures)==len(expected) and len(guards)==len(expected),'complete capture/history count')
    seen=set()
    for row in captures:
        require(type(row) is dict and row.get('truncated') is False,'capture truncation')
        data=row['datagram'];require(type(data) is bytes and len(data)>=40,'complete datagram')
        g=int.from_bytes(data[16:20],'big');key=(row['trial_id'],g)
        require(key in expected and key not in seen,'capture set identity');seen.add(key);p=expected[key];size=p['payload_bytes']
        require(data==header(p['session_base'],g,size)+source_reference[(g-1)*size:g*size],'application header/payload bytes')
    require(seen==set(expected),'complete generation capture')
    seen=set()
    for row in guards:
        require(type(row) is dict,'history record');key=(row['trial_id'],row['generation'])
        require(key in expected and key not in seen,'guard set identity');seen.add(key);p=expected[key]
        require(type(row['generation']) is int and type(row['frame_pos']) is int and type(row['slot_addr']) is int,'guard identity types')
        pos=(row['generation']-1)%p['depth']
        require(row['frame_pos']==pos and row['slot_addr']==index[row['trial_id']]['frame_slots'][pos],'guard frame identity')
        require(row['terminal_phase']=='post-send' and row['committed'] is True and row['before_reuse'] is True and row['notification_complete'] is True,'terminal history evidence')
        require(type(row['raw_prefix']) is bytes and row['raw_prefix']==b'\xa5'*430,'complete prefix bytes')
        require(type(row['raw_tail']) is bytes and row['raw_tail']==b'\x5a'*(4096-512-p['payload_bytes']),'complete tail bytes')
    require(seen==set(expected),'complete generation guards')
    return dict(status='ok',validated_trials=len(trials),validated_packets=len(expected),validated_bytes=total_bytes,validated_guards=len(expected))
