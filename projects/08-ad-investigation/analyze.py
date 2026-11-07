"""Reproducible, offline analysis of a pinned OTRF public AD lab capture.

No attack execution. Packet analysis is header/first-line inspection, not stream
reassembly. EventTime's UTC-04:00 conversion is an explicit capture assumption.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import ipaddress
import json
from pathlib import Path, PurePosixPath
import struct
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PIN = ROOT / 'docs/research/2026-10-24-ad-investigation-source-intake.json'
UTC = timezone.utc
CAPTURE_OFFSET = timezone(timedelta(hours=-4))
SYSMON = 'Microsoft-Windows-Sysmon'
SECURITY = 'Microsoft-Windows-Security-Auditing'
SELECTED = {SYSMON:{1,3}, SECURITY:{4624,4625,4769,5145}}
FIELDS = ('@timestamp EventTime EventReceivedTime UtcTime SourceName EventID Channel '
          'Hostname RecordNumber User Image CommandLine ProcessId ProcessGuid '
          'ParentProcessGuid ParentImage ParentProcessId LogonId TargetLogonId '
          'SubjectLogonId SubjectUserName SubjectDomainName TargetUserName '
          'TargetDomainName LogonType Status SubStatus IpAddress IpPort '
          'SourceIp SourcePort DestinationIp DestinationPort Protocol Initiated '
          'ServiceName TicketEncryptionType ShareName RelativeTargetName AccessMask').split()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stamp(epoch):
    return datetime.fromtimestamp(epoch,UTC).isoformat(timespec='milliseconds').replace('+00:00','Z')


def parse_time(value, *, local=False):
    try:
        if not isinstance(value,str) or not value:
            raise ValueError('missing timestamp')
        dt = datetime.fromisoformat(value.replace('Z','+00:00'))
        if local:
            if dt.tzinfo is not None:
                raise ValueError('capture EventTime must be explicitly local')
            dt = dt.replace(tzinfo=CAPTURE_OFFSET)
        elif dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)  # Sysmon's named UtcTime field
        return dt.timestamp()
    except (ValueError,TypeError,OverflowError) as exc:
        raise ValueError('Invalid timestamp: '+repr(value)) from exc


def normalize_account(value, domain=None):
    if not isinstance(value,str) or value in ('','-'):
        return None
    if '\\' in value:
        dom,user = value.split('\\',1)
    elif '@' in value:
        user,dom = value.rsplit('@',1)
    else:
        user,dom = value,domain
    if not dom or dom=='-':
        return 'unqualified\\'+user.casefold()
    dom = dom.casefold()
    if dom=='theshire':
        dom='theshire.local'  # Explicit alias in this capture, not global stripping.
    return dom+'\\'+user.casefold()


def normalize_ip(value):
    if value in (None,'','-'):
        return None
    try:
        ip=ipaddress.ip_address(value)
        return str(ip.ipv4_mapped or ip) if isinstance(ip,ipaddress.IPv6Address) else str(ip)
    except ValueError:
        raise ValueError('Malformed IP address') from None


def integer(value):
    if value in (None,'','-'):
        return None
    try:
        text=str(value)
        return int(text,16) if text.lower().startswith('0x') else int(text)
    except (ValueError,TypeError):
        raise ValueError('Malformed integer: '+repr(value)) from None


def normalize_event(raw,line,raw_line=None):
    if not isinstance(raw,dict) or not raw.get('SourceName') or not raw.get('Hostname'):
        raise ValueError('Provider and host are required')
    event_id=integer(raw.get('EventID'))
    if event_id is None or not 0<=event_id<=65535:
        raise ValueError('Invalid event ID')
    provider=raw['SourceName']
    collected=parse_time(raw.get('@timestamp'))
    native=provider==SYSMON and bool(raw.get('UtcTime'))
    epoch=parse_time(raw.get('UtcTime')) if native else parse_time(raw.get('EventTime'),local=True)
    if provider==SYSMON:
        actor=normalize_account(raw.get('User'))
    elif event_id in (4624,4769):
        actor=normalize_account(raw.get('TargetUserName'),raw.get('TargetDomainName'))
    else:
        actor=normalize_account(raw.get('SubjectUserName'),raw.get('SubjectDomainName'))
    session=integer(raw.get('LogonId') if provider==SYSMON else raw.get('TargetLogonId') if event_id==4624 else raw.get('SubjectLogonId'))
    raw_bytes=raw_line if raw_line is not None else json.dumps(raw,sort_keys=True,separators=(',',':')).encode()
    return {
        'id':f'H{line:05d}', 'line':line, 'raw_sha256':digest(raw_bytes),
        'provider':provider, 'event_id':event_id, 'channel':raw.get('Channel'),
        'host':raw['Hostname'].casefold(), 'record_number':raw.get('RecordNumber'),
        'epoch':epoch, 'event_time':stamp(epoch), 'collection_time':stamp(collected),
        'delay_seconds':round(collected-epoch,3),
        'clock_basis':'Sysmon UtcTime (UTC)' if native else 'EventTime + capture UTC-04:00 (inferred)',
        'time_precision':'millisecond' if native else 'second',
        'actor':actor, 'target_account':normalize_account(raw.get('TargetUserName'),raw.get('TargetDomainName')),
        'caller_pid':integer(raw.get('ProcessId')), 'session':hex(session) if session is not None else None,
        'guid':str(raw.get('ProcessGuid','')).casefold(),
        'parent_guid':str(raw.get('ParentProcessGuid','')).casefold(),
        'image':raw.get('Image',''), 'parent_image':raw.get('ParentImage',''),
        'client_ip':normalize_ip(raw.get('IpAddress')),
        'source_ip':normalize_ip(raw.get('SourceIp')),
        'destination_ip':normalize_ip(raw.get('DestinationIp')),
        'source_port':integer(raw.get('SourcePort')),
        'destination_port':integer(raw.get('DestinationPort')),
        'initiated':str(raw.get('Initiated','')).lower()=='true',
        'status':raw.get('Status'), 'substatus':raw.get('SubStatus'),
        'encryption':raw.get('TicketEncryptionType'), 'service':raw.get('ServiceName'),
        'share':raw.get('ShareName',''), 'share_target':raw.get('RelativeTargetName',''),
        'logon_type':integer(raw.get('LogonType')),
        'raw':{k:raw[k] for k in FIELDS if k in raw}
    }


def verified_member(blob,spec):
    if len(blob)>32*1024*1024 or digest(blob)!=spec['sha256']:
        raise ValueError('Source archive size/hash mismatch')
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        entries=z.infolist()
        if len(entries)!=1:
            raise ValueError('Expected exactly one source member')
        info=entries[0];name=PurePosixPath(info.filename)
        if name.is_absolute() or '..' in name.parts or '\\' in info.filename or info.flag_bits&1:
            raise ValueError('Unsafe or encrypted member')
        expected=spec['members'][0]
        if info.filename!=expected['name'] or info.file_size!=expected['bytes'] or info.file_size>64*1024*1024:
            raise ValueError('Source member identity/size mismatch')
        return z.read(info)  # CRC verified by zipfile; no filesystem extraction.


def parse_pcap(data):
    if len(data)<24 or len(data)>16*1024*1024:
        raise ValueError('Invalid PCAP size')
    formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
    if data[:4] not in formats:
        raise ValueError('Classic PCAP required')
    endian,scale=formats[data[:4]]
    _,major,minor,_,_,snap,link=struct.unpack_from(endian+'IHHIIII',data)
    if (major,minor)!=(2,4) or link!=1 or snap<1:
        raise ValueError('PCAP 2.4 Ethernet required')
    packets=[];skipped=Counter();offset=24;total=0
    while offset<len(data):
        start=offset
        if len(data)-offset<16:
            raise ValueError('Truncated packet header')
        sec,fraction,size,wire=struct.unpack_from(endian+'IIII',data,offset);offset+=16
        if fraction>=scale or size>snap or size>wire or size>len(data)-offset:
            raise ValueError('Invalid/truncated packet record')
        frame=data[offset:offset+size];offset+=size;total+=1
        if total>20000:
            raise ValueError('Packet limit exceeded')
        if len(frame)<14 or frame[12:14]!=b'\x08\x00':
            skipped['non_ipv4']+=1;continue
        ip=frame[14:]
        if len(ip)<20 or ip[0]>>4!=4:
            skipped['invalid_ipv4']+=1;continue
        h=(ip[0]&15)*4;length=struct.unpack_from('!H',ip,2)[0]
        if h<20 or length<h or length>len(ip):
            skipped['truncated_ipv4']+=1;continue
        if struct.unpack_from('!H',ip,6)[0]&0x3fff:
            skipped['fragmented_ipv4']+=1;continue
        ip=ip[:length];payload=ip[h:];protocol={6:'tcp',17:'udp'}.get(ip[9])
        minimum=20 if protocol=='tcp' else 8
        if not protocol or len(payload)<minimum:
            skipped['unsupported_transport']+=1;continue
        sp,dp=struct.unpack_from('!HH',payload)
        body=b''
        if protocol=='tcp':
            tcp_h=(payload[12]>>4)*4
            if tcp_h<20 or tcp_h>len(payload):
                skipped['invalid_tcp']+=1;continue
            body=payload[tcp_h:]
        packet={'id':f'P{total:05d}','packet_number':total,'byte_offset':start,
                'frame_sha256':digest(frame),'epoch':sec+fraction/scale,
                'event_time':stamp(sec+fraction/scale),'protocol':protocol,
                'source_ip':str(ipaddress.ip_address(ip[12:16])),
                'destination_ip':str(ipaddress.ip_address(ip[16:20])),
                'source_port':sp,'destination_port':dp,'captured_bytes':size,
                'http_request':None}
        if protocol=='tcp' and dp==5985 and body.startswith(b'POST /wsman'):
            line=body.split(b'\r\n',1)[0]
            if len(line)<=200 and b' HTTP/1.' in line:
                packet['http_request']=line.decode('ascii',errors='replace')
        packets.append(packet)
    return {'total':total,'packets':packets,'skipped':dict(skipped)}


def base_name(path):
    return str(path).replace('\\','/').rsplit('/',1)[-1].casefold()


def best_window(rows,field,seconds=15):
    rows=sorted(rows,key=lambda r:(r['epoch'],r['line']))
    windows=[[r for r in rows[i:] if 0<=r['epoch']-start['epoch']<=seconds] for i,start in enumerate(rows)]
    return max(windows,key=lambda w:len({r[field] for r in w}),default=[])


def find_signals(records,packets):
    # Deduplicate exact source references, never merge records across providers.
    unique={}
    for r in records:
        if r['id'] in unique and r!=unique[r['id']]:
            raise ValueError('Conflicting source reference')
        unique[r['id']]=r
    records=sorted(unique.values(),key=lambda r:(r['epoch'],r['line']))
    signals=[]
    def add(rule,phase,title,rows,facts,limits):
        primary = [r for r in rows if r['id']==facts.get('child_record')] if phase=='remote' else [r for r in rows if r['id'] in facts.get('failure_records',[])] if phase=='spray' else rows
        signals.append({'id':rule+'-'+str(len(signals)+1),'rule':rule,'phase':phase,
                        'title':title,'record_ids':list(dict.fromkeys(r['id'] for r in rows)),
                        'event_time':stamp(min(r['epoch'] for r in primary)),
                        'facts':facts,'limits':limits})
    groups=defaultdict(list)
    for r in records:
        if r['provider']==SECURITY and r['event_id']==4625 and r['actor'] and r['caller_pid'] and r['session'] and r['target_account']:
            groups[(r['host'],r['actor'],r['caller_pid'],r['session'])].append(r)
    for key,rows in groups.items():
        w=best_window(rows,'target_account')
        if len({r['target_account'] for r in w})<5:
            continue
        anchors=[p for p in records if p['provider']==SYSMON and p['event_id']==1 and
                 (p['host'],p['actor'],p['caller_pid'],p['session'])==key and 0<=w[0]['epoch']-p['epoch']<=60]
        anchor=max(anchors,key=lambda p:p['epoch'],default=None)
        add('ACCOUNT_SPRAY','spray','Distinct-account authentication failures',w+([anchor] if anchor else []),
            {'host':key[0],'actor':key[1],'caller_pid':key[2],'distinct_accounts':len({r['target_account'] for r in w}),
             'failure_records':[r['id'] for r in w],'source_ip':None,'process_record':anchor['id'] if anchor else None},
            'The 4625 records have no client IP. Caller host/PID/logon session links the failures; password reuse and recovery are not established.')
    groups=defaultdict(list)
    for r in records:
        if r['provider']==SECURITY and r['event_id']==4769 and r['status']=='0x0' and r['encryption']=='0x17' and r['actor'] and r['client_ip'] and r['service'] and not r['service'].endswith('$') and r['service'].casefold()!='krbtgt':
            groups[(r['host'],r['actor'],r['client_ip'])].append(r)
    for key,rows in groups.items():
        w=best_window(rows,'service')
        if len({r['service'] for r in w})>=5:
            add('RC4_SERVICE_BURST','tickets','RC4 service-ticket request burst',w,
                {'host':key[0],'actor':key[1],'client_ip':key[2],'services':sorted({r['service'] for r in w})},
                'A successful RC4 TGS request is not proof of password cracking. Legacy clients, services, and administration are competing explanations.')
    groups=defaultdict(list)
    for r in records:
        if r['provider']==SECURITY and r['event_id']==5145 and r['share'].casefold().endswith('ipc$') and r['share_target'].casefold()=='srvsvc' and r['actor'] and r['client_ip']:
            groups[(r['actor'],r['client_ip'])].append(r)
    for key,rows in groups.items():
        w=best_window(rows,'host')
        if len({r['host'] for r in w})>=2:
            add('IPC_SHARE_CONTEXT','shares','IPC$ / srvsvc access across hosts',w,
                {'actor':key[0],'client_ip':key[1],'hosts':sorted({r['host'] for r in w})},
                'Share access checks provide discovery context; they do not prove file theft or reveal the full RPC operation.')
    starts={(r['host'],r['guid']):r for r in records if r['provider']==SYSMON and r['event_id']==1 and r['guid']}
    connections=[r for r in records if r['provider']==SYSMON and r['event_id']==3 and r['destination_port']==5985]
    # Incoming target addresses are tied to the target host, not to client SourceIp.
    local_ips=defaultdict(set)
    for c in connections:
        value=c['source_ip'] if c['initiated'] else c['destination_ip']
        if value:local_ips[c['host']].add(value)
    for child in starts.values():
        if base_name(child['image'])!='powershell.exe' or base_name(child['parent_image'])!='wsmprovhost.exe' or not child['actor'] or not child['session']:
            continue
        parent=starts.get((child['host'],child['parent_guid']))
        if not parent or base_name(parent['image'])!='wsmprovhost.exe' or parent['actor']!=child['actor'] or parent['session']!=child['session'] or not 0<=child['epoch']-parent['epoch']<=10:
            continue
        auth=[r for r in records if r['provider']==SECURITY and r['event_id']==4624 and r['logon_type']==3 and r['host']==child['host'] and r['actor']==child['actor'] and r['session']==child['session'] and -2<=parent['epoch']-r['epoch']<=15]
        a=max(auth,key=lambda r:r['epoch'],default=None)
        target_ips=local_ips.get(child['host'],set())
        candidates=[]
        if len(target_ips)==1:
            for c in connections:
                anchor=starts.get((c['host'],c['guid']))
                if c['initiated'] and c['destination_ip'] in target_ips and c['actor']==child['actor'] and abs(c['epoch']-parent['epoch'])<=10 and anchor and anchor['actor']==c['actor'] and 0<=c['epoch']-anchor['epoch']<=60:
                    ps=[p for p in packets if p['protocol']=='tcp' and p['http_request'] and
                        (p['source_ip'],p['source_port'],p['destination_ip'],p['destination_port'])==
                        (c['source_ip'],c['source_port'],c['destination_ip'],c['destination_port']) and abs(p['epoch']-c['epoch'])<=10]
                    if ps:candidates.append((c,anchor,ps))
        supported=bool(a and candidates)
        rows=[parent,child]+([a] if a else [])+[r for c,anchor,_ in candidates for r in [c,anchor]]
        packet_ids=sorted({p['id'] for _,_,ps in candidates for p in ps})
        add('REMOTE_POWERSHELL','remote','WinRM-hosted PowerShell on '+child['host'].split('.')[0],rows,
            {'host':child['host'],'actor':child['actor'],'parent_record':parent['id'],'child_record':child['id'],
             'auth_record':a['id'] if a else None,'network_state':'corroborated' if supported else 'not corroborated',
             'network_records':list(dict.fromkeys(c['id'] for c,_,_ in candidates)),
             'packet_ids':packet_ids,'target_ips':sorted(target_ips)},
            'Process GUID parentage and the target logon session are direct joins. Client traffic is associated by host/account, exact transport tuple, and time; no end-to-end WinRM request ID links a packet to a child process. Legitimate remote administration can produce the same pattern.')
    return {'signals':signals,'host_ip_observations':{k:sorted(v) for k,v in sorted(local_ips.items())}}


def load_sources(source_dir,download=False):
    pin=json.loads(PIN.read_text());members={};archives=[]
    for spec in pin['archives']:
        path=source_dir/(spec['kind']+'.zip')
        if not path.exists() and download:
            url=spec['pinned_url']
            if not url.startswith('https://raw.githubusercontent.com/OTRF/Security-Datasets/'+pin['source_commit']+'/'):
                raise ValueError('Unexpected source origin/pin')
            with urllib.request.urlopen(url,timeout=30) as response:
                blob=response.read(32*1024*1024+1)
            verified_member(blob,spec)
            source_dir.mkdir(parents=True,exist_ok=True);path.write_bytes(blob)
        blob=path.read_bytes();members[spec['kind']]=verified_member(blob,spec)
        archives.append({'kind':spec['kind'],'url':spec['pinned_url'],'sha256':spec['sha256'],
                         'member':spec['members'][0]['name'],'member_sha256':digest(members[spec['kind']])})
    return pin,members,archives


def build(source_dir,download=False):
    pin,members,archives=load_sources(source_dir,download)
    records=[];providers=Counter();host_counts=Counter();event_count=0;calibration=[];source_keys={};duplicates=0
    for line,raw_bytes in enumerate(io.BytesIO(members['host']),1):
        if not raw_bytes.strip():continue
        raw=json.loads(raw_bytes);event_count+=1;provider=raw.get('SourceName');event_id=raw.get('EventID')
        providers[provider]+=1;host_counts[raw.get('Hostname')]+=1
        if provider==SYSMON and event_id==1:
            delta=parse_time(raw['UtcTime'])-parse_time(raw['EventTime'],local=True)
            calibration.append({'host':raw['Hostname'],'line':line,'difference_seconds':round(delta,3)})
        if event_id not in SELECTED.get(provider,set()):continue
        record=normalize_event(raw,line,raw_line=raw_bytes)
        key=(record['host'],provider,record['channel'],record['record_number'])
        if key in source_keys:
            if source_keys[key]!=record['raw_sha256']:raise ValueError('Conflicting provider/channel/record number')
            duplicates+=1;continue
        source_keys[key]=record['raw_sha256'];records.append(record)
    if not calibration or any(not 0<=r['difference_seconds']<1 for r in calibration):
        raise ValueError('Capture-local clock calibration does not agree with Sysmon process-start pairs')
    network=parse_pcap(members['network']);report=find_signals(records,network['packets'])
    packet_refs={p for s in report['signals'] for p in s['facts'].get('packet_ids',[])}
    result={'schema':'portfolio.ad-investigation.v1','source_commit':pin['source_commit'],'source_page':pin['dataset_page'],
            'scope':'Independent analysis of OTRF recorded emulation telemetry; not a production incident or owner-operated attack lab.',
            'archives':archives,'clock_policy':{'offset':'-04:00','status':'inferred capture-local offset; not a geographic timezone claim',
                'calibration':calibration,'ingestion_is_event_time':False},
            'coverage':{'host_events':event_count,'hosts':dict(sorted(host_counts.items())),'providers':dict(sorted(providers.items())),
                'selected_host_records':len(records),'duplicate_selected_records':duplicates,
                'pcap_records':network['total'],'decoded_transport_records':len(network['packets']),
                'packet_exclusions':network['skipped']},
            'records':sorted(records,key=lambda r:(r['epoch'],r['line'])),
            'packets':[p for p in network['packets'] if p['id'] in packet_refs],**report}
    oracle=json.loads((HERE/'expected_findings.json').read_text())
    by_rule=defaultdict(list)
    for s in result['signals']:by_rule[s['rule']].append(s)
    failures=[]
    if (event_count,network['total'],len(host_counts))!=(25993,1121,4):failures.append('coverage')
    for rule,key,field in [('ACCOUNT_SPRAY','spray_records','failure_records'),('RC4_SERVICE_BURST','rc4_records',None),('IPC_SHARE_CONTEXT','share_records',None)]:
        found=by_rule[rule]
        refs=found[0]['facts'][field] if len(found)==1 and field else found[0]['record_ids'] if len(found)==1 else []
        if sorted(refs)!=sorted(oracle[key]):failures.append(rule)
    remotes=by_rule['REMOTE_POWERSHELL']
    if {s['facts']['host']:s['facts']['child_record'] for s in remotes}!=oracle['remote_children']:failures.append('remote process identities')
    if {s['facts']['host']:s['facts']['auth_record'] for s in remotes}!=oracle['remote_auth']:failures.append('remote logon identities')
    if not remotes or any(s['facts']['network_state']!='corroborated' for s in remotes):failures.append('network corroboration')
    result['validation']={'status':'PASS' if not failures else 'FAIL','oracle':'expected_findings.json','failures':failures,
                          'limit':'Source-reference agreement on one recorded capture, not precision/recall or production validation.'}
    if failures:raise ValueError('Capture oracle mismatch: '+', '.join(failures))
    return result


def write_outputs(result,check=False):
    encoded=json.dumps(result,indent=2,ensure_ascii=True)+'\n'
    browser='// Generated by projects/08-ad-investigation/analyze.py from pinned public capture.\n(function(root){const data='+json.dumps(result,separators=(',',':'),ensure_ascii=True)+';root.ADInvestigation=data;if(typeof module!=="undefined")module.exports=data;})(globalThis);\n'
    dests={HERE/'analysis.json':encoded,ROOT/'assets/js/ad-evidence.js':browser}
    out=io.StringIO(newline='');fields=['id','event_time','collection_time','delay_seconds','provider','event_id','host','actor','caller_pid','session','guid','line','raw_sha256']
    writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
    for r in result['records']:writer.writerow({k:r[k] for k in fields})
    dests[HERE/'evidence.csv']=out.getvalue()
    for path,content in dests.items():
        if check:
            if not path.exists() or path.read_bytes()!=content.encode():raise ValueError('Generated output stale: '+str(path.relative_to(ROOT)))
        else:path.write_bytes(content.encode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir',type=Path,required=True);parser.add_argument('--download',action='store_true');parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    try:
        result=build(args.source_dir,args.download);write_outputs(result,args.check)
    except (ValueError,OSError,zipfile.BadZipFile,json.JSONDecodeError) as exc:
        parser.exit(1,'ERROR: '+str(exc)+'\n')
    print(json.dumps({'status':result['validation']['status'],'host_events':result['coverage']['host_events'],
                      'selected_records':len(result['records']),'packets':result['coverage']['pcap_records'],
                      'signal_counts':dict(Counter(s['rule'] for s in result['signals'])),'splunk_executed':False}))

if __name__=='__main__':main()
