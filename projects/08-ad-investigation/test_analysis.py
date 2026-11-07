import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import unittest
import zipfile
from analyze import normalize_event, normalize_account, normalize_ip, find_signals, parse_pcap, verified_member

SYSMON='Microsoft-Windows-Sysmon'
SECURITY='Microsoft-Windows-Security-Auditing'
def raw(event_id=4625,provider=SECURITY,**extra):
    row={'SourceName':provider,'EventID':event_id,'Hostname':'WORKSTATION5.theshire.local','Channel':'Security','RecordNumber':1,'@timestamp':'2020-10-22T08:29:55.000Z','EventTime':'2020-10-22 04:29:53','TargetUserName':'alice','TargetDomainName':'THESHIRE','SubjectUserName':'operator','SubjectDomainName':'THESHIRE','ProcessId':'0x1d60','SubjectLogonId':'0x123','LogonType':'2','Status':'0xc000006d','SubStatus':'0xc000006a'}
    row.update(extra);return row
def event(line=1,**kwargs):return normalize_event(raw(**kwargs),line)
def failures(seconds=0,count=5,**kwargs):
    return [event(i+1,RecordNumber=i+1,TargetUserName='user'+str(i),EventTime=f'2020-10-22 04:29:{53+seconds:02d}',**kwargs) for i in range(count)]
def signal(rows,rule):return [r for r in find_signals(rows,[])['signals'] if r['rule']==rule]
def tcp_packet(src_port=50000,dst_port=5985,body=b'POST /wsman HTTP/1.1\r\n\r\n',fragment=0):
    import ipaddress
    tcp=struct.pack('!HHIIBBHHH',src_port,dst_port,1,0,5<<4,0x18,8192,0,0)+body
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),1,fragment,64,6,0,ipaddress.ip_address('172.18.39.5').packed,ipaddress.ip_address('172.18.39.6').packed)+tcp
    return b'\x00'*12+b'\x08\x00'+ip
def pcap(frames):
    return struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+b''.join(struct.pack('<IIII',1603355397,1000,len(f),len(f))+f for f in frames)

class Normalization(unittest.TestCase):
    def test_domain_preserved_and_explicit_alias_only(self):
        self.assertEqual(normalize_account('THESHIRE\\Alice'),'theshire.local\\alice')
        self.assertEqual(normalize_account('alice@THESHIRE.LOCAL'),'theshire.local\\alice')
        self.assertNotEqual(normalize_account('OTHER\\alice'),normalize_account('THESHIRE\\alice'))
    def test_mapped_ipv4_and_missing_ip(self):
        self.assertEqual(normalize_ip('::ffff:172.18.39.5'),'172.18.39.5')
        self.assertIsNone(normalize_ip('-'))
    def test_explicit_capture_clock_and_collection_delay(self):
        r=event();self.assertEqual(r['event_time'],'2020-10-22T08:29:53.000Z');self.assertEqual(r['delay_seconds'],2)
        self.assertIn('inferred',r['clock_basis']);self.assertIsNone(r['client_ip'])
    def test_native_sysmon_clock_wins(self):
        r=event(provider=SYSMON,event_id=1,UtcTime='2020-10-22 08:29:52.016',User='THESHIRE\\operator')
        self.assertEqual(r['event_time'],'2020-10-22T08:29:52.016Z');self.assertEqual(r['clock_basis'],'Sysmon UtcTime (UTC)')
    def test_malformed_date_and_missing_provider_rejected(self):
        for data in [raw(EventTime='wrong'),raw(SourceName=''),raw(Hostname=''),raw(EventID='')]:
            with self.assertRaises(ValueError):normalize_event(data,1)
    def test_source_reference_hash(self):
        b=b'example raw line\n';r=normalize_event(raw(),7,raw_line=b)
        self.assertEqual(r['id'],'H00007');self.assertEqual(r['raw_sha256'],hashlib.sha256(b).hexdigest())

class Rules(unittest.TestCase):
    def test_distinct_account_failures(self):
        hit=signal(failures(),'ACCOUNT_SPRAY')[0]
        self.assertEqual(hit['facts']['distinct_accounts'],5)
        self.assertIsNone(hit['facts']['source_ip'])
    def test_same_account_retries_do_not_become_spray(self):
        rows=failures()
        for r in rows:r['target_account']='theshire.local\\same'
        self.assertFalse(signal(rows,'ACCOUNT_SPRAY'))
    def test_duplicate_reference_does_not_inflate_count(self):
        rows=failures(count=4);self.assertFalse(signal(rows+[copy.deepcopy(rows[0])],'ACCOUNT_SPRAY'))
    def test_other_host_pid_session_or_domain_cannot_complete_group(self):
        for field,value in [('host','other.local'),('caller_pid',999),('session','0x999'),('actor','other\\operator')]:
            rows=failures();rows[-1][field]=value;self.assertFalse(signal(rows,'ACCOUNT_SPRAY'))
    def test_provider_collision_rejected(self):
        rows=failures()
        for r in rows:r['provider']=SYSMON
        self.assertFalse(signal(rows,'ACCOUNT_SPRAY'))
    def test_inclusive_window(self):
        rows=failures();rows[-1]['epoch']+=15;self.assertTrue(signal(rows,'ACCOUNT_SPRAY'))
        rows[-1]['epoch']+=0.001;self.assertFalse(signal(rows,'ACCOUNT_SPRAY'))
    def test_rc4_tickets_require_success_distinct_services_and_same_principal(self):
        rows=[event(i+1,event_id=4769,RecordNumber=i+1,TargetUserName='operator@THESHIRE.LOCAL',ServiceName='svc'+str(i),TicketEncryptionType='0x17',Status='0x0',IpAddress='::ffff:172.18.39.5') for i in range(5)]
        self.assertEqual(len(signal(rows,'RC4_SERVICE_BURST')),1)
        for field,value in [('actor','other\\operator'),('client_ip','172.18.39.99'),('encryption','0x12'),('status','0x1')]:
            test=copy.deepcopy(rows);test[-1][field]=value;self.assertFalse(signal(test,'RC4_SERVICE_BURST'))
    def test_remote_parent_guid_host_account_session_required(self):
        p=event(1,provider=SYSMON,event_id=1,Image=r'C:\Windows\System32\wsmprovhost.exe',ProcessGuid='{parent}',LogonId='0xabc',User='THESHIRE\\operator',UtcTime='2020-10-22 08:29:56.000')
        c=event(2,provider=SYSMON,event_id=1,Image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',ParentImage=p['image'],ParentProcessGuid='{parent}',ProcessGuid='{child}',LogonId='0xabc',User='THESHIRE\\operator',UtcTime='2020-10-22 08:29:57.000')
        a=event(3,event_id=4624,TargetUserName='operator',TargetLogonId='0xabc',LogonType='3')
        hit=signal([p,c,a],'REMOTE_POWERSHELL')[0];self.assertEqual(hit['facts']['auth_record'],'H00003');self.assertEqual(hit['facts']['network_state'],'not corroborated')
        bad=copy.deepcopy(a);bad['session']='0xdef';self.assertIsNone(signal([p,c,bad],'REMOTE_POWERSHELL')[0]['facts']['auth_record'])
        for key,val in [('parent_guid','{wrong}'),('host','other.local'),('actor','other\\operator'),('session','0xdef')]:
            bad=copy.deepcopy(c);bad[key]=val;self.assertFalse(signal([p,bad,a],'REMOTE_POWERSHELL'))
    def test_input_is_not_mutated(self):
        rows=failures();saved=copy.deepcopy(rows);find_signals(rows,[]);self.assertEqual(rows,saved)

class Capture(unittest.TestCase):
    def test_packet_reference_headers_and_wsman_request(self):
        result=parse_pcap(pcap([tcp_packet()]))
        self.assertEqual(result['total'],1);p=result['packets'][0];self.assertEqual(p['id'],'P00001');self.assertEqual(p['destination_port'],5985);self.assertEqual(p['http_request'],'POST /wsman HTTP/1.1')
    def test_fragment_explicitly_excluded(self):
        r=parse_pcap(pcap([tcp_packet(fragment=0x2000)]));self.assertEqual(r['skipped']['fragmented_ipv4'],1);self.assertEqual(r['packets'],[])
    def test_truncated_capture_rejected(self):
        for data in [b'bad',pcap([tcp_packet()])[:-5]]:
            with self.assertRaises(ValueError):parse_pcap(data)
    def test_zip_integrity_before_parsing(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('events.json','{}\n')
        blob=b.getvalue();spec={'sha256':hashlib.sha256(blob).hexdigest(),'members':[{'name':'events.json','bytes':3}]}
        self.assertEqual(verified_member(blob,spec),b'{}\n')
        with self.assertRaises(ValueError):verified_member(blob+b'x',spec)
    def test_unsafe_member_rejected(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('../events.json','{}')
        blob=b.getvalue();spec={'sha256':hashlib.sha256(blob).hexdigest(),'members':[{'name':'../events.json','bytes':2}]}
        with self.assertRaises(ValueError):verified_member(blob,spec)

class CaptureCounterexamples(unittest.TestCase):
    """Perturb the retained capture, challenging joins rather than rule wording."""
    @classmethod
    def setUpClass(cls):
        cls.data=json.loads((Path(__file__).parent/'analysis.json').read_text())
    def test_changed_client_port_cannot_corroborate_remote_execution(self):
        packets=copy.deepcopy(self.data['packets'])
        for p in packets:p['source_port']+=1000
        remote=[s for s in find_signals(self.data['records'],packets)['signals'] if s['rule']=='REMOTE_POWERSHELL']
        self.assertEqual(len(remote),3)
        self.assertTrue(all(s['facts']['network_state']=='not corroborated' for s in remote))
    def test_missing_target_logon_cannot_be_promoted_by_packet_presence(self):
        rows=[r for r in self.data['records'] if r['event_id']!=4624]
        remote=[s for s in find_signals(rows,self.data['packets'])['signals'] if s['rule']=='REMOTE_POWERSHELL']
        self.assertEqual(len(remote),3)
        self.assertTrue(all(s['facts']['auth_record'] is None and s['facts']['network_state']=='not corroborated' for s in remote))
    def test_remote_phase_time_is_child_execution_not_source_anchor(self):
        records={r['id']:r for r in self.data['records']}
        for s in find_signals(self.data['records'],self.data['packets'])['signals']:
            if s['rule']=='REMOTE_POWERSHELL':self.assertEqual(s['event_time'],records[s['facts']['child_record']]['event_time'])

if __name__=='__main__':unittest.main()
