#!/usr/bin/env python3
"""A Cisco FTD (or ASA) log, read the way this program reads it.

FTD writes a sentence behind a message id - `%FTD-6-302014: Teardown TCP
connection ...` - and a syslog server usually files it a message id to a
file. The lines below have the shapes of a real pair in failover, with every
address, name and identifier changed. Nothing here is ever judged.

    ./test/ftd.py
"""
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def title(words):
    print('\n%s' % words)


def fresh(**more):
    folder = tempfile.mkdtemp(prefix='isemon-ftd-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'ftd.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'ftd.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'ise': 0,
                          'ise_paths': [str(Path(folder) / 'nothing')], 'fwlog': 1,
                          'fwlog_keep_allowed': 1})
    isemon.CONFIG.update(more)
    isemon._ZONES.clear() if hasattr(isemon, '_ZONES') else None
    store = isemon.Storage(isemon.DB_FILE)
    return folder, store, isemon.Daemon(store)


T = time.localtime(time.time() - 600)
MON = time.strftime('%b', T)
DAY = '%2d' % T.tm_mday
CLOCK = time.strftime('%H:%M:%S', T)


def line(unit, msg, sec=0):
    clock = time.strftime('%H:%M:%S', time.localtime(time.time() - 600 + sec))
    return '%s %s %s fw%d.example.cz %s' % (MON, DAY, clock, unit, msg)


BUILT = line(1, '%FTD-6-302013: Built inbound TCP connection 9001 for LAN:10.1.2.3/50000 '
                '(203.0.113.10/40000) to OUTSIDE:198.51.100.7/443 (198.51.100.7/443)')
TEAR = line(1, '%FTD-6-302014: Teardown TCP connection 9001 for LAN:10.1.2.3/50000 to '
               'OUTSIDE:198.51.100.7/443 duration 0:01:05 bytes 64000 TCP FINs from LAN', 65)
OUT_BUILT = line(1, '%FTD-6-302015: Built outbound UDP connection 9002 for '
                    'OUTSIDE:198.51.100.53/53 (198.51.100.53/53) to LAN:10.1.2.4/60000 '
                    '(10.1.2.4/60000)', 1)
OUT_TEAR = line(1, '%FTD-6-302016: Teardown UDP connection 9002 for OUTSIDE:198.51.100.53/53 '
                   'to LAN:10.1.2.4/60000 duration 0:00:00 bytes 120', 2)
STANDBY_TCP = line(2, '%FTD-6-302014: Teardown TCP connection 77001 for LAN:10.1.2.3/50000 to '
                      'OUTSIDE:198.51.100.7/443 duration 0:01:05 bytes 64000 Failover primary '
                      'closed', 66)
STANDBY_UDP = line(2, '%FTD-6-302016: Teardown UDP connection 77002 for LAN:10.1.2.9/5353 to '
                      'OUTSIDE:198.51.100.53/53 duration 0:02:01 bytes 0', 30)
ICMP = line(1, '%FTD-6-302021: Teardown ICMP connection for faddr 10.1.2.3/7 gaddr '
               '198.51.100.9/0 laddr 198.51.100.9/0 type 8 code 0 ', 3)
ACL = line(1, '%FTD-4-106023: Deny tcp src OUTSIDE:192.0.2.66/40000 dst DMZ:203.0.113.5/23 '
              'by access-group "CSM_FW_ACL_" [0x97aa021a, 0x0]', 4)
DACL = line(1, "%FTD-4-106103: access-list #ACSACL#-IP-VPN_Users-6a1446bd denied tcp for user "
               "'jnovak' OUTSIDE/10.9.0.80(52728) -> LAN/10.1.6.23(445) hit-cnt 1 first hit "
               "[0xb7c1c1a6, 0x0]", 5)
NOCONN = line(1, '%FTD-6-106015: Deny TCP (no connection) from 10.1.2.90/43348 to '
                 '10.1.6.123/1514 flags RST  on interface LAN', 6)
AAA = line(1, '%FTD-6-113005: AAA user authentication Rejected : reason = AAA failure : '
              'server = 10.1.14.83 : user = ***** : user IP = 9.9.9.9', 7)
WEBVPN = line(1, '%FTD-6-716039: Group <VPN_ADM> User <*****> IP <192.0.2.54> '
                 'Authentication: rejected, Session Type: WebVPN.', 8)
IKE = line(1, '%FTD-4-750003: Local:203.0.113.2:500 Remote:192.0.2.35:500 Username:L2LGroup '
              'IKEv2 Negotiation aborted due to ERROR: Failed to locate an item in the '
              'database', 9)
GONE = line(1, '%FTD-4-113019: Group = VPN_Users, Username = jnovak, IP = 192.0.2.26, Session '
               'disconnected. Session Type: SSL, Duration: 13h:38m:45s, Bytes xmt: 723879244, '
               'Bytes rcv: 128915865, Reason: User Requested', 10)
UAUTH = line(1, '%FTD-5-109210: UAUTH: Session=0x5b1ff000, User=pdvorak, Assigned '
                'IP=10.9.0.78, Succeeded removing entry.', 11)
FILE = line(1, '%FTD-6-430004: DeviceUUID: 1a8b, InstanceID: 3, ConnectionID: 1, SrcIP: '
               '10.1.6.56, DstIP: 198.51.100.205, SrcPort: 43126, DstPort: 80, Protocol: tcp, '
               'FileDirection: Download, FileAction: Malware Cloud Lookup, FileName: a.gz, '
               'FileType: GZ, SHA_Disposition: Unknown, User: Not Found, URI: '
               'http://mirror.example.org/a.gz', 12).replace('fw1.example.cz ',
                                                             'fw1.example.cz  : ')
OFFLOAD = line(1, '%FTD-6-805001: Offloaded TCP Flow for connection 9001 from LAN:10.1.2.3/50000 '
                  '(10.1.2.3/50000) to OUTSIDE:198.51.100.7/443 (198.51.100.7/443)', 13)


title('One line read')
f = isemon.ftd_record_from(TEAR).facts
ok('a session that ended was let through', (f['type'], f['verdict']), ('traffic', 'allow'))
ok('...from where, to where', (f['srcintf'], f['srcip'], f['srcport'], f['dstintf'],
                               f['dstip'], f['dstport']),
   ('LAN', '10.1.2.3', 50000, 'OUTSIDE', '198.51.100.7', 443))
ok('...how long and how much, both ways together', (f['duration'], f['sent'], f['rcvd'],
                                                    f['fields']['bytes']),
   (65, 64000, 0, 'both ways'))
ok('...and why it ended', f['fields']['reason'], 'TCP FINs from LAN')
ok('...the service by its port', (f['proto'], f['service']), (6, 'HTTPS'))
ok('...the unit that wrote it', f['dev'], 'fw1.example.cz')
ok('...its connection is the session', f['session'], 9001)
ok('the time is the syslog header\'s, in this machine\'s zone where log_zone is empty', abs(f['ts'] - (time.time() - 600 + 65)) < 2,
   True)
b = isemon.ftd_record_from(BUILT).facts
ok('a session opened is marked, for the one that ends it',
   (b['fields'].get('_built'), b['fields'].get('transip'), b['fields'].get('transport')),
   ('1', '203.0.113.10', '40000'))
ob = isemon.ftd_record_from(OUT_BUILT).facts
ok('an outbound session is turned round: the source is who began it',
   (ob['srcip'], ob['dstip'], ob['dstport']), ('10.1.2.4', '198.51.100.53', 53))
a = isemon.ftd_record_from(ACL).facts
ok('a refusal by the access group is refused, with the rule',
   (a['verdict'], a['policyname'], a['fields']['rule']), ('deny', 'CSM_FW_ACL_ 0x97aa021a',
                                                          '0x97aa021a'))
d = isemon.ftd_record_from(DACL).facts
ok('a downloadable ACL refusing a VPN user names them',
   (d['verdict'], d['user'], d['policyname'], d['srcip'], d['dstport']),
   ('deny', 'jnovak', '#ACSACL#-IP-VPN_Users-6a1446bd', '10.9.0.80', 445))
n = isemon.ftd_record_from(NOCONN).facts
ok('a packet of a session already closed is said, not refused',
   (n['sub'], n['verdict'], n['fields']['flags']), ('stray', 'info', 'RST'))
aa = isemon.ftd_record_from(AAA).facts
ok('a refused VPN sign-in failed, the masked name taken as none',
   (aa['type'], aa['sub'], aa['verdict'], aa['user'], aa['srcip']),
   ('event', 'vpn', 'fail', '', '9.9.9.9'))
ok('...and the WebVPN one too, with its group',
   (isemon.ftd_record_from(WEBVPN).facts['verdict'],
    isemon.ftd_record_from(WEBVPN).facts['fields']['group']), ('fail', 'VPN_ADM'))
ik = isemon.ftd_record_from(IKE).facts
ok('a tunnel that could not be built failed, the tunnel group not taken for a person',
   (ik['verdict'], ik['user'], ik['fields']['group'], ik['srcip']),
   ('fail', '', 'L2LGroup', '192.0.2.35'))
g = isemon.ftd_record_from(GONE).facts
ok('a VPN session ending says how long and how much, each way',
   (g['user'], g['duration'], g['sent'], g['rcvd']), ('jnovak', 49125, 723879244, 128915865))
ok('a file event from the management centre is read as one',
   (isemon.ftd_record_from(FILE).facts['sub'], isemon.ftd_record_from(FILE).facts['host']),
   ('file', 'mirror.example.org'))
ok('a flow moved to the fast path is nothing', isemon.ftd_record_from(OFFLOAD), None)
ok('the standby\'s copy of a session is nothing', isemon.ftd_record_from(STANDBY_TCP), None)
ok('a line that is not FTD\'s is nothing', isemon.ftd_record_from('Oct  1 x sshd: hi'), None)
ok('the events say what they are', isemon.ftd_record_from(IKE).facts['fields']['logdesc'],
   'IKEv2: negotiation aborted')

title('A pair in failover, one firewall with two folders')
folder, store, daemon = fresh()
u1, u2 = Path(folder) / 'fw1', Path(folder) / 'fw2'
u1.mkdir()
u2.mkdir()
isemon.CONFIG['fwlog_sources'] = isemon.check_setting('fwlog_sources', [
    {'name': 'hq', 'type': 'ftd', 'paths': [str(u1), str(u2)], 'files': '*.log'}])
ok('one firewall, with a folder for each unit',
   [(s['name'], len(s['paths'])) for s in isemon.fw_sources()], [('hq', 2)])
(u1 / '%FTD-6-302013.log').write_text(BUILT + '\n')
(u1 / '%FTD-6-302014.log').write_text(TEAR + '\n')
(u1 / '%FTD-6-302015.log').write_text(OUT_BUILT + '\n')
(u1 / '%FTD-6-302016.log').write_text(OUT_TEAR + '\n')
(u1 / '%FTD-4-106103.log').write_text(DACL + '\n')
(u1 / '%FTD-6-113005.log').write_text(AAA + '\n')
(u1 / '%FTD-4-113019.log').write_text(GONE + '\n')
(u1 / '%FTD-6-805001.log').write_text(OFFLOAD + '\n')
(u1 / '.log').write_text(FILE + '\n')
(u2 / '%FTD-6-302014.log').write_text(STANDBY_TCP + '\n')
(u2 / '%FTD-6-302016.log').write_text(STANDBY_UDP + '\n')
followed = sorted(Path(p).name for _k, p, s in daemon.log_files() if s == 'fwlog')
ok('every file of every unit is followed, not the newest two',
   len(followed), 11)
daemon.read_logs()
daemon.flush_fw_events()
rows = {r['msg'].split(':')[0][:20]: r for r in store.fw_rows(since=0, limit=100)[0]}
ok('each line carries the firewall\'s name', {r['fw'] for r in rows.values()}, {'hq'})
sessions = store.fw_rows(since=0, kind='traffic', verdict='allow')[0]
ok('a session is one row, not an opening and an ending',
   sorted((r['srcip'], r['dstip']) for r in sessions),
   [('10.1.2.3', '198.51.100.7'), ('10.1.2.4', '198.51.100.53')])
tear = [r for r in sessions if r['srcip'] == '10.1.2.3'][0]
got = store.fw_get(tear['ident'])
ok('...and the ending has the opening\'s translation', got['fields'].get('transip'),
   '203.0.113.10')
ok('the standby\'s copies are not counted, said or unsaid',
   store.fw_rows(since=0, query='dev:fw2*')[1], 0)
s = store.fw_summary(time.time() - 7200, fw='hq')
ok('the cards count each session once', s['totals']['allow']['n'], 2)
ok('...and the bytes it carried', s['totals']['allow']['sent'], 64120)
ok('how sessions ended is a card of its own',
   [r['val'] for r in s['tops']['reason']['busiest']], ['TCP FINs'])
ok('the file the management centre looked at is kept', store.fw_rows(since=0,
                                                                     kind='utm/file')[1], 1)
ok('countries are filled in where the firewall writes none: its own are private',
   tear['srccountry'], 'Reserved')

title('The person behind an address inside the VPN')
folder, store, daemon = fresh()
facts = [isemon.ftd_record_from(DACL).facts,
         isemon.ftd_record_from(line(1, '%FTD-6-302014: Teardown TCP connection 9100 for '
                                        'OUTSIDE:10.9.0.80/52730 to LAN:10.1.6.23/443 '
                                        'duration 0:00:05 bytes 900 TCP FINs from LAN',
                                     20)).facts]
for one in facts:
    one['fw'] = 'hq'
store.note_fw_events(daemon.fw_fill(facts))
named = [r for r in store.fw_rows(since=0, verdict='allow')[0]]
ok('a session from an address a refusal named is that person\'s',
   [(r['srcip'], r['usr']) for r in named], [('10.9.0.80', 'jnovak')])
ok('...and says where the name came from',
   store.fw_get(named[0]['ident'])['fields'].get('user_from'), 'its VPN address')
about = daemon.fw_about_user('jnovak')
ok('a name looked up shows what the firewall saw of it',
   (about['by'].get('allow'), about['by'].get('deny'), about['inner']),
   (1, 1, ['10.9.0.80']))

title('Read beside ISE, and without it')
folder, store, daemon = fresh(ise=1)
masked = isemon.ftd_record_from(AAA).facts
masked['fw'] = 'hq'
store.note_fw_events(daemon.fw_fill([dict(masked)]))
ok('without ISE records, a masked name stays empty',
   store.fw_rows(since=0, verdict='fail')[0][0]['usr'], '')
folder, store, daemon = fresh(ise=1)
store.add_failed({'session': 'ise/1', 'ts': masked['ts'] - 1, 'ip': '9.9.9.9',
                  'username': 'mkral', 'device': 'FTD-VPN', 'server': 'ise1', 'detail': '{}'})
store.note_fw_events(daemon.fw_fill([dict(masked, fields=dict(masked['fields']))]))
row = store.fw_rows(since=0, verdict='fail')[0][0]
ok('with them, the name ISE wrote for the same attempt is put on it',
   (row['usr'], store.fw_get(row['ident'])['fields'].get('user_from')), ('mkral', 'ISE'))
store.add_passed({'session': 'ise/2', 'ts': time.time() - 300, 'ip': '192.0.2.26',
                  'username': 'mkral', 'device': 'FTD-VPN', 'server': 'ise1',
                  'detail': '{}', 'kind': 'vpn', 'groups': 'VPN users',
                  'acl': '#ACSACL#-IP-VPN_Users-6a1446bd'}) \
    if hasattr(store, 'add_passed') else None
line_said = daemon.fw_detail(row['ident'])
ok('...and the line\'s popup shows the person\'s last ISE sign-in where there is one',
   bool(line_said.get('ise')) == hasattr(store, 'add_passed'), True)

title('What the management centre sends: intrusions, malware, Security Intelligence, SSL')
IPS = line(1, '%FTD-1-430001: DeviceUUID: 1a8b, InstanceID: 1, FirstPacketSecond: '
              '2026-10-01T18:00:00Z, ConnectionID: 7, AccessControlRuleAction: Allow, SrcIP: '
              '9.9.9.9, DstIP: 10.1.2.30, SrcPort: 44000, DstPort: 80, Protocol: tcp, '
              'IngressInterface: OUTSIDE, EgressInterface: DMZ, Priority: 1, GID: 1, SID: 58722, '
              'Revision: 3, Message: SERVER-WEBAPP Example exploit attempt, Classification: '
              'Attempted Administrator Privilege Gain, IntrusionPolicy: Balanced, InlineResult: '
              'Blocked', 30)
MAL = line(1, '%FTD-1-430005: DeviceUUID: 1a8b, SrcIP: 198.51.100.205, DstIP: 10.1.6.56, '
              'SrcPort: 80, DstPort: 43126, Protocol: tcp, FileDirection: Download, FileAction: '
              'Malware Block, FileName: x.exe, FileType: MSEXE, SHA_Disposition: Malware, '
              'ThreatName: W32.Example.Trojan, URI: http://bad.example.net/x.exe', 31)
SI = line(1, '%FTD-1-430002: DeviceUUID: 1a8b, AccessControlRuleAction: Block, SrcIP: '
             '10.1.2.40, DstIP: 198.51.100.66, SrcPort: 50001, DstPort: 443, Protocol: tcp, '
             'SecurityIntelligenceCategory: Malware, URLSICategory: Malware', 32)
SSLE = line(1, '%FTD-6-430003: DeviceUUID: 1a8b, AccessControlRuleAction: Allow, SrcIP: '
               '10.1.2.41, DstIP: 198.51.100.70, SrcPort: 50002, DstPort: 443, Protocol: tcp, '
               'InitiatorBytes: 1200, ResponderBytes: 64000, SSLActualAction: Decrypt (Resign), '
               'SSLFlowStatus: Success, SSLServerName: www.example.com, SSLVersion: TLSv1.3, '
               'URLCategory: Business and Economy', 33)
i = isemon.ftd_record_from(IPS).facts
ok('an intrusion: the rule, what it is, how bad, and that it was blocked',
   (i['sub'], i['verdict'], i['fields']['signature'], i['cat'], i['fields']['priority']),
   ('ips', 'block', '1:58722:3', 'Attempted Administrator Privilege Gain', '1'))
mw = isemon.ftd_record_from(MAL).facts
ok('malware the file policy blocked, by name',
   (mw['sub'], mw['verdict'], mw['cat'], mw['host']),
   ('malware', 'block', 'W32.Example.Trojan', 'bad.example.net'))
si = isemon.ftd_record_from(SI).facts
ok('an address on a Security Intelligence feed, blocked',
   (si['sub'], si['verdict'], si['fields']['si']), ('si', 'block', 'Malware'))
se = isemon.ftd_record_from(SSLE).facts
ok('a session the decryption policy resigned: both directions\' bytes and the server\'s name',
   (se['sub'], se['fields']['ssl'], se['host'], se['sent'], se['rcvd'], se['cat']),
   ('ssl', 'decrypt (resign)', 'www.example.com', 1200, 64000, 'Business and Economy'))
dims = dict(isemon.Storage.fw_dims(i))
ok('each of them is a card of its own', ('ips' in dims, 'malware' in dict(
   isemon.Storage.fw_dims(mw)), 'si' in dict(isemon.Storage.fw_dims(si)),
   'ssl' in dict(isemon.Storage.fw_dims(se))), (True, True, True, True))
folder, store, daemon = fresh()
facts = [isemon.ftd_record_from(TEAR).facts, isemon.ftd_record_from(SSLE).facts]
for one in facts:
    one['fw'] = 'hq'
store.note_fw_events(facts)
ok('where the firewall writes its own session end as well, a session is counted once',
   store.fw_summary(time.time() - 7200, fw='hq')['totals']['allow']['n'], 1)

title('Cards only FTD fills')
dims = lambda text: dict(isemon.Storage.fw_dims(isemon.ftd_record_from(text).facts))  # noqa
ok('what was dropped on the way, and why', dims(NOCONN).get('drop'), 'stray \u00b7 RST')
ok('the unit that wrote it', dims(TEAR).get('unit'), 'fw1.example.cz')
ok('a site-to-site peer, by its address', dims(IKE).get('peer'), '192.0.2.35')
ok('VPN sessions by person, with their bytes',
   (dims(GONE).get('vpnuser'), isemon.fw_carried(isemon.ftd_record_from(GONE).facts)),
   ('jnovak', (723879244, 128915865, 1)))
FAIL_OVER = line(2, '%FTD-1-105005: (Primary) Lost Failover communications with mate on '
                    'interface OUTSIDE-IPv6', 40)
ok('failover, by what was said and on which interface', dims(FAIL_OVER).get('ha'),
   'Failover: lost contact with the other unit \u00b7 OUTSIDE-IPv6')
ok('the page draws them, and the connections each unit has open',
   all(x in PAGE_SRC for x in ("dim: 'drop'", "dim: 'peer'", "dim: 'vpnuser'", "dim: 'ha'",
                               "dim: 'threat'", "dim: 'unit'", "'Connections open'")), True)

title('A page of the Traffic tab for each part of the log, for every kind of firewall')
area = lambda text: isemon.fw_area(isemon.ftd_record_from(text).facts)   # noqa: E731
ok('sessions, refusals and drops are the sessions\' page',
   (area(TEAR), area(ACL), area(NOCONN)), ('session', 'session', 'session'))
ok('AnyConnect and its refused sign-ins are the client VPN',
   (area(GONE), area(AAA), area(WEBVPN), area(UAUTH)), ('client-vpn',) * 4)
ok('IKE is the site-to-site VPN', area(IKE), 's2s-vpn')
ok('intrusions, malware and files are the threats', (area(IPS), area(MAL), area(FILE)),
   ('threat', 'threat', 'threat'))
ok('an administrator\'s command is the administrators\'',
   area(line(1, "%FTD-5-111008: User 'admin1' executed the 'write memory' command.")),
   'admin')
ok('failover is the firewall itself', area(FAIL_OVER), 'system')
fg = lambda **f: isemon.fw_area(dict({'type': 'event', 'sub': 'vpn', 'action': '',
                                      'fields': {}}, **f))   # noqa: E731
ok('a FortiGate\'s SSL VPN is the client VPN',
   fg(fields={'tunneltype': 'ssl-web'}, action='ssl-login-fail'), 'client-vpn')
ok('...its IPsec tunnels the site-to-site VPN', fg(action='tunnel-up',
                                                   fields={'tunneltype': 'ipsec'}), 's2s-vpn')
ok('...FortiClient over IPsec, a person, the client VPN',
   fg(action='tunnel-up', fields={'tunneltype': 'ipsec', 'xauthuser': 'jnovak'}),
   'client-vpn')
ok('...an administrator changing a setting the administrators\'',
   fg(sub='system', action='Edit', fields={'ui': 'GUI(10.1.2.9)'}), 'admin')
folder, store, daemon = fresh()
facts = [isemon.ftd_record_from(x).facts for x in (TEAR, GONE, IKE, IPS)]
for one in facts:
    one['fw'] = 'hq'
store.note_fw_events(facts)
ok('each page lists only its own lines',
   [store.fw_rows(since=0, area=a)[1] for a in ('session', 'client-vpn', 's2s-vpn', 'threat',
                                                 'admin')], [1, 1, 1, 1, 0])
db = store.db
db.execute("UPDATE fw_events SET area = NULL")
db.commit() if hasattr(db, 'commit') else None
ok('a line written before there were pages is on its page by its kind',
   store.fw_rows(since=0, area='session')[1], 1)
store.set_meta('mended_fw_areas', '')
store.mend_fw_areas()
ok('...and the firewall\'s own lines are put on theirs once',
   (store.fw_rows(since=0, area='client-vpn')[1], store.fw_rows(since=0, area='s2s-vpn')[1]),
   (1, 1))
ok('the pages are counted, for the numbers on their buttons',
   sorted(r['val'] for r in store.fw_summary(time.time() - 7200)['tops']['area']['busiest']),
   ['client-vpn', 's2s-vpn', 'session', 'threat'])

title('SIP pinholes and a VPN session that drops')
sip = isemon.ftd_record_from('Oct  1 18:24:01 ftd1.example.cz %FTD-6-607001: Pre-allocate SIP Via '
                             'UDP secondary channel for VOICE:192.0.2.21/5060 to MGMT:198.51.100.55 '
                             'from REGISTER message').facts
ok('a SIP pinhole whose far end has no port keeps both addresses',
   (sip['srcintf'], sip['srcip'], sip['srcport'], sip['dstintf'], sip['dstip'], sip['proto']),
   ('VOICE', '192.0.2.21', 5060, 'MGMT', '198.51.100.55', 17))
lost = isemon.ftd_record_from('Oct  1 19:23:13 ftd1.example.cz %FTD-6-716058: Group <AC_USERS> '
                              'User <jnovak> IP <9.9.9.9> AnyConnect session lost connection. '
                              'Waiting to resume.').facts
back = isemon.ftd_record_from('Oct  1 19:23:43 ftd1.example.cz %FTD-6-716059: Group <AC_USERS> '
                              'User <jnovak> IP <9.9.9.9> AnyConnect session resumed. Connection '
                              'from IP <9.9.9.9>.').facts
ok('a session that lost its connection is said so, on the Client VPN page',
   (lost['action'], lost['user'], isemon.fw_area(lost), isemon.FTD_DESC['716058'] != ''),
   ('session-lost', 'jnovak', 'client-vpn', True))
ok('...and one that came back', (back['action'], isemon.fw_area(back)),
   ('session-resumed', 'client-vpn'))
ok('...both are words on the page', "'session-lost':" in PAGE_SRC and "'session-resumed':" in PAGE_SRC,
   True)
ok('the firewall switch and the time window wrap together', '<span class="t-right">' in PAGE_SRC,
   True)

title('Other: what fits no page')
odd = isemon.ftd_record_from('Oct  1 19:30:00 ftd1.example.cz %FTD-5-999123: Something this '
                             'version has never heard of').facts
ok('an FTD message nobody here knows is on Other', isemon.fw_area(odd), 'other')
ok('...one it does know about itself is still on The firewall',
   isemon.fw_area(isemon.ftd_record_from('Oct  1 19:30:00 ftd1.example.cz %FTD-5-317077: '
                                         'Added route 192.0.2.0 255.255.255.0').facts), 'system')
ok('...a kind of line no parser here knows is on Other',
   isemon.fw_area({'type': 'odd', 'sub': 'x', 'fields': {}}), 'other')
ok('...a FortiGate event about itself is not', isemon.fw_area(
    {'type': 'event', 'sub': 'system', 'action': 'connect', 'fields': {'logdesc': 'x'}}), 'system')
odd['fw'] = 'hq'
store.note_fw_events([odd])
oid = store.db.execute("SELECT ident FROM fw_events WHERE area = 'other'").fetchall()[0]['ident']
store.db.execute("UPDATE fw_events SET area = 'system' WHERE ident = ?", (oid,))
store.db.commit() if hasattr(store.db, 'commit') else None
store.set_meta('mended_fw_other', '')
ok('a line put on The firewall before there was Other is moved there once',
   (store.mend_fw_other(), store.fw_rows(since=0, area='other')[1], store.mend_fw_other()), (1, 1, 0))
ok('...the page has Other, shown only where there is any, and no Everything button',
   'data-page="other" aria-selected="false" hidden' in PAGE_SRC
   and '<span>Everything</span>' not in PAGE_SRC and "areas.other ||" in PAGE_SRC, True)

title('More out of each line (1.10.128)')
def facts(line):
    return isemon.ftd_record_from(line).facts
def dims(f):
    return dict((d, v) for d, v in isemon.Storage.fw_dims(f))
box = facts('Oct  1 18:24:01 ftd1.example.cz %FTD-3-710003: TCP access denied by ACL from '
            '192.0.2.1/38912 to INTERNET:198.51.100.7/80')
ok('a refusal to the box itself keeps where it was going', (box['dstip'], box['dstport']),
   ('198.51.100.7', 80))
acc = facts('Oct  1 18:24:01 ftd1.example.cz %FTD-6-113004: AAA user accounting Successful : '
            'server =  192.0.2.9 : user = jnovak')
ok('accounting with two spaces before the server is read', (acc['user'], acc['dstip']),
   ('jnovak', '192.0.2.9'))
loc = facts('Oct  1 18:24:01 ftd1.example.cz %FTD-6-113015: AAA user authentication Rejected : '
            'reason = User was not found : local database : user = ***** : user IP = 9.9.9.9')
ok('...a refusal by the local database says so', loc['fields']['server'], 'local database')
ts = facts('Oct  1 18:24:03 ftd1.example.cz %FTD-3-751022: Local:192.0.2.2:500 '
           'Remote:198.51.100.153:500 Username:198.51.100.153 IKEv2 Tunnel rejected: Crypto Map '
           'Policy not found for remote traffic selector 10.1.192.36/10.1.192.36/0/65535/0 local '
           'traffic selector 192.0.2.41/192.0.2.41/0/65535/0!')
ok('a tunnel refused for its networks says why, which networks, and what that means',
   (ts['fields']['reason'], ts['fields']['remote_ts'], ts['fields']['local_ts'],
    ts['fields']['meaning'], 'group' in ts['fields']),
   ('Crypto Map Policy not found', '10.1.192.36', '192.0.2.41',
    'the two sides ask for different networks', False))
ok('...and is counted on the card of why tunnels fail', dims(ts).get('s2swhy'),
   'Crypto Map Policy not found \u2014 the two sides ask for different networks')
db_ = facts('Oct  1 18:24:03 ftd1.example.cz %FTD-5-750003: Local:192.0.2.2:500 '
            'Remote:198.51.100.153:500 Username:DefaultLNLGroup IKEv2 Negotiation aborted due '
            'to ERROR: Failed to locate an item in the database')
ok('...a peer no tunnel is set up for', (db_['fields']['reason'], db_['fields']['meaning']),
   ('Failed to locate an item in the database', 'no tunnel is set up for this peer'))
sel = facts('Oct  1 18:24:03 ftd1.example.cz %FTD-5-750001: Local:192.0.2.2:500 '
            'Remote:198.51.100.153:500 Username:Unknown IKEv2 Received request to establish an '
            'IPsec tunnel; local traffic selector = Address Range: 10.0.0.1-10.0.0.1 Protocol: 0 '
            'Port Range: 0-65535 ; remote traffic selector = Address Range: 10.9.0.0-10.9.255.255 '
            'Protocol: 0 Port Range: 0-65535 ')
ok('...the networks asked for when a tunnel is negotiated',
   (sel['fields']['local_ts'], sel['fields']['remote_ts']), ('10.0.0.1', '10.9.0.0-10.9.255.255'))
vti = facts('Oct  1 18:24:59 ftd1.example.cz %FTD-4-752012: IKEv2 was unsuccessful at setting up '
            'a tunnel.  Map Tag = __vti-crypto-map-38-0-200.  Map Sequence Number = 65280.')
ok('...a tunnel manager failure names the tunnel and why',
   (vti['fields']['vpntunnel'], vti['fields']['reason']),
   ('__vti-crypto-map-38-0-200', 'IKEv2 was unsuccessful at setting up a tunnel'))
end = facts('Oct  1 18:42:28 ftd1.example.cz %FTD-4-722037: Group <AC_USERS> User <jnovak> IP '
            '<9.9.9.9> SVC closing connection: DPD failure.')
said = facts('Oct  1 18:42:28 ftd1.example.cz %FTD-5-722012: Group <AC_USERS> User <jnovak> IP '
             '<9.9.9.9> SVC Message: 16/NOTICE: Client PC is shutting down..')
ok('a VPN connection dropped, and what the client said on its way out',
   (end['action'], end['fields']['reason'], dims(end).get('vpndrop'),
    said['action'], said['fields']['reason']),
   ('closing', 'DPD failure', 'DPD failure', 'client-said', 'Client PC is shutting down'))
gone = facts('Oct  1 18:42:28 ftd1.example.cz %FTD-6-113019: Group = AC_USERS, Username = jnovak, '
             'IP = 9.9.9.9, Session disconnected. Session Type: SSL, Duration: 1h:02m:03s, '
             'Bytes xmt: 1000, Bytes rcv: 2000, Reason: Idle Timeout')
ok('...how a VPN session ended is a card', dims(gone).get('vpnend'), 'Idle Timeout')
big = facts('Oct  1 18:42:28 ftd1.example.cz %FTD-3-722035: Group <AC_USERS> User <jnovak> IP '
            '<9.9.9.9> Received large packet 1550 (threshold 1390).')
ok('a packet too large for the tunnel, by person, with its size',
   dims(big).get('mtu'), 'jnovak \u00b7 1550 > 1390')
dacl = facts("Oct  1 18:24:01 ftd1.example.cz %FTD-4-106103: access-list "
             "#ACSACL#-IP-AnyConnect_DEMO-5f3e2a1b denied tcp for user 'jnovak' "
             "INTERNET/10.9.9.9(5555) -> SERVERS/192.0.2.5(443) hit-cnt 1 first hit [0x1, 0x0]")
ok('a refusal by a downloadable ACL, by its ISE name and the person',
   dims(dacl).get('dacl'), 'AnyConnect_DEMO \u00b7 jnovak')
dns = facts('Oct  1 18:39:50 ftd1.example.cz %FTD-3-746016: user-identity: DNS lookup for '
            'update.example.com failed, reason:Timeout or unresolvable')
ok('a name the firewall cannot resolve', (dns['host'], dns['fields']['reason'],
                                          dims(dns).get('dnsfail'), isemon.fw_area(dns)),
   ('update.example.com', 'Timeout or unresolvable', 'update.example.com', 'system'))
route = facts('Oct  1 18:39:50 ftd1.example.cz %FTD-6-317078: Deleted STATIC route 192.0.2.0 '
              '255.255.255.0 via 198.51.100.1 [1/0] on [INTERNET] [Po1.901] tableid [0]')
ok('a route taken out, by network and gateway',
   (route['action'], route['fields']['route'], route['dstintf'], dims(route).get('route')),
   ('route-removed', '192.0.2.0/24', 'INTERNET', '192.0.2.0/24 via 198.51.100.1'))
rad = facts('Oct  1 18:39:50 ftd1.example.cz %FTD-6-324303: Server=<192.0.2.10:1812>, ID=<0x85>: '
            'The RADIUS server supports and included the Message-Authenticator payload.')
ok('RADIUS advice names the server', (rad['dstip'], rad['dstport'], rad['srcip']),
   ('192.0.2.10', 1812, ''))
cmd = facts("Oct  1 18:39:50 ftd1.example.cz %FTD-5-111008: User 'jnovak' executed the "
            "'show running-config' command.")
ok('an administrator is a card of their own', dims(cmd).get('admin'), 'jnovak')
for one in (ts, end, gone, big, dacl, dns, route, cmd):
    one['fw'] = 'hq'
    one['ts'] = time.time() - 60
store.note_fw_events([ts, end, gone, big, dacl, dns, route, cmd])
tops = store.fw_summary(time.time() - 7200)['tops']
ok('the overview counts every new card',
   sorted(d for d in ('s2swhy', 'vpnend', 'vpndrop', 'mtu', 'dacl', 'dnsfail', 'route', 'admin')
          if (tops.get(d) or {}).get('busiest')),
   sorted(['s2swhy', 'vpnend', 'vpndrop', 'mtu', 'dacl', 'dnsfail', 'route', 'admin']))
ok('...the page draws them, on the overview only',
   all(("dim: '%s'" % d) in PAGE_SRC for d in ('vpnend', 'vpndrop', 'mtu', 'dacl', 's2swhy',
                                                 'admin', 'dnsfail', 'route'))
   and 'function drawPageCards' not in PAGE_SRC and 't-page-cards' not in PAGE_SRC, True)

title('Connected now (1.10.129)')
def vrow(line, fw='hq', at=None):
    f = isemon.ftd_record_from(line).facts
    f['fw'] = fw
    if at is not None:
        f['ts'] = at
    f['area'] = isemon.fw_area(f)
    return f
T0 = time.time() - 3600
G = 'Oct  1 18:24:01 ftd1.example.cz '
seq = [
    vrow(G + '%FTD-6-113009: AAA retrieved default group policy (GP_USERS) for user = jnovak', at=T0),
    vrow(G + '%FTD-6-734001: DAP: User jnovak, Addr 9.9.9.9, Connection AnyConnect: The following '
         'DAP records were selected for this connection: DAP_Win', at=T0 + 1),
    vrow(G + '%FTD-6-113039: Group <AC_USERS> User <jnovak> IP <9.9.9.9> AnyConnect parent '
         'session started.', at=T0 + 2),
    vrow(G + '%FTD-4-722051: Group <AC_USERS> User <jnovak> IP <9.9.9.9> IPv4 Address '
         '<10.255.0.7> IPv6 address <::> assigned to session', at=T0 + 3),
    vrow(G + '%FTD-5-722055: Group <AC_USERS> User <jnovak> IP <9.9.9.9> Client Type: Cisco '
         'AnyConnect VPN Agent for Windows 5.1.8.122', at=T0 + 3),
    vrow(G + '%FTD-4-722037: Group <AC_USERS> User <jnovak> IP <9.9.9.9> SVC closing '
         'connection: DPD failure.', at=T0 + 600),
    # a second person, whose session ends, and whose last lines of that same
    # second come back after the end
    vrow(G + '%FTD-6-113039: Group <AC_USERS> User <mkral> IP <9.9.9.10> AnyConnect parent '
         'session started.', at=T0 + 5),
    vrow(G + '%FTD-4-113019: Group = AC_USERS, Username = mkral, IP = 9.9.9.10, Session '
         'disconnected. Session Type: AnyConnect-Parent, Duration: 0h:10m:00s, Bytes xmt: 100, '
         'Bytes rcv: 200, Reason: User Requested', at=T0 + 605),
    vrow(G + '%FTD-4-722037: Group <AC_USERS> User <mkral> IP <9.9.9.10> SVC closing '
         'connection: User Requested.', at=T0 + 605),
    # a tunnel known only by its SAs, and one whose SAs were all deleted
    vrow(G + '%FTD-6-602303: IPSEC: An outbound LAN-to-LAN SA (SPI= 0xAAAA0001) between '
         '192.0.2.2 and 198.51.100.7 (user= 198.51.100.7) has been created.', at=T0 + 10),
    vrow(G + '%FTD-6-602303: IPSEC: An inbound LAN-to-LAN SA (SPI= 0xAAAA0002) between '
         '198.51.100.7 and 192.0.2.2 (user= 198.51.100.7) has been created.', at=T0 + 10),
    vrow(G + '%FTD-5-750001: Local:192.0.2.2:500 Remote:198.51.100.7:500 Username:198.51.100.7 '
         'IKEv2 Received request to establish an IPsec tunnel; local traffic selector = Address '
         'Range: 10.0.0.0-10.0.0.255 Protocol: 0 Port Range: 0-65535 ; remote traffic selector = '
         'Address Range: 10.9.0.0-10.9.0.255 Protocol: 0 Port Range: 0-65535 ', at=T0 + 11),
    vrow(G + '%FTD-5-750006: Local:192.0.2.2:500 Remote:198.51.100.7:500 Username:198.51.100.7 '
         'IKEv2 SA UP. Reason: Parent SA Rekeyed', at=T0 + 12),
    vrow(G + '%FTD-6-602303: IPSEC: An outbound LAN-to-LAN SA (SPI= 0xBBBB0001) between '
         '192.0.2.2 and 198.51.100.8 (user= 198.51.100.8) has been created.', at=T0 + 20),
    vrow(G + '%FTD-6-602304: IPSEC: An outbound LAN-to-LAN SA (SPI= 0xBBBB0001) between '
         '192.0.2.2 and 198.51.100.8 (user= 198.51.100.8) has been deleted.', at=T0 + 30),
]
for one in seq:
    one['user'] = one.get('user') or ''
now_ = isemon.fw_vpn_fold(sorted(seq, key=lambda r: r['ts']), now=T0 + 3600)
people = dict((c['user'], c) for c in now_['clients'])
ok('who is connected: a session begun and not ended', sorted(people), ['jnovak'])
c = people.get('jnovak', {})
ok('...with everything its lines said, the policy and DAP said before it began included',
   (c.get('srcip'), c.get('inner'), c.get('group'), c.get('group_policy'), c.get('dap'),
    c.get('since_known'), c.get('drops'), 'Windows' in c.get('client', '')),
   ('9.9.9.9', '10.255.0.7', 'AC_USERS', 'GP_USERS', 'DAP_Win', True, 1, True))
ok('...a session that ended is not, even with lines of the same second after its end',
   now_['ended_clients'], 1)
tun = dict((t['peer'], t) for t in now_['tunnels'])
ok('a tunnel up by its SAs, with the networks it asked for, since "at least"',
   (sorted(tun), tun['198.51.100.7']['since_known'], len(tun['198.51.100.7']['sas']),
    tun['198.51.100.7']['remote_ts'], tun['198.51.100.7']['ike']),
   (['198.51.100.7'], False, 2, '10.9.0.0-10.9.0.255', 'IKEv2'))
ok('...a tunnel whose SAs were all deleted is not up', '198.51.100.8' in tun, False)
fg = isemon.fg_record_from(
    'date=2026-10-01 time=10:01:13 devname="FG-1" devid="FGT0000000000000" '
    'eventtime=%d000000000 tz="+0000" logid="0101039949" type="event" subtype="vpn" '
    'level="information" vd="root" logdesc="SSL VPN statistics" action="tunnel-stats" '
    'tunneltype="ssl-tunnel" tunnelid=42 remip=9.9.9.11 tunnelip=10.212.134.200 '
    'user="pdvorak" group="VPN_Users" dst_host="N/A" nextstat=600 duration=4800 '
    'sentbyte=1000 rcvdbyte=2000 msg="SSL tunnel statistics"' % int(T0)).facts
fg['fw'], fg['area'] = 'branch', isemon.fw_area(fg)
fgnow = isemon.fw_vpn_fold([fg], now=T0 + 60)
ok('FortiGate: a session counted by its statistics, since its own duration says',
   [(x['user'], x['inner'], x['since_known'], int(T0 - x['started']), x['quiet'])
    for x in fgnow['clients']], [('pdvorak', '10.212.134.200', True, 4800, False)])
ok('...and gone quiet three statistics later', isemon.fw_vpn_fold([fg], now=T0 + 3600)
   ['clients'][0]['quiet'], True)
ok('a traffic selector as a range of addresses, every address as none',
   (isemon.fw_selector_net('10.9.0.0-10.9.0.255') is not None,
    isemon.fw_selector_net('0.0.0.0-255.255.255.255'), isemon.fw_selector_net('')),
   (True, None, None))
for one in seq:
    one.pop('area', None)
store.note_fw_events(seq)
rows = store.fw_vpn_rows(T0 - 60)
ok('the database gives back the VPN lines, not the session lines', 
   (len(rows) >= 14, all(r['area'] in ('client-vpn', 's2s-vpn') for r in rows)), (True, True))
ok('the page has the page and its popups',
   all(x in PAGE_SRC for x in ('data-page="vpn"', 'id="t-page-vpn"', 'function drawVpnNow',
                               'function drawVpnClient', 'function drawVpnTunnel',
                               "'fw-vpn'    => '/api/fw/vpn'")), True)
for l, want in (('%FTD-4-411002: Line protocol on Interface Ethernet1/3, changed state to down',
                 ('link-down', 'Ethernet1/3 \u00b7 down')),
                ("%FTD-1-321001: Resource 'conns' limit of 10000 reached for system",
                 ('limit', 'conns (10000)'))):
    f = isemon.ftd_record_from(G + l).facts
    d = dict(isemon.Storage.fw_dims(f))
    ok('a new message id is read and counted: ' + l.split(':')[0],
       (f['action'], d.get('link') or d.get('limit')), want)
nat = isemon.ftd_record_from(G + '%FTD-3-202010: NAT pool exhausted. Unable to create TCP '
                             'connection from inside:10.1.1.1/1234 to outside:198.51.100.2/80').facts
ok('...a NAT pool exhausted is a session that could not be made',
   (nat['type'], nat['verdict'], nat['srcip'], nat['dstip'], nat['dstport']),
   ('traffic', 'deny', '10.1.1.1', '198.51.100.2', 80))

title('The address pools and a session begun with the new ids')
T1 = time.time() - 1800
H = 'Oct  1 18:24:01 ftd1.example.cz '
chain = [
    vrow(H + "%FTD-6-737006: IPAA: Session=0x5b6f4000, Local pool request succeeded for "
         "tunnel-group 'AC_ADM'", at=T1),
    vrow(H + '%FTD-6-737026: IPAA: Session=0x5b6f4000, Client assigned 10.255.1.9 from local '
         'pool ADM_POOL', at=T1 + 1),
    vrow(H + '%FTD-5-109201: UAUTH: Session=0x5b6f4000, user = pdvorak, Assigned IP=10.255.1.9, '
         'Succeeded adding entry.', at=T1 + 1),
    vrow(H + '%FTD-6-113009: AAA retrieved default group policy (GP_ADM) for user = pdvorak',
         at=T1 + 1),
    vrow(H + '%FTD-6-113039: Group <AC_ADM> User <pdvorak> IP <9.9.9.12> AnyConnect parent '
         'session started.', at=T1 + 2),
    vrow(H + '%FTD-5-722033: Group <AC_ADM> User <pdvorak> IP <9.9.9.12> First UDP SVC '
         'connection established for SVC session.', at=T1 + 3),
    vrow(H + '%FTD-4-722041: TunnelGroup <AC_ADM> GroupPolicy <GP_ADM> User <pdvorak> IP '
         '<9.9.9.12> No IPv6 address available for SVC connection', at=T1 + 3),
    vrow(H + '%FTD-5-750001: Local:192.0.2.2:500 Remote:198.51.100.9:500 Username:198.51.100.9 '
         'IKEv2 Received request to rekey an IPsec tunnel; local traffic selector = Address '
         'Range: 10.0.1.0-10.0.1.255 Protocol: 0 Port Range: 0-65535; remote traffic selector = '
         'Address Range: 10.9.1.0-10.9.1.255 Protocol: 0 Port Range: 0-65535', at=T1 + 4),
    vrow(H + '%FTD-5-750001: Local:192.0.2.2:500 Remote:198.51.100.9:500 Username:198.51.100.9 '
         'IKEv2 Received request to rekey an IPsec tunnel; local traffic selector = Address '
         'Range: 10.0.2.0-10.0.2.255 Protocol: 0 Port Range: 0-65535; remote traffic selector = '
         'Address Range: 10.9.2.0-10.9.2.255 Protocol: 0 Port Range: 0-65535', at=T1 + 5),
    vrow(H + '%FTD-6-602303: IPSEC: An inbound LAN-to-LAN SA (SPI= 0xCCCC0001) between '
         '198.51.100.9 and 192.0.2.2 (user= 198.51.100.9) has been created.', at=T1 + 6),
]
for one in chain:
    one['user'] = one.get('user') or ''
got = isemon.fw_vpn_fold(chain, now=T1 + 60)
pd = [c for c in got['clients'] if c['user'] == 'pdvorak']
ok('a session told by its address pool, its handle and its start: one session, all of it',
   [(c['srcip'], c['inner'], c['pool'], c['group_policy'], c['group'], c['since_known'],
     c.get('dtls')) for c in pd],
   [('9.9.9.12', '10.255.1.9', 'ADM_POOL', 'GP_ADM', 'AC_ADM', True, True)])
tn = [t for t in got['tunnels'] if t['peer'] == '198.51.100.9']
ok('a tunnel rekeyed for two pairs of networks lists both',
   [[(x['local'], x['remote']) for x in t['selectors']] for t in tn],
   [[('10.0.2.0-10.0.2.255', '10.9.2.0-10.9.2.255'),
     ('10.0.1.0-10.0.1.255', '10.9.1.0-10.9.1.255')]])
w = isemon.ftd_record_from(H + '%FTD-6-721016: (WebVPN-Primary) WebVPN session for client user '
                           'pdvorak, IPv4 9.9.9.12 has been created.').facts
ok('a WebVPN session created starts a session', (w['action'], w['user'], w['srcip']),
   ('login', 'pdvorak', '9.9.9.12'))

title('Commands on the firewall, and a deployment (1.10.131)')
seen_ = {}
C = 'Oct  1 21:11:12 ftd1.example.cz '
def cmd(line):
    return isemon.ftd_record_from(C + line, None, seen_).facts
c1 = cmd("%FTD-5-111010: User 'Config', running 'N/A' from IP 192.0.2.40, executed 'access-list "
         "#ACSACL#-IP-AnyConnect_DEMO-6a144957 extended permit udp any4 host 10.1.1.1 eq domain'")
ok('a command that changed the configuration: who, from where, which part',
   (c1['action'], c1['user'], c1['srcip'], c1['fields']['section'], isemon.fw_area(c1),
    dict(isemon.Storage.fw_dims(c1)).get('cfg')),
   ('config', 'Config', '192.0.2.40', 'access-list (dACL) AnyConnect_DEMO', 'admin',
    'access-list (dACL) AnyConnect_DEMO'))
c2 = cmd("%FTD-5-111008: User 'Config' executed the 'access-list #ACSACL#-IP-AnyConnect_DEMO-6a144957 "
         "extended permit udp any4 host 10.1.1.1 eq domain' command.")
ok('...its twin without the address is not kept a second time, nor taken for coming from '
   'the address in the command', (c2['fields'].get('_count'), c2['srcip']), ('0', ''))
ok('...a command that only looked is not a change, saving is said as saving',
   [cmd("%FTD-5-111010: User 'enable_1', running 'N/A' from IP 192.0.2.40, executed '" + x + "'")
    ['action'] for x in ('show running-config', 'more system:running-config', 'write memory',
                          'group-policy GP_X attributes')],
   ['command', 'command', 'config-save', 'config'])
ok('...which part of the configuration, in a word or three',
   [isemon.ftd_cmd_section(x)[1] for x in ('ipv6 icmp permit any 128 DMZ',
                                            'no object network OBJ-1', 'vpn-idle-timeout 30',
                                            'tunnel-group 198.51.100.7 ipsec-attributes',
                                            'ipv6 ipv6 icmp permit any 128 VRF-X')],
   ['ipv6 icmp permit', 'object network OBJ-1', 'vpn-idle-timeout', 'tunnel-group 198.51.100.7',
    'ipv6 icmp permit'])
dep = cmd('%FTD-5-199017: sudo:      root : PWD=/opt/cisco/csp/applications ; USER=root ; '
          'COMMAND=/usr/bin/nice -n -10 /ngfw/usr/local/sf/bin/policy_apply.pl '
          '/var/cisco/deploy/db/41/policy_deployment.db SIGNAL')
ok('a deployment step is the firewall itself, not an administrator',
   (dep['action'], dep['fields']['phase'], isemon.fw_area(dep)), ('deploy-step', 'SIGNAL', 'system'))
ssh = cmd('%FTD-5-199017: sshd[123]: Failed password for invalid user admin from 198.51.100.5 '
          'port 4000 ssh2')
ok('SSH to the box refused names who tried and from where',
   (ssh['action'], ssh['verdict'], ssh['user'], ssh['srcip'], isemon.fw_area(ssh)),
   ('login-fail', 'fail', 'admin', '198.51.100.5', 'admin'))
ok('the configuration changed is a card, offered to the search and the box at the top',
   ("dim: 'cfg'" in PAGE_SRC, isemon.Storage.FW_SUGGEST_DIMS.get('section')), (True, ('cfg',)))

title('A firewall writing its clock in UTC (1.10.132)')
ok('a firewall may be given the zone of its clock',
   [x['zone'] for x in isemon.fw_sources_checked(
       [{'name': 'a', 'type': 'ftd', 'path': '/x', 'zone': 'UTC'}, {'name': 'b', 'path': '/y'}])],
   ['UTC', ''])
try:
    isemon.fw_sources_checked([{'name': 'a', 'type': 'ftd', 'path': '/x', 'zone': 'Mars/Base'}])
    bad = None
except ValueError as e:
    bad = str(e)
ok('...and a zone nobody knows is refused, naming it', 'Mars/Base' in (bad or ''), True)
L = 'Oct  1 22:00:54 ftd1.example.cz %FTD-6-302014: Teardown TCP connection 1 for A:192.0.2.1/1 to B:198.51.100.1/2 duration 0:00:01 bytes 10 TCP FINs'
isemon._READING_IN.zone = None
here = isemon.ftd_record_from(L).ts
isemon._READING_IN.zone = 'UTC'
utc = isemon.ftd_record_from(L).ts
isemon._READING_IN.zone = None
import datetime as _dt
off = _dt.datetime.fromtimestamp(here).astimezone().utcoffset().total_seconds()
ok('the same line read in UTC is that many hours later than read here, cached apart',
   round(utc - here), round(off))
lagd = isemon.Daemon.__new__(isemon.Daemon)
lagd._fw_hours, lagd._fw_fresh = {}, {}
for _ in range(isemon.Daemon.FW_LAG_PASSES):
    lagd._fw_fresh = {'hq-ftd': 2 * 3600 + 40, 'branch': 3}
    lagd.note_fw_clocks()
ok('lines arriving two whole hours late, pass after pass, are said - and only for that one',
   (sorted(lagd.fw_lags()), '2 h' in lagd.fw_lags().get('hq-ftd', '')), (['hq-ftd'], True))
lagd._fw_fresh = {'hq-ftd': 5}
lagd.note_fw_clocks()
ok('...and no longer once they arrive on time', lagd.fw_lags(), {})
ok('the settings page has a column for it, and says why beside a firewall that is late',
   "'The zone of its clock'" in PAGE_SRC and 'fwsrc-lag' in PAGE_SRC, True)

title('AMP, tunnels started over, certificates, ARP (1.10.134)')
N = 'Oct  1 18:24:01 ftd1.example.cz '
def nf(line):
    return isemon.ftd_record_from(N + line).facts
def nd(f):
    return dict(isemon.Storage.fw_dims(f))
amp = nf(' : %FTD-6-430004: DeviceUUID: x, InstanceID: 3, ConnectionID: 1, SrcIP: 10.1.1.56, '
         'DstIP: 198.51.100.205, SrcPort: 43126, DstPort: 80, Protocol: tcp, FileDirection: '
         'Download, FileAction: Malware Cloud Lookup, FileSHA256: 1fa6, SHA_Disposition: Unknown, '
         'FileName: setup.exe, FileType: MSEXE, FileSize: 23362, ApplicationProtocol: HTTP, '
         'User: Not Found, FilePolicy: FILE_X, FileSandboxStatus: Sent for Analysis, '
         'ThreatScore: 61, URI: http://dl.example.com/setup.exe')
ok('AMP: a file sent to the sandbox, with its score, and a program nobody knows',
   (nd(amp).get('sandbox'), nd(amp).get('ampnew')),
   ('Sent for Analysis \u00b7 score 61 \u00b7 setup.exe', 'setup.exe \u00b7 dl.example.com'))
cab = dict(amp['fields'], FileType='MSCAB')
ok('...a Windows Update cabinet nobody has a verdict on is not one',
   'ampnew' in nd(dict(amp, fields=cab)), False)
rs = nf('%FTD-4-750014: Local:192.0.2.2:500 Remote:198.51.100.90:500 Username:198.51.100.90 '
        'IKEv2 Session Aborted. Reason: Initial contact received for Local ID: 192.0.2.2, '
        'Remote ID: 198.51.100.90 from remote peer: 198.51.100.90:500 to 192.0.2.2:500')
ok('a tunnel started over by its peer is that, not a failure',
   (rs['action'], rs['verdict'], nd(rs).get('s2sevent')),
   ('tunnel-reset', 'info', '198.51.100.90 \u00b7 started over by the peer'))
cert = nf('%FTD-1-717055: The <ID> certificate in the trustpoint <vpn_example_2025> has expired. '
          'Expiration <00:59:59 CET Nov 27 2025> Subject Name <cn=vpn.example.cz,o=Example,c=CZ> '
          'Issuer Name <cn=Some CA,o=CA,c=NL> Serial Number <4CCF>')
ok('an expired certificate: which trustpoint, whose, by whom, when',
   (cert['fields']['trustpoint'], cert['fields']['subject'], cert['fields']['issuer'],
    nd(cert).get('cert')),
   ('vpn_example_2025', 'vpn.example.cz', 'Some CA',
    'vpn_example_2025 \u00b7 expired 00:59:59 CET Nov 27 2025'))
arp = nf('%FTD-4-405001: Received ARP request collision from 10.1.2.3/0012.0146.9eb6 on interface '
         'LAN with existing ARP entry 10.1.2.3/70ea.1a55.21bf')
ok('an ARP collision: the address, both MACs, the interface',
   (arp['srcip'], arp['fields']['mac'], arp['fields']['mac_before'], nd(arp).get('arp')),
   ('10.1.2.3', '0012.0146.9eb6', '70ea.1a55.21bf', '10.1.2.3 \u00b7 LAN'))
ftp = nf('%FTD-6-303002: FTP connection from USERS:10.1.2.4/38541 to SERVERS:10.1.9.9/21, user '
         'scan Stored file scan1.pdf')
ok('a file stored over FTP is a file that crossed, not one more session',
   (ftp['type'], ftp['fields']['ftp_file'], ftp['fields']['file'], isemon.fw_area(ftp)),
   ('utm', 'scan1.pdf', 'FTP stored \u00b7 PDF', 'threat'))
bad = nf('%FTD-5-500003: Bad TCP hdr length (hdrlen=28, pktlen=58) from 198.51.100.38/30120 to '
         '192.0.2.88/11440, flags: RST , on interface INTERNET')
ok('a bad TCP header and an over-long DNS answer are dropped on the way',
   (nd(bad).get('drop'), nd(nf('%FTD-4-410001: Dropped UDP DNS reply from INTERNET:198.51.100.1/53 '
                                'to DMZ:10.1.1.1/53; packet length 2000 bytes exceeds configured '
                                'limit of 512 bytes')).get('drop')),
   ('stray \u00b7 bad TCP header length', 'inspect \u00b7 DNS reply longer than allowed'))
T2 = time.time() - 900
story = [vrow(N + '%FTD-5-750006: Local:192.0.2.2:500 Remote:198.51.100.90:500 Username:198.51.100.90 '
              'IKEv2 SA UP. Reason: Parent SA Rekeyed', at=T2),
         vrow(N + '%FTD-4-750014: Local:192.0.2.2:500 Remote:198.51.100.90:500 Username:198.51.100.90 '
              'IKEv2 Session Aborted. Reason: Initial contact received for Local ID: 192.0.2.2', at=T2 + 60),
         vrow(N + '%FTD-5-750006: Local:192.0.2.2:500 Remote:198.51.100.90:500 Username:198.51.100.90 '
              'IKEv2 SA UP. Reason: New Connection Established', at=T2 + 61),
         vrow(N + '%FTD-6-602303: IPSEC: An outbound LAN-to-LAN SA (SPI= 0xDDDD0001) between '
              '192.0.2.2 and 198.51.100.90 (user= 198.51.100.90) has been created.', at=T2 + 62)]
for one in story:
    one['user'] = ''
tt = isemon.fw_vpn_fold(story, now=T2 + 600)['tunnels']
ok('a tunnel\u2019s story: rekeyed, started over by the peer, up anew - and up since then',
   [([e['what'] for e in t['events']], t['resets'], t['since_known'], int(t['since'] - T2))
    for t in tt],
   [(['rekeyed', 'started over by the peer', 'came up'], 1, True, 61)])
ok('the page has the new cards and the tunnel\u2019s story',
   all(("dim: '%s'" % d) in PAGE_SRC for d in ('sandbox', 'ampnew', 's2sevent', 'cert', 'arp'))
   and "'What happened to it'" in PAGE_SRC, True)

title('Settings and the page')
ok('FTD is a kind of firewall the settings offer', 'ftd' in isemon.FW_TYPES, True)
ok('...the editor gives a firewall several folders',
   'fwsrc-paths' in PAGE_SRC and 'Another folder for the same firewall' in PAGE_SRC, True)
ok('...the page shows FTD\'s bytes as both ways', "'⇅ ' + bytes(r.sent)" in PAGE_SRC, True)
ok('...and a person looked up shows the firewall', "'On the firewall: '" in PAGE_SRC, True)

title('Names of addresses on the rows (1.10.137)')
ok('a row\u2019s address has its reverse-zone name written above it, where the firewall '
   'named no host itself - FTD as FortiGate',
   'function ptrInline(' in PAGE_SRC and "said.dataset.ptrinline = '1'" in PAGE_SRC
   and 'ptrInline(node, got.name);' in PAGE_SRC
   and "if (had && !had.classList.contains('t-ptr')) return;" in PAGE_SRC, True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
