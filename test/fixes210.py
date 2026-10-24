#!/usr/bin/env python3
"""1.10.210: the NAT page for a FortiGate and an FTD as well - every session
that was translated, with what its source was made, where its destination
was sent and the address it was asked at.

    ./test/fixes210.py
"""
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = Path(tempfile.mkdtemp(prefix='isemon-210-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'fwlog': 1,
                      'fwlog_sources': [{'name': 'fg', 'type': 'fortigate', 'path': str(folder),
                                         'files': '*.log'},
                                        {'name': 'ftd', 'type': 'ftd', 'path': str(folder),
                                         'files': '*.log'}]})
NOW = time.time()
AT = int(NOW - 300)
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(datetime.fromtimestamp(AT))


def fg(rest, ns):
    d = datetime.fromtimestamp(AT)
    return ('%s fw.example.net date=%s time=%s devname="FG-EX" devid="FGT00EXAMPLE0001" '
            'eventtime=%d%09d tz="+0200" ' % (STAMP, d.strftime('%Y-%m-%d'),
                                              d.strftime('%H:%M:%S'), AT, ns) + rest)


SNAT = fg('logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
          'srcip=192.168.90.134 srcport=63693 srcintf="VLAN91" srcintfrole="lan" '
          'dstip=37.157.6.230 dstport=443 dstintf="wan1" dstintfrole="wan" '
          'srccountry="Reserved" dstcountry="Denmark" sessionid=27040292 proto=6 '
          'action="client-rst" policyid=6 policytype="policy" policyname="LAN-WAN" '
          'service="HTTPS" trandisp="snat" transip=195.189.0.3 transport=63693 duration=5 '
          'sentbyte=172 rcvdbyte=88', 1)
DNAT = fg('logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
          'srcip=94.154.20.57 srcport=15023 srcintf="wan1" srcintfrole="wan" '
          'dstip=195.189.0.3 dstport=443 dstintf="DMZ" dstintfrole="dmz" '
          'srccountry="Poland" dstcountry="Czech Republic" sessionid=27040293 proto=6 '
          'action="close" policyid=9 policytype="policy" policyname="WAN-MAIL" '
          'service="HTTPS" trandisp="dnat" tranip=192.168.43.17 tranport=443 duration=5 '
          'sentbyte=172 rcvdbyte=88', 2)
NOOP = fg('logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
          'srcip=192.168.90.10 srcport=5000 srcintf="VLAN91" srcintfrole="lan" '
          'dstip=192.168.43.17 dstport=443 dstintf="DMZ" dstintfrole="dmz" '
          'srccountry="Reserved" dstcountry="Reserved" sessionid=27040294 proto=6 '
          'action="close" policyid=7 policytype="policy" policyname="LAN-DMZ" '
          'service="HTTPS" trandisp="noop" duration=5 sentbyte=172 rcvdbyte=88', 3)
H = '%s ftd1.example.net ' % STAMP
FTD = [H + '%FTD-6-302013: Built inbound TCP connection 4161323992 for INTERNET:2.57.17.200/22565 '
       '(2.57.17.200/22565) to VRF-MGMT:172.29.6.100/31398 (46.227.172.22/31398)',
       H + '%FTD-6-302014: Teardown TCP connection 4161323992 for INTERNET:2.57.17.200/22565 to '
       'VRF-MGMT:172.29.6.100/31398 duration 0:00:01 bytes 1232 TCP FINs from INTERNET',
       H + '%FTD-6-302013: Built inbound TCP connection 4161322496 for INETKU:172.29.200.181/47872 '
       '(46.227.172.21/47872) to INTERNET:104.18.32.177/443 (104.18.32.177/443)',
       H + '%FTD-6-302014: Teardown TCP connection 4161322496 for INETKU:172.29.200.181/47872 to '
       'INTERNET:104.18.32.177/443 duration 0:00:01 bytes 1232 TCP FINs from INETKU']

print('\nWhat a translation is, said one way for all three')
f = isemon.fg_parse_lines([DNAT], {}, NOW)[0].facts
ok('a FortiGate dst-nat: asked at the address it went to, sent to the server inside',
   isemon.fw_nat_said(f, f['fields']),
   {'natdst': '195.189.0.3:443', 'natto': '192.168.43.17:443', 'natkind': 'dst-nat'})
f = isemon.fg_parse_lines([SNAT], {}, NOW)[0].facts
ok('...a src-nat: what its source was made', isemon.fw_nat_said(f, f['fields']),
   {'natsrc': '195.189.0.3:63693', 'natkind': 'src-nat'})
f = isemon.fg_parse_lines([NOOP], {}, NOW)[0].facts
ok('...and one not translated is nothing', isemon.fw_nat_said(f, f['fields']), {})
ok('an FTD writes the destination the other way round, and it is said the same',
   isemon.fw_nat_said({'dstip': '172.29.6.100', 'dstport': 31398},
                      {'msgid': '302014', 'tranip': '46.227.172.22', 'tranport': '31398'}),
   {'natdst': '46.227.172.22:31398', 'natto': '172.29.6.100:31398', 'natkind': 'dst-nat'})
ok('a MikroTik\'s says its own', isemon.fw_nat_said({}, {'topics': 'firewall,info',
                                                          'transip': '1.2.3.4'}), {})
f = isemon.fg_parse_lines([DNAT], {}, NOW)[0].facts
ok('a translated session is counted on the NAT page, by its kind',
   ('natted', 'dst-nat') in isemon.Storage.fw_dims(f), True)
f = isemon.fg_parse_lines([NOOP], {}, NOW)[0].facts
ok('...one that was not, not', any(d == 'natted' for d, _v in isemon.Storage.fw_dims(f)), False)

print('\nThe NAT page')
store = isemon.Storage(isemon.DB_FILE)
lot = [dict(r.facts, fw='fg') for r in isemon.fg_parse_lines([SNAT, DNAT, NOOP], {}, NOW)]
lot += [dict(r.facts, fw='ftd') for r in isemon.ftd_parse_lines(FTD, {}, NOW)]
store.note_fw_events(lot)
said = {}
rows, _n = store.fw_rows(since=NOW - 3600, area='nat', limit=50, said=said)
rows = store.fw_row_fields([dict(r) for r in rows])
by = sorted((r['srcip'], (r.get('extra') or {}).get('natkind'),
             (r.get('extra') or {}).get('natsrc'), (r.get('extra') or {}).get('natto'),
             (r.get('extra') or {}).get('natdst')) for r in rows)
ok('every translated session, a FortiGate\'s and an FTD\'s, and no other', by, sorted([
    ('192.168.90.134', 'src-nat', '195.189.0.3:63693', None, None),
    ('94.154.20.57', 'dst-nat', None, '192.168.43.17:443', '195.189.0.3:443'),
    ('2.57.17.200', 'dst-nat', None, '172.29.6.100:31398', '46.227.172.22:31398'),
    ('172.29.200.181', 'src-nat', '46.227.172.21:47872', None, None)]))
ok('...said as what was typed, not as the page\'s own part of it', said.get('says'), '')
rows, _n = store.fw_rows(since=NOW - 3600, area='nat', limit=50,
                         query='(natkind:dst-nat,netmap,redirect OR tranip:*)')
ok('the quick dst-nat finds the dst-nats', sorted(r['srcip'] for r in rows),
   ['2.57.17.200', '94.154.20.57'])
rows, _n = store.fw_rows(since=NOW - 3600, area='session', limit=50)
ok('the sessions stay where they were', len(rows), 5)
isemon.CONFIG['fwlog_sources'] = [{'name': 'gw', 'type': 'routeros', 'path': str(folder),
                                   'files': '*.log'}]
ok('a MikroTik alone: its NAT rules\' lines, read as before', isemon.fw_nat_in_sessions(), False)

print('\nThe page')
ok('the button counts every translation and shows wherever there is one',
   "(((d.tops || {}).natted || {}).busiest || [])" in page
   and "(one === 'nat' && natted)" in page)
ok('the page holds sessions too', "nat: {area: 'nat', title: 'NAT', kinds: /^traffic/," in page)
ok('the quick searches find every firewall\'s', "'(natkind:dst-nat,netmap,redirect OR tranip:*)'"
   in page and "'(natkind:src-nat,masquerade,same OR transip:*)'" in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
