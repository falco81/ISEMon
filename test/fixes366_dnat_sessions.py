#!/usr/bin/env python3
"""1.10.366: the DNAT analyzer where the translation is in the sessions - a
FortiGate and an FTD. The devices inside it offers are the ones that went
out translated, or were forwarded to; and a device published by a VIP alone
(nothing of its own going out) has its forwards found all the same.

All names and addresses made up.

    ./test/fixes366_dnat_sessions.py
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


folder = Path(tempfile.mkdtemp(prefix='isemon-366-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'fwlog': 1,
                      'fwlog_sources': [{'name': 'fg', 'type': 'fortigate', 'path': str(folder),
                                         'files': '*.log'},
                                        {'name': 'ftd', 'type': 'ftd', 'path': str(folder),
                                         'files': '*.log'}]})
NOW = time.time()
PUB = '195.189.10.3'
CON = '192.168.90.50'          # a console, going out translated
SRV = '192.168.43.17'          # a server, published by a VIP alone


def fg(rest, ago, ns):
    at = int(NOW - ago)
    d = datetime.fromtimestamp(at)
    stamp = d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S')
    return ('%s fw.example.net date=%s time=%s devname="FG-EX" devid="FGT00EXAMPLE0001" '
            'eventtime=%d%09d tz="+0200" ' % (stamp, d.strftime('%Y-%m-%d'),
                                              d.strftime('%H:%M:%S'), at, ns) + rest)


lines = []
n = 0
for i in range(5):
    n += 1
    lines.append(fg('logid="0000000013" type="traffic" subtype="forward" level="notice" '
                    'vd="root" srcip=%s srcport=3074 srcintf="LAN" srcintfrole="lan" '
                    'dstip=81.20.2.%d dstport=3074 dstintf="wan1" dstintfrole="wan" '
                    'sessionid=%d proto=17 action="accept" policyid=6 policytype="policy" '
                    'policyname="LAN-WAN" service="udp/3074" trandisp="snat" transip=%s '
                    'transport=3074 duration=5 sentbyte=172 rcvdbyte=88'
                    % (CON, i, 1000 + n, PUB), 900 - n, n))
for i in range(4):
    n += 1
    lines.append(fg('logid="0000000013" type="traffic" subtype="forward" level="notice" '
                    'vd="root" srcip=94.154.20.%d srcport=1502%d srcintf="wan1" '
                    'srcintfrole="wan" dstip=%s dstport=443 dstintf="DMZ" dstintfrole="dmz" '
                    'sessionid=%d proto=6 action="close" policyid=9 policytype="policy" '
                    'policyname="WAN-WEB" service="HTTPS" trandisp="dnat" tranip=%s '
                    'tranport=443 duration=5 sentbyte=172 rcvdbyte=88'
                    % (i, i, PUB, 2000 + n, SRV), 900 - n, n))
H = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(
    datetime.fromtimestamp(NOW - 600)) + ' ftd1.example.net '
FTD = [H + '%FTD-6-302013: Built inbound TCP connection 4161323992 for INTERNET:2.57.17.200/22565 '
       '(2.57.17.200/22565) to DMZ:172.29.6.100/8443 (46.227.172.22/8443)',
       H + '%FTD-6-302014: Teardown TCP connection 4161323992 for INTERNET:2.57.17.200/22565 to '
       'DMZ:172.29.6.100/8443 duration 0:00:01 bytes 1232 TCP FINs from INTERNET']

store = isemon.Storage(isemon.DB_FILE)
lot = [dict(r.facts, fw='fg') for r in isemon.fg_parse_lines(lines, {}, NOW)]
lot += [dict(r.facts, fw='ftd') for r in isemon.ftd_parse_lines(FTD, {}, NOW)]
store.note_fw_events(lot)
d = isemon.Daemon(store)

print('The devices offered')
hosts = {h['ip']: h['n'] for h in store.fw_dnat_hosts(NOW - 86400)}
ok('a FortiGate\'s device going out translated', hosts.get(CON), 5)
ok('...one forwarded to by a VIP', hosts.get(SRV), 4)
ok('...an FTD\'s forwarded to', '172.29.6.100' in hosts)
ok('of one firewall only, when one is chosen',
   sorted(h['ip'] for h in store.fw_dnat_hosts(NOW - 86400, fw='ftd')), ['172.29.6.100'])
ok('no public address among them', PUB in hosts or '2.57.17.200' in hosts, False)

print('A device published by a VIP alone')
got = d.fw_dnat(SRV, 24, 'fg')
fwd = {(f['proto'], f['public_port']): f for f in got['forwards']}
ok('its forward found, though nothing of its own goes out', ('tcp', 443) in fwd)
ok('...working, from four sources', (fwd.get(('tcp', 443)) or {}).get('state'), 'working')
ok('...asked at the public address', (fwd.get(('tcp', 443)) or {}).get('public'), PUB)
ok('...and the VIP is not said to be its way out', [p['ip'] for p in got['out']['public']], [])
ok('the counted forwards of it', store.fw_dnat_vips(SRV, NOW - 86400), {PUB: 4})

print('The console')
got = d.fw_dnat(CON, 24, 'fg')
ok('it leaves as the public address', [p['ip'] for p in got['out']['public']], [PUB])
ok('...the port kept', (got['out']['kept'], got['out']['changed']), (5, 0))
ok('...no VIP of another device taken for its own', store.fw_dnat_vips(CON, NOW - 86400), {})

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
