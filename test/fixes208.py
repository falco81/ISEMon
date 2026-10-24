#!/usr/bin/env python3
"""1.10.208: a MikroTik dst-nat rule's line says where it went - the server
inside - and a masquerade's what its source was made, out of the filter's own
lines about the same connection.

    ./test/fixes208.py
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
folder = Path(tempfile.mkdtemp(prefix='isemon-208-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
NOW = time.time()
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(datetime.fromtimestamp(NOW - 120))
H = '%s gw.example.net ' % STAMP
DNAT = (H + 'firewall,info nat-dst-nat dstnat: in:VLAN108 out:(unknown 0), connection-state:new '
        'src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), 94.154.20.57:15023->195.189.0.26:443, len 60')
FWD = (H + 'firewall,info accept forward: in:VLAN108 out:DMZ, connection-state:new,dnat src-mac '
       '44:31:92:3E:5E:CA, proto TCP (SYN), 94.154.20.57:15023->192.168.43.17:443, NAT '
       '94.154.20.57:15023->(195.189.0.26:443->192.168.43.17:443), len 60')
MASQ = (H + 'firewall,info nat-masquerade srcnat: in:LAN out:VLAN108, connection-state:new '
        'src-mac 00:11:32:E6:94:43, proto UDP, 192.168.40.253:58007->52.46.184.236:53, len 103')
BACK = (H + 'firewall,info accept forward: in:VLAN108 out:LAN, connection-state:established,snat '
        'src-mac 44:31:92:3E:5E:CA, proto UDP, 52.46.184.236:53->192.168.40.253:58007, NAT '
        '52.46.184.236:53->(195.189.0.26:58099->192.168.40.253:58007), len 444')

print('\nWhile it is read')
got = isemon.ros_parse_lines([DNAT, FWD, DNAT.replace('15023', '15024')], {}, NOW)
ok('a dst-nat rule\'s line says the server inside, from the lines of the same read',
   [(r.facts['fields'].get('natto'), r.facts['fields'].get('natguess')) for r in got
    if r.facts['action'] == 'dstnat'],
   [('192.168.43.17:443', '1'), ('192.168.43.17:443', '1')])
hold = {}
isemon.ros_parse_lines([FWD], hold, NOW)
got = isemon.ros_parse_lines([DNAT], hold, NOW)
ok('...and from what a read before it learned', got[0].facts['fields'].get('natto'),
   '192.168.43.17:443')
got = isemon.ros_parse_lines([DNAT.replace(':443,', ':8443,')], hold, NOW)
ok('...never for another port', got[0].facts['fields'].get('natto'), None)

print('\nWhen it is shown')
store = isemon.Storage(isemon.DB_FILE)
lot = []
for line in (DNAT, FWD, MASQ, BACK):
    one = isemon.ros_record_from(line, NOW, {}, None)   # nothing learned: as old rows were
    lot.append(dict(one.facts, fw='gw'))
store.note_fw_events(lot)
rows, _n = store.fw_rows(since=NOW - 3600, area='nat', limit=10)
rows = store.fw_row_fields([dict(r) for r in rows])
by = {r['action']: r.get('extra') or {} for r in rows}
ok('a dst-nat line read before anything was known says where it went, exactly',
   (by['dstnat'].get('natto'), by['dstnat'].get('natguess')), ('192.168.43.17:443', None))
ok('...and a masquerade what its source was made, exactly',
   (by['srcnat'].get('natsrc'), by['srcnat'].get('natguess')), ('195.189.0.26:58099', None))
daemon = isemon.Daemon(store)
ident = [r['ident'] for r in rows if r['action'] == 'dstnat'][0]
said = daemon.fw_detail(ident, NOW)
ok('...in its popup too', said['fields'].get('natto'), '192.168.43.17:443')

print('\nThe page')
ok('the NAT list says where a dst-nat went', "tNatEnd(x.natto," in page
   and "if (!x.natsrc && !x.natdst && !x.natto)" in page)
ok('...it is a field of the popup and of the search box',
   "'natdst', 'natto', 'transip'" in page and "natto: ['natto'," in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
