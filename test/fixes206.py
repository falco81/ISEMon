#!/usr/bin/env python3
"""1.10.206: a MikroTik's log shown whole - what a rule that only logs wrote
is let through (or only said, as the setting says), a packet of the answer
said the way its session was opened, the address translation in all three
of RouterOS's shapes, and a packet two rules logged counted once.

    ./test/fixes206.py
"""
import sys
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
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
NOW = time.time()
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(datetime.fromtimestamp(NOW - 120))
H = '%s gw.example.net ' % STAMP


def one(msg):
    got = isemon.ros_record_from(H + msg, NOW, {}, {})
    return got.facts if got else None


print('\nWhat became of it')
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('the setting, let through by default, checked as a choice',
   (isemon.DEFAULTS.get('fwlog_ros_plain'), "'fwlog_ros_plain': ('allow', 'info')," in src),
   ('allow', True))
f = one('firewall,info forward: in:LAN out:SRV, connection-state:new src-mac BC:FC:E7:D7:86:70, '
        'proto TCP (SYN), 192.168.40.12:54997->192.168.42.31:22, len 52')
ok('no prefix: let through', (f['verdict'], f['sub'], f['service']), ('allow', 'forward', 'tcp/22'))
f = one('firewall,info LOG-FORWARD forward: in:IoT out:LAN, connection-state:established '
        'src-mac AC:EB:E6:E6:97:C0, proto TCP (SYN,ACK), 172.16.17.6:80->192.168.40.233:38094, '
        'len 44')
ok('a prefix with no verdict in it: let through too', f['verdict'], 'allow')
f = one('firewall,info input: in:VLAN108 out:(unknown 0), connection-state:invalid '
        'src-mac 44:31:92:3E:5E:CA, proto TCP (ACK), 3.253.179.213:443->195.189.0.26:41000, '
        'len 40')
ok('...but an invalid packet only said', f['verdict'], 'info')
f = one('firewall,info DROP-FOR - IPv4 forward: in:VLAN108 out:LAN, connection-state:new '
        'proto TCP (SYN), 203.0.113.5:40000->192.168.40.12:3389, len 60')
ok('a DROP prefix still refuses', f['verdict'], 'deny')
isemon.CONFIG['fwlog_ros_plain'] = 'info'
f = one('firewall,info forward: in:LAN out:SRV, connection-state:new proto TCP (SYN), '
        '192.168.40.12:54997->192.168.42.31:22, len 52')
ok('...and with the setting at info, a plain line is only said', f['verdict'], 'info')
isemon.CONFIG['fwlog_ros_plain'] = 'allow'

print('\nA prefix named after its action')
verdicts = {}
for prefix, chain in (('accept', 'forward'), ('v6-accept', 'input'), ('drop', 'input'),
                      ('v6-drop', 'forward'), ('add-src-to-address-list', 'input'),
                      ('nat-masquerade', 'srcnat'), ('nat-accept', 'srcnat'),
                      ('nat-dst-nat', 'dstnat'), ('fasttrack', 'forward')):
    f = one('firewall,info %s %s: in:VLAN108 out:(unknown 0), connection-state:new '
            'src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), 80.82.77.33:21057->195.189.0.26:9000, '
            'len 60' % (prefix, chain))
    verdicts[prefix] = f['verdict']
ok('accept and drop, v6- or not; an action that goes on to the next rule only said; '
   'the address translation only said',
   verdicts, {'accept': 'allow', 'v6-accept': 'allow', 'drop': 'deny', 'v6-drop': 'deny',
              'add-src-to-address-list': 'info', 'nat-masquerade': 'info', 'nat-accept': 'info',
              'nat-dst-nat': 'info', 'fasttrack': 'allow'})
f = one('system,info nat rule changed by winbox-3.43/tcp-msg(winbox):Admin@192.168.40.12/script:'
        'LOG-ENABLE-NAT/action:966 (/ip firewall nat set *AC log=yes log-prefix=nat-dst-nat)')
ok('a change a script made: who ran it, from where, which script',
   (f['action'], f['user'], f['srcip'], f['fields'].get('script'), f['fields'].get('cfgpath')),
   ('changed', 'Admin', '192.168.40.12', 'LOG-ENABLE-NAT', 'nat rule'))
f = one('system,info changed script settings by winbox-3.43/tcp-msg(winbox):Admin@192.168.40.12 '
        '(/system script set LOG-DISABLE-ALL dont-require-permissions=no)')
ok('...and one with the verb first', (f['action'], f['user'], f['fields'].get('cfgpath')),
   ('changed', 'Admin', 'script settings'))

print('\nThe answer, turned round')
f = one('firewall,info LOG-FORWARD forward: in:VLAN108 out:LAN, packet-mark:Download '
        'connection-state:established,snat src-mac 44:31:92:3E:5E:CA, proto TCP (ACK,PSH), '
        '4.150.223.100:443->192.168.40.12:56655, NAT 4.150.223.100:443->(195.189.0.26:56655'
        '->192.168.40.12:56655), len 549')
ok('the ends the way the session was opened',
   (f['srcip'], f['srcport'], f['dstip'], f['dstport'], f['service'], f['srcintf'],
    f['dstintf']),
   ('192.168.40.12', 56655, '4.150.223.100', 443, 'tcp/443', 'LAN', 'VLAN108'))
ok('...said to be the answer, with its MAC the other end\'s',
   (f['fields'].get('direction'), f['fields'].get('dstmac'), 'srcmac' in f['fields']),
   ('reply', '44:31:92:3E:5E:CA', False))
ok('...the whole connection state, and the address the client was made',
   (f['fields'].get('connectionstate'), f['fields'].get('transip'),
    f['fields'].get('transport'), f['fields'].get('packetmark')),
   ('established,snat', '195.189.0.26', '56655', 'Download'))
f = one('firewall,info input: in:LAN out:(unknown 0), connection-state:established '
        'src-mac BC:FC:E7:D7:86:70, proto TCP (ACK), 192.168.40.12:49729->192.168.40.1:8291, '
        'len 40')
ok('a packet towards a service is left as it is',
   (f['srcip'], f['dstport'], f['service'], 'direction' in f['fields']),
   ('192.168.40.12', 8291, 'tcp/8291', False))

print('\nThe address translation')
f = one('firewall,info forward: in:LAN out:VLAN108, connection-state:new src-mac '
        '44:31:92:3E:5E:CA, proto TCP (SYN), 192.168.40.12:56655->4.150.223.100:443, '
        'NAT (192.168.40.12:56655->195.189.0.26:56655)->4.150.223.100:443, len 60')
ok('the source translated: (a->b)->c',
   (f['fields'].get('nat'), f['fields'].get('transip'), f['fields'].get('transport')),
   ('(192.168.40.12:56655->195.189.0.26:56655)->4.150.223.100:443', '195.189.0.26', '56655'))
f = one('firewall,info dstnat: in:VLAN108 out:(unknown 0), connection-state:new proto TCP '
        '(SYN), 1.2.3.4:5555->195.189.0.26:443, NAT 1.2.3.4:5555->(195.189.0.26:443'
        '->192.168.43.17:443), len 60')
ok('the destination translated: a->(c->d), a proto straight after the state',
   (f['fields'].get('tranip'), f['fields'].get('tranport'), f['proto'], f['service']),
   ('192.168.43.17', '443', 6, 'tcp/443'))
f = one('firewall,info ACCEPT-WEB forward: in:WAN out:DMZ, connection-state:new,dnat proto '
        'TCP (SYN), 203.0.113.5:40000->192.0.2.10:443, NAT (203.0.113.5:40000->198.51.100.1:443)'
        '->(203.0.113.5:40000->192.0.2.10:443), len 60')
ok('...and both: (a->b)->(c->d)', (f['fields'].get('tranip'), f['fields'].get('nat')),
   ('192.0.2.10', '(203.0.113.5:40000->198.51.100.1:443)->(203.0.113.5:40000->192.0.2.10:443)'))

print('\nOne packet, two rules')
twin = ('in:VLAN108 out:LAN, connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
        '203.0.113.5:40000->192.168.40.12:3389, len 60')
got = isemon.ros_parse_lines([H + 'firewall,info forward: ' + twin,
                              H + 'firewall,info DROP-FOR - IPv4 forward: ' + twin,
                              H + 'firewall,info forward: ' + twin.replace('len 60', 'len 64')],
                             {}, NOW)
ok('the line that only logged it is the refusal\'s twin, left out',
   [(r.facts['verdict'], r.facts['fields'].get('len')) for r in got],
   [('deny', '60'), ('allow', '64')])

print('\nNAT and DHCP, each a page of its own')
hold = {}
got = isemon.ros_parse_lines([
    H + 'firewall,info accept forward: in:LAN out:VLAN108, connection-state:established,snat '
    'src-mac D4:9D:C0:BF:8D:17, proto TCP (ACK), 192.168.40.40:39047->142.251.157.4:443, '
    'NAT (192.168.40.40:39047->195.189.0.26:39047)->142.251.157.4:443, len 52',
    H + 'firewall,info nat-masquerade srcnat: in:LAN out:VLAN108, connection-state:new '
    'src-mac 00:11:32:E6:94:43, proto UDP, 192.168.40.253:58007->52.46.184.236:53, len 103',
    H + 'firewall,info nat-accept srcnat: in:SRV out:LAN, connection-state:new src-mac '
    '00:50:56:A8:53:C5, proto UDP, 192.168.42.31:44557->192.168.40.253:53, len 118',
    H + 'dhcp,info DHCP_LAN assigned 192.168.40.115 for 98:E2:55:F8:0C:23 Temp'], hold, NOW)
f0, f1, f2, f3 = [r.facts for r in got]
ok('a translated session stays a session, saying what its source was made',
   (isemon.fw_area(f0), f0['fields'].get('natsrc')), ('session', '195.189.0.26:39047'))
ok('a NAT rule\'s own line is on the NAT page, only said, by the kind of translation',
   (isemon.fw_area(f1), f1['verdict'], f1['fields'].get('natkind')), ('nat', 'info', 'masquerade'))
ok('...made the address the router\'s other lines show for that way out, marked as such',
   (f1['fields'].get('natsrc'), f1['fields'].get('natguess')), ('195.189.0.26:58007', '1'))
ok('...and a NAT rule that translates nothing says so', (isemon.fw_area(f2), f2['fields'].get('natkind'),
                                                          'natsrc' in f2['fields']),
   ('nat', 'none', False))
ok('a DHCP lease is on the DHCP page', (isemon.fw_area(f3), f3['fields'].get('mac'), f3['host']),
   ('dhcp', '98:E2:55:F8:0C:23', 'Temp'))
ok('...and both are pages', ('nat' in isemon.FW_AREAS, 'dhcp' in isemon.FW_AREAS), (True, True))
ok('FTD\'s own NAT refusals stay where they were',
   isemon.fw_area({'type': 'traffic', 'sub': 'nat', 'fields': {'msgid': '305006'}}), 'session')
f = one('firewall,info accept forward: in:VLAN108 out:LAN, packet-mark:Download '
        'connection-state:established,snat src-mac 44:31:92:3E:5E:CA, proto UDP, '
        '195.113.144.201:123->192.168.40.6:123, NAT 195.113.144.201:123->(195.189.0.26:123'
        '->192.168.40.6:123), len 76')
ok('an answer through a translation is turned round whatever its ports',
   (f['srcip'], f['dstip'], f['fields'].get('direction'), f['fields'].get('natsrc')),
   ('192.168.40.6', '195.113.144.201', 'reply', '195.189.0.26:123'))
f = one('firewall,info accept forward: in:DMZ out:VLAN108, connection-state:established,dnat '
        'src-mac 00:50:56:A8:A1:24, proto TCP (SYN,ACK), 192.168.43.17:443->94.154.19.102:25665, '
        'NAT (192.168.43.17:443->195.189.0.26:443)->94.154.19.102:25665, len 44')
ok('...and so is one of a published server, with the address it was asked at',
   (f['srcip'], f['dstip'], f['dstport'], f['fields'].get('natdst'), f['fields'].get('tranip')),
   ('94.154.19.102', '192.168.43.17', 443, '195.189.0.26:443', '192.168.43.17'))
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('a list\'s rows carry the translation and the lease, read for that page alone',
   "FW_ROW_FIELDS = ('natsrc', 'natdst', 'natto', 'natkind', 'natguess', 'mac', 'server')" in src
   and 'store.fw_row_fields(rows)' in src)

print('\nWritten, and listed with what each row says')
import tempfile                                       # noqa: E402
folder = Path(tempfile.mkdtemp(prefix='isemon-206-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
store = isemon.Storage(isemon.DB_FILE)
lot = []
for r in got:
    one_f = dict(r.facts)
    one_f['fw'] = 'gw'
    lot.append(one_f)
store.note_fw_events(lot)
rows, _n = store.fw_rows(since=NOW - 3600, area='nat', limit=10)
rows = store.fw_row_fields([dict(r) for r in rows])
ok('the NAT page lists the NAT rules\' lines, each with its translation',
   sorted((r.get('extra') or {}).get('natkind', '') for r in rows), ['masquerade', 'none'])
rows, _n = store.fw_rows(since=NOW - 3600, area='dhcp', limit=10)
rows = store.fw_row_fields([dict(r) for r in rows])
ok('...and the DHCP page the lease, with its MAC and server',
   [((r.get('extra') or {}).get('mac'), (r.get('extra') or {}).get('server')) for r in rows],
   [('98:E2:55:F8:0C:23', 'DHCP_LAN')])

print('\nThe page')
ok('the NAT and DHCP pages, each only where there are lines of it',
   'data-page="nat" aria-selected="false" hidden' in page
   and 'data-page="dhcp" aria-selected="false" hidden' in page
   and "nat: {area: 'nat'" in page and "dhcp: {area: 'dhcp'" in page
   and "['nat', 'dhcp'].forEach(function (one) {" in page)
ok('...drawn each its own way, and the sessions offer the translation as a column',
   "shape === 'nat'" in page and "shape === 'dhcp'" in page
   and "['Translated', '', '', 'nat', function (r) { return tNatCell(r); }]" in page)

ok('the setting is on the firewall pane, shown with the firewalls',
   "'fwlog_sources', 'fwlog_ros_plain'" in page and "fwlog_ros_plain: ['fwlog', '1']" in page)
ok('the legend says each verdict as a string of its own',
   "one.appendChild(el('span', '', T_VERDICTS[v].words));" in page)
ok('...and what is kept is said a sentence at a time',
   "' counted bucket(s) behind the cards and the chart'" in page
   and "' \\u00b7 kept ' + (k.allowed" not in page)
ok('the router\'s own fields are named', all(('  %s: ' % k) in page or (' %s: ' % k) in page
                                             for k in ('connectionstate', 'packetmark', 'nat')))
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
