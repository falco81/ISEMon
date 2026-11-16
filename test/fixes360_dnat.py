#!/usr/bin/env python3
"""1.10.360: the DNAT analyzer - what one device inside needs forwarded to it.

A console behind a MikroTik's masquerade (all names and addresses made up):
it talks to PSN's STUN ports, one port (UDP 3074) is forwarded to it and gets
through, its peers knock on the public address at the port its own
connections leave by - and are dropped, no rule forwards it - and the
internet scans SSH. The analyzer must tell the three apart, find the public
address it leaves as, see what kind of device it is, and never call a scan a
missing forward.

    ./test/fixes360_dnat.py
"""
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 18960


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = Path(tempfile.mkdtemp(prefix='isemon-360-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'api_port': PORT,
                      'fwlog': 1})
NOW = time.time()
CON = '192.168.40.50'          # the console
PUB = '94.100.10.26'          # the router's public address
PEERS = ['84.20.1.%d' % i for i in range(10, 16)]


def stamp(ago):
    d = datetime.fromtimestamp(NOW - ago)
    return d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S')


def h(ago):
    return '%s gw.example.net ' % stamp(ago)


lines = []
ago = 3000
# Its connections out: STUN to PSN (TCP and UDP 3478-3480), masqueraded, the
# port kept; the filter's line says what it was made.
for i, peer in enumerate(['18.10.1.%d' % n for n in range(1, 9)]):
    for proto, dport in (('UDP', 3478), ('UDP', 3479), ('TCP', 3480)):
        sport = 3478 if proto == 'UDP' else 40000 + i
        ago -= 3
        lines.append(h(ago) + 'firewall,info nat-masquerade srcnat: in:LAN out:WAN1, '
                     'connection-state:new src-mac 00:11:22:33:44:55, proto %s, %s:%d->%s:%d, '
                     'len 100' % (proto, CON, sport, peer, dport))
        lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:WAN1, '
                     'connection-state:new,snat src-mac 00:11:22:33:44:55, proto %s, '
                     '%s:%d->%s:%d, NAT (%s:%d->%s:%d)->%s:%d, len 100'
                     % (proto, CON, sport, peer, dport, CON, sport, PUB, sport, peer, dport))
# ...and to its game peers, from the same port.
for peer in PEERS:
    ago -= 3
    lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:WAN1, '
                 'connection-state:new,snat src-mac 00:11:22:33:44:55, proto UDP, '
                 '%s:3478->%s:9308, NAT (%s:3478->%s:3478)->%s:9308, len 100'
                 % (CON, peer, CON, PUB, peer))
# UDP 3074 is forwarded to it, and gets through.
for i, peer in enumerate(PEERS[:3]):
    ago -= 3
    lines.append(h(ago) + 'firewall,info nat-dst-nat dstnat: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto UDP, %s:5000%d->%s:3074, '
                 'len 60' % (peer, i, PUB))
    lines.append(h(ago) + 'firewall,info accept forward: in:WAN1 out:LAN, connection-state:new,dnat '
                 'src-mac 44:31:92:3E:5E:CA, proto UDP, %s:5000%d->%s:3074, NAT '
                 '%s:5000%d->(%s:3074->%s:3074), len 60' % (peer, i, CON, peer, i, PUB, CON))
# Its peers knock on 3478 and 3479 - dropped, nothing forwards them.
for i, peer in enumerate(PEERS):
    for port in (3478, 3479):
        ago -= 2
        lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                     'connection-state:new src-mac 44:31:92:3E:5E:CA, proto UDP, '
                     '%s:6%03d->%s:%d, len 60' % (peer, i, PUB, port))
# The internet scans SSH and a high port nobody uses.
for i in range(12):
    ago -= 2
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
                 '45.%d.1.1:4%04d->%s:22, len 60' % (i, i, PUB))
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
                 '45.%d.1.1:4%04d->%s:49152, len 60' % (i, i, PUB))
# Another server inside has HTTPS forwarded to it.
ago -= 2
lines.append(h(ago) + 'firewall,info nat-dst-nat dstnat: in:WAN1 out:(unknown 0), '
             'connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
             '45.9.9.9:40000->%s:443, len 60' % PUB)
lines.append(h(ago) + 'firewall,info accept forward: in:WAN1 out:DMZ, connection-state:new,dnat '
             'src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), 45.9.9.9:40000->192.168.43.17:443, NAT '
             '45.9.9.9:40000->(%s:443->192.168.43.17:443), len 60' % PUB)
# And a laptop that talks to nothing special.
ago -= 2
lines.append(h(ago) + 'firewall,info nat-masquerade srcnat: in:LAN out:WAN1, '
             'connection-state:new src-mac 00:11:22:33:44:66, proto TCP (SYN), '
             '192.168.40.77:51000->18.10.2.200:443, len 60')

store = isemon.Storage(isemon.DB_FILE)
hold = {}
lot = [dict(r.facts, fw='gw') for r in isemon.ros_parse_lines(lines, hold, NOW)]
store.note_fw_events(lot)
d = isemon.Daemon(store)

got = d.fw_dnat(CON, 24)
print('\nThe way out')
ok('the public address it leaves as', [p['ip'] for p in got['out']['public']], [PUB])
ok('...not a private one', got['out']['public'][0]['private'], False)
ok('the port kept', (got['out']['kept'] > 0, got['out']['changed']), (True, 0))
ok('what it talks to, a connection counted once',
   {(s['proto'], s['port']): s['n'] for s in got['out']['services']}.get(('udp', 3478)), 8)
ok('...STUN named', any(s['name'].startswith('STUN') for s in got['out']['services']), True)
ok('its zone', got['zone'], 'LAN')

print('\nWhat it looks like')
ok('a PlayStation', [p['key'] for p in got['profiles']][:1], ['playstation'])
ports = {(p['proto'], p['ports'][0]): p for p in got['profiles'][0]['ports']}
ok('...UDP 3478-3479 needed and missing, seen knocking',
   (ports[('udp', 3478)]['need'], ports[('udp', 3478)]['state'], ports[('udp', 3478)]['knocks'] > 0),
   ('need', 'missing', True))
ok('...UDP 3074 forwarded and working',
   (ports[('udp', 3074)]['state'], ports[('udp', 3074)]['working']), ('forwarded', True))

print('\nWhat is forwarded to it')
fwd = {(f['proto'], f['public_port']): f for f in got['forwards']}
ok('UDP 3074 forwarded', ('udp', 3074) in fwd)
ok('...and working', fwd[('udp', 3074)]['state'], 'working')
ok('...from three addresses', fwd[('udp', 3074)]['sources'], 3)
ok('...the rule\'s prefix', fwd[('udp', 3074)]['prefix'], 'nat-dst-nat')
ok('the other server\'s HTTPS is not its', ('tcp', 443) in fwd, False)

print('\nWhat knocks and is not forwarded')
miss = {(m['proto'], m['port']): m for m in got['missing']}
ok('UDP 3478 missing', ('udp', 3478) in miss)
ok('...likely: its own port, its peers, its kind',
   (miss[('udp', 3478)]['likely'], sorted(w['kind'] for w in miss[('udp', 3478)]['why'])),
   ('likely', ['mapped', 'peer', 'profile']))
ok('...knocked from six addresses, all dropped',
   (miss[('udp', 3478)]['sources'], miss[('udp', 3478)]['denied'] == miss[('udp', 3478)]['n']),
   (6, True))
ok('UDP 3479 missing too', ('udp', 3479) in miss)
ok('SSH is a scan, not a missing forward', ('tcp', 22) in miss, False)
scans = {(s['proto'], s['port']) for s in got['scans']}
ok('...listed among the scans', ('tcp', 22) in scans and ('tcp', 49152) in scans)
ok('a scan of a port forwarded elsewhere would say where',
   isinstance(got['scans'][0].get('elsewhere'), list))

print('\nWarnings')
ok('nothing wrong said for a public address', [w['key'] for w in got['warnings']
                                                if w['key'] in ('cgnat', 'ports', 'blocked')], [])

print('\nA device behind the provider\'s NAT')
lines2 = [h(100) + 'firewall,info accept forward: in:LAN out:WAN1, connection-state:new,snat '
          'src-mac 00:11:22:33:44:77, proto UDP, 192.168.40.60:3478->18.10.1.1:3478, NAT '
          '(192.168.40.60:3478->100.64.12.7:61000)->18.10.1.1:3478, len 100']
store.note_fw_events([dict(r.facts, fw='gw') for r in isemon.ros_parse_lines(lines2, {}, NOW)])
got2 = d.fw_dnat('192.168.40.60', 24)
ok('carrier NAT said', 'cgnat' in [w['key'] for w in got2['warnings']])
ok('a port changed is said', 'ports' in [w['key'] for w in got2['warnings']])

print('\nNothing at all')
got3 = d.fw_dnat('192.168.40.99', 24)
ok('nothing in the log said', [w['key'] for w in got3['warnings']], ['nothing'])
try:
    d.fw_dnat('not an address')
    ok('a bad address refused', False)
except ValueError:
    ok('a bad address refused', True)

print('\nA MikroTik read through its API: its rules for the device')


class Readers(object):
    def snapshot(self, fw):
        return {'wan': ['WAN1'], 'addresses': [{'address': PUB + '/24', 'interface': 'WAN1'},
                                               {'address': '192.168.40.1/24',
                                                'interface': 'LAN'}],
                'rules': [{'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat',
                           'protocol': 'udp', 'dst-port': '3074', 'to-addresses': CON,
                           'packets': '120', 'bytes': '9000', '.id': '*5',
                           'comment': 'PS5 UDP'},
                          {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat',
                           'protocol': 'tcp', 'dst-port': '9295', 'to-addresses': CON,
                           'packets': '0', 'bytes': '0', '.id': '*6',
                           'comment': 'PS5 remote play'},
                          {'table': 'nat', 'chain': 'srcnat', 'action': 'masquerade'},
                          {'table': 'filter', 'chain': 'forward', 'action': 'drop',
                           'connection-nat-state': '!dstnat'}]}


d.rosapi = Readers()
got4 = d.fw_dnat(CON, 24, 'gw')
ok('its public address from the router', got4['router']['wan_addresses'], [PUB])
f4 = {(f['proto'], f['public_port']): f for f in got4['forwards']}
ok('the rule beside the forward seen, with its counter',
   (f4[('udp', 3074)]['rule'], f4[('udp', 3074)]['rule_packets']), ('PS5 UDP', 120))
ok('a rule nothing used is listed as unused', f4[('tcp', 9295)]['state'], 'unused')
ok('the filter\'s dst-nat rule seen', got4['router']['dstnat_filter'], '!dstnat')

print('\nThrough the API')
d.rosapi = None
d.add_user('falco', 'a-long-enough-password-1', 'fulladmin', by='test')
api = isemon.ApiServer(d, PORT)
api.start()
time.sleep(0.4)
tok = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')


def call(path):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path))
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('X-Isemon-Session', tok)
    try:
        with urllib.request.urlopen(req, timeout=30) as a:
            return a.status, json.loads(a.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


st, body = call('/api/fw/dnat?hours=24')
ok('the devices to choose from, busiest first',
   (st, [x['ip'] for x in body.get('hosts', [])][:1]), (200, [CON]))
st, body = call('/api/fw/dnat?ip=%s&hours=24' % CON)
ok('the analysis', (st, body.get('ip'), bool(body.get('missing'))), (200, CON, True))
st, body = call('/api/fw/dnat?ip=nonsense')
ok('a bad address: 400', st, 400)

page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
print('\nThe page')
ok('the button on the NAT page', 'id="t-dnat"' in page)
ok('the analyzer asks the daemon', "api('fw-dnat&" in page)
ok('...relayed by PHP', "'fw-dnat' => '/api/fw/dnat'" in page)
ok('rules for MikroTik, iptables, FortiGate and Cisco',
   all(s in page for s in ('/ip firewall nat', 'iptables -t nat', 'config firewall vip',
                           'nat (inside,outside) static')))

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
