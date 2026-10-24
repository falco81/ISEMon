#!/usr/bin/env python3
"""1.10.211: a MikroTik read through its API as well - read-only, one session
- for how much went where (the connection tracking table: each connection's
bytes, how long it lasted, what it was translated to), who is on its VPN and
which tunnels are up now, and how the router is. Against a RouterOS API that
is played here, over TLS with a certificate made here and pinned, and plain.

    ./test/fixes211.py
"""
import json
import socket
import ssl
import sys
import tempfile
import threading
import time
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
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
folder = Path(tempfile.mkdtemp(prefix='isemon-211-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})


# ---- a RouterOS API, played -------------------------------------------------
class FakeRouter(object):
    """Enough of RouterOS's API to be read: /login and the prints asked."""

    def __init__(self, tls_files=None):
        self.asked = []
        self.conns = []
        self.ppp = []
        self.group_policy = 'read,api,!write,!policy'
        self.srv = socket.socket()
        self.srv.bind(('127.0.0.1', 0))
        self.srv.listen(5)
        self.port = self.srv.getsockname()[1]
        self.ctx = None
        if tls_files:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(*tls_files)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            if self.ctx:
                try:
                    c = self.ctx.wrap_socket(c, server_side=True)
                except (ssl.SSLError, OSError):
                    c.close()
                    continue
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    @staticmethod
    def read_word(c):
        def exact(n):
            out = b''
            while len(out) < n:
                got = c.recv(n - len(out))
                if not got:
                    raise EOFError
                out += got
            return out
        first = exact(1)[0]
        if first < 0x80:
            n = first
        elif first < 0xC0:
            n = ((first & 0x3F) << 8) | exact(1)[0]
        else:
            n = ((first & 0x1F) << 16) | int.from_bytes(exact(2), 'big')
        return exact(n).decode() if n else ''

    def send(self, c, words):
        c.sendall(b''.join(isemon.RosApi.encode_length(len(w.encode())) + w.encode()
                           for w in words) + b'\x00')

    def one(self, c):
        signed = False
        try:
            while True:
                words = []
                while True:
                    w = self.read_word(c)
                    if not w:
                        break
                    words.append(w)
                if not words:
                    continue
                cmd, args = words[0], {}
                for w in words[1:]:
                    if w.startswith('='):
                        k, _, v = w[1:].partition('=')
                        args[k] = v
                self.asked.append(cmd)
                if cmd == '/login':
                    if args.get('name') == 'isemon-read' and args.get('password') == 's3cret':
                        signed = True
                        self.send(c, ['!done'])
                    else:
                        self.send(c, ['!trap', '=message=invalid user name or password (6)'])
                        self.send(c, ['!done'])
                    continue
                if not signed:
                    self.send(c, ['!trap', '=message=not logged in'])
                    self.send(c, ['!done'])
                    continue
                rows = self.answer(cmd)
                if 'count-only' in args:
                    self.send(c, ['!done', '=ret=%d' % len(rows)])
                    continue
                for r in rows:
                    self.send(c, ['!re'] + ['=%s=%s' % kv for kv in r.items()])
                self.send(c, ['!done'])
        except (EOFError, OSError, ssl.SSLError):
            pass

    def answer(self, cmd):
        return {
            '/system/identity/print': [{'name': 'gw'}],
            '/system/resource/print': [{'version': '7.16.1', 'board-name': 'RB5009',
                                        'uptime': '3d2h', 'cpu-load': '4',
                                        'free-memory': '700000000',
                                        'total-memory': '1000000000'}],
            '/ip/firewall/connection/tracking/print': [{'total-entries': str(len(self.conns))}],
            '/ip/firewall/connection/print': self.conns,
            '/ipv6/firewall/connection/print': getattr(self, 'conns6', []),
            '/ipv6/neighbor/print': [{'address': '2001:db8:40::15', 'mac-address':
                                      '98:E2:55:F8:0C:23', 'interface': 'bridge',
                                      'status': 'reachable'}],
            '/ipv6/dhcp-server/binding/print': [{'address': '2001:db8:99::/56',
                                                 'duid': '0x000100012b', 'status': 'bound'}],
            '/ipv6/firewall/filter/print': [{'.id': '*9', 'chain': 'forward', 'action': 'drop',
                                             'bytes': '64', 'packets': '1'}],
            '/ppp/active/print': self.ppp,
            '/interface/print': [
                {'name': 'ether1', 'type': 'ether', 'running': 'true', 'disabled': 'false'},
                {'name': 'vCloud', 'type': 'ovpn-out', 'running': 'true', 'disabled': 'false',
                 'tx-byte': '1000', 'rx-byte': '2000'}],
            '/ip/ipsec/active-peers/print': [{'remote-address': '203.0.113.9',
                                              'local-address': '195.189.0.26',
                                              'state': 'established', 'uptime': '1h'}],
            '/ip/address/print': [{'address': '195.189.0.26/29'}, {'address': '192.168.40.1/24'}],
            '/ipv6/address/print': [],
            '/ip/dhcp-server/lease/print': [{'address': '192.168.40.115',
                                             'mac-address': '98:E2:55:F8:0C:23',
                                             'host-name': 'Temp', 'status': 'bound'}],
            '/user/print': [{'name': 'isemon-read', 'group': 'isemon-read'}],
            '/ip/route/print': [{'dst-address': '0.0.0.0/0', 'gateway': '195.189.0.25',
                                 'distance': '1', 'active': 'true', 'static': 'true'}],
            '/ipv6/route/print': [],
            '/ip/arp/print': [{'address': '192.168.40.115', 'mac-address': '98:E2:55:F8:0C:23',
                               'interface': 'bridge', 'status': 'reachable'}] * getattr(
                                   self, 'arp_n', 1),
            '/ip/neighbor/print': [{'identity': 'sw1', 'address': '192.168.40.2',
                                    'interface': 'ether2', 'platform': 'MikroTik'}],
            '/ip/firewall/filter/print': [{'.id': '*1', 'chain': 'input', 'action': 'drop',
                                           'bytes': '1234', 'packets': '12',
                                           'src-address-list': 'isemon'}],
            '/interface/wireguard/peers/print': [{'interface': 'wg0', 'name': 'laptop',
                                                  'last-handshake': '1m5s', 'rx': '100',
                                                  'tx': '200'}],
            '/system/health/print': [{'name': 'temperature', 'value': '41', 'type': 'C'}],
            '/user/group/print': [{'name': 'isemon-read', 'policy': self.group_policy}],
        }.get(cmd, [])


class FakeStore(object):
    def __init__(self):
        self.meta = {}

    def get_meta(self, k, default=None):
        return self.meta.get(k, default)

    def set_meta(self, k, v):
        self.meta[k] = v


class FakeDaemon(object):
    def __init__(self):
        self.store = FakeStore()
        self.handed = []

    def fw_hand_in(self, many):
        self.handed.extend(many)


print('\nThe API\'s words')
ok('a word\'s length, short and long, as RouterOS writes it',
   [isemon.RosApi.encode_length(n).hex() for n in (5, 0x7f, 0x80, 0x3fff, 0x4000)],
   ['05', '7f', '8080', 'bfff', 'c04000'])
ok('only prints are ever sent', (bool(isemon.ROSAPI_SAFE.match('/ip/firewall/connection/print')),
                                 bool(isemon.ROSAPI_SAFE.match('/ip/firewall/filter/add')),
                                 bool(isemon.ROSAPI_SAFE.match('/system/reboot'))),
   (True, False, False))

print('\nA certificate made here, pinned')
cert, key, fp = isemon.rosapi_make_certificate('127.0.0.1')
(folder / 'r.crt').write_text(cert)
(folder / 'r.key').write_text(key)
ok('a key and a certificate, and its fingerprint', (cert.startswith('-----BEGIN CERTIFICATE'),
                                                    'PRIVATE KEY' in key, len(fp)), (True, True, 64))
router = FakeRouter((str(folder / 'r.crt'), str(folder / 'r.key')))
api = {'host': '127.0.0.1', 'port': router.port, 'mode': 'pin', 'user': 'isemon-read'}
got = isemon.rosapi_probe(api, fp, 's3cret')
ok('it answers, signed in, over TLS with the certificate pinned',
   (got.get('ok'), got.get('identity'), got.get('version'), got.get('can_write')),
   (True, 'gw', '7.16.1', False))
got = isemon.rosapi_probe(api, 'ab' * 32, 's3cret')
ok('...another certificate than the one pinned is refused, nothing asked',
   (got.get('ok'), 'another certificate' in (got.get('trouble') or '')), (False, True))
got = isemon.rosapi_probe(api, fp, 'wrong')
ok('...a wrong password said as such', 'refused the sign-in' in (got.get('trouble') or ''), True)
router.group_policy = 'read,write,api,policy'
got = isemon.rosapi_probe(api, fp, 's3cret')
ok('an account that may change things is said to', (got.get('can_write'), 'write' in
                                                     (got.get('policy') or [])), (True, True))
router.group_policy = 'read,api'
ok('...and nothing but prints was asked of the router',
   sorted(set(router.asked) - {'/login'}) == sorted(
       c for c in set(router.asked) - {'/login'} if c.endswith('/print')), True)
plain = FakeRouter()
got = isemon.rosapi_probe({'host': '127.0.0.1', 'port': plain.port, 'mode': 'plain',
                           'user': 'isemon-read'}, '', 's3cret')
ok('the plain API too', (got.get('ok'), got.get('identity')), (True, 'gw'))

print('\nRead, round by round')
daemon = FakeDaemon()
sealed = isemon.seal_secret('s3cret')
reader = isemon.RosReader(daemon, 'gw', {'host': '127.0.0.1', 'port': router.port,
                                         'mode': 'pin', 'user': 'isemon-read',
                                         'password': sealed, 'every': 30})
router.conns = [
    {'.id': '*1', 'src-address': '192.168.40.12:50000', 'dst-address': '8.8.8.8:443',
     'reply-src-address': '8.8.8.8:443', 'reply-dst-address': '195.189.0.26:50000',
     'protocol': 'tcp', 'orig-bytes': '1000', 'repl-bytes': '50000', 'orig-packets': '10',
     'repl-packets': '40', 'tcp-state': 'established'},
    {'.id': '*2', 'src-address': '94.154.20.57:15023', 'dst-address': '195.189.0.26:443',
     'reply-src-address': '192.168.43.17:443', 'reply-dst-address': '94.154.20.57:15023',
     'protocol': 'tcp', 'orig-bytes': '700', 'repl-bytes': '9000'},
    {'.id': '*3', 'src-address': '10.0.0.5:5353', 'dst-address': '192.168.40.1:53',
     'reply-src-address': '192.168.40.1:53', 'reply-dst-address': '10.0.0.5:5353',
     'protocol': 'udp', 'orig-bytes': '80', 'repl-bytes': '120'}]
router.ppp = [{'name': 'jnovak', 'service': 'ovpn', 'caller-id': '89.21.67.173',
               'address': '10.9.9.2', 'uptime': '1h2m'}]
store_pin = daemon.store
reader.open()
ok('the first connection pins the certificate it is shown',
   store_pin.get_meta('rosapi_pin_gw'), fp)
reader.one_round()
ok('...nothing ended yet: three connections open', (daemon.handed and
                                                    [f['action'] for f in daemon.handed],
                                                    reader.state['conns']),
   (['perf-stats'], 3))
router.conns[0]['orig-bytes'] = '3000'
router.conns[0]['repl-bytes'] = '90000'
gone = router.conns.pop(0)
router.conns.pop(0)
daemon.handed.clear()
time.sleep(1.1)
reader.one_round()
sessions = {f['srcip']: f for f in daemon.handed if f['type'] == 'traffic'}
ok('two connections gone: two sessions that ended', sorted(sessions),
   ['192.168.40.12', '94.154.20.57'])
f = sessions['192.168.40.12']
ok('...with the bytes each way of its last look, how long it was seen, and the service',
   (f['sent'], f['rcvd'], f['duration'] >= 0, f['service'], f['sub'], f['verdict'], f['fw']),
   (1000, 50000, True, 'tcp/443', 'forward', 'allow', 'gw'))
ok('...what its source was made', (f['fields'].get('transip'), f['fields'].get('transport'),
                                   f['fields'].get('via')), ('195.189.0.26', '50000', 'api'))
f = sessions['94.154.20.57']
ok('...and a dst-nat\'s server inside', (f['fields'].get('tranip'), f['fields'].get('tranport'),
                                          isemon.fw_nat_said(f, f['fields']).get('natto')),
   ('192.168.43.17', '443', '192.168.43.17:443'))
ok('...through the router to that server, not to the router itself, though asked at its '
   'address', f['sub'], 'forward')
del gone
ok('a connection to the router itself is to the firewall itself',
   isemon.rosapi_session_of('gw', 'gw', router.conns[0], 0, 1, reader.mine)['sub'], 'local')
ok('the router\'s DHCP leases are learned for the sign-ins beside them',
   isemon.FRAD_LEARNED['dhcp'].get('98-E2-55-F8-0C-23', {}).get('host')
   or isemon.FRAD_LEARNED['dhcp'].get(isemon.mac_written('98:E2:55:F8:0C:23'), {}).get('host'),
   'Temp')

print('\nThe router as it is, for the Traffic tab\'s Router page')
snap = reader.router
ok('its interfaces with what they carry, its addresses and its routes',
   ([i['name'] for i in snap['interfaces']], [a['address'] for a in snap['addresses']],
    [r['dst-address'] for r in snap['routes']]),
   (['ether1', 'vCloud'], ['195.189.0.26/29', '192.168.40.1/24'], ['0.0.0.0/0']))
ok('...its leases, ARP, neighbours, rules with their counters, WireGuard and its health',
   (snap['leases'][0]['host-name'], snap['arp'][0]['mac-address'], snap['neighbors'][0]['identity'],
    (snap['rules'][0]['table'], snap['rules'][0]['bytes']), snap['wireguard'][0]['name'],
    snap['health']), ('Temp', '98:E2:55:F8:0C:23', 'sw1', ('filter', '1234'), 'laptop',
                      {'temperature': '41C'}))
router.arp_n = isemon.ROSAPI_LIST_MOST + 1
reader.read_arp(reader.session)
ok('a table larger than it is asked for at a time is counted first and not read',
   ([a['family'] for a in snap['arp']], snap['arp_left_out']),
   (['ipv6'], isemon.ROSAPI_LIST_MOST + 1))
router.arp_n = 1
reader.read_interfaces(reader.session, time.time() + 10)
ok('an interface\'s rate is worked out from two looks', 'rx-rate' in snap['interfaces'][1], True)
readers = isemon.RosReaders(daemon)
readers.readers['gw'] = reader
readers.wanted['gw'] = reader.api
reader.state['connected'] = True
got = readers.snapshot('gw')
ok('the page is given it whole, said how it was read', (got['via'], got['name'],
   bool(got['interfaces']), got['vpn'][0]['user'] if got['vpn'] else None), ('api', 'gw', True,
                                                                         'jnovak'))
ok('...and which routers are read', (readers.routers(), readers.snapshot('nope')), (['gw'], None))
readers.readers.clear()

print('\nIPv6 as well as IPv4, in everything read')
ok('a connection\'s end, however RouterOS writes it',
   [isemon.rosapi_end(x) for x in ('192.0.2.1:443', '[2001:db8::1]:443', '2001:db8::1.443',
                                   '2001:db8::1', '192.0.2.1')],
   [('192.0.2.1', 443), ('2001:db8::1', 443), ('2001:db8::1', 443), ('2001:db8::1', 0),
    ('192.0.2.1', 0)])
router.conns6 = [{'.id': '*1', 'src-address': '[2001:db8:40::15]:51000',
                  'dst-address': '[2a00:1450:4014::200e]:443',
                  'reply-src-address': '[2a00:1450:4014::200e]:443',
                  'reply-dst-address': '[2001:db8:40::15]:51000', 'protocol': 'tcp',
                  'orig-bytes': '500', 'repl-bytes': '7000'}]
daemon.handed.clear()
reader.read_connections(reader.session, time.time())
ok('IPv6\'s connections read too, apart from IPv4\'s with the same id',
   sorted(c for c in reader.conns if c.endswith('*1')), ['*1', '6*1'] if '*1' in reader.conns
   else ['6*1'])
router.conns6 = []
reader.read_connections(reader.session, time.time() + 1)
v6 = [f for f in daemon.handed if f['type'] == 'traffic' and ':' in f['srcip']]
ok('...and one that ended is a session with its IPv6 ends, its port and its bytes',
   [(f['srcip'], f['srcport'], f['dstip'], f['dstport'], f['sent'], f['rcvd']) for f in v6],
   [('2001:db8:40::15', 51000, '2a00:1450:4014::200e', 443, 500, 7000)])
reader.read_arp(reader.session)
reader.read_rules(reader.session)
reader.read_leases(reader.session)
ok('IPv6 neighbours beside ARP, DHCPv6 beside DHCP, IPv6\'s rules beside IPv4\'s',
   ([(a['address'], a['family']) for a in reader.router['arp']],
    [b['address'] for b in reader.router['leases6']],
    sorted(set(r['table'] for r in reader.router['rules']))),
   ([('192.168.40.115', 'ipv4'), ('2001:db8:40::15', 'ipv6')], ['2001:db8:99::/56'],
    ['filter', 'ipv6 filter']))

print('\nThe same, over ssh')
ok('a print as the console writes it, a line an entry',
   isemon.RosSsh.command('/ip/firewall/connection/print', 'src-address,orig-bytes'),
   ':foreach r in=[/ip firewall connection print as-value proplist=src-address,orig-bytes] '
   'do={:put $r}')
ok('...one thing as one line, and a query as where',
   (isemon.RosSsh.command('/system/resource/print', 'version'),
    isemon.RosSsh.command('/user/print', 'name,group', ['name=isemon-read'])),
   (':put [/system resource print as-value proplist=version]',
    ':foreach r in=[/user print as-value proplist=name,group where name="isemon-read"] '
    'do={:put $r}'))
for bad in (('/ip/firewall/filter/add', None, None), ('/user/print', None, ['name=x";/system reboot']),
            ('/ip/address/print', 'address;x', None), ('/login', None, None)):
    try:
        isemon.RosSsh.command(*bad)
        said = None
    except isemon.RosApiError as e:
        said = str(e)
    ok('...refused, never written to a console: %s' % (bad,), bool(said), True)
ok('the answers read back as the API gives them, a broken line put back together',
   isemon.RosSsh.answers('.id=*1;src-address=1.2.3.4:5;orig-bytes=100\n'
                         '.id=*2;src-address=5.6.7.8:9;orig-bytes=2\n  00\n\n'),
   [{'.id': '*1', 'src-address': '1.2.3.4:5', 'orig-bytes': '100'},
    {'.id': '*2', 'src-address': '5.6.7.8:9', 'orig-bytes': '200'}])
said_cmds = []
real_run = isemon.ssh_run
def fake_run(cfg, host, command):
    said_cmds.append((cfg['ssh_auth'], cfg['ssh_user'], command))
    if 'count-only' in command:
        return '7\n'
    if 'identity' in command:
        return 'name=gw\n'
    if 'resource' in command:
        return 'version=7.16.1;board-name=RB5009;uptime=3d\n'
    if '/user print' in command:
        return 'name=isemon-read;group=isemon-read\n'
    if '/user group' in command:
        return 'name=isemon-read;policy=read,ssh,!write\n'
    if 'tracking' in command:
        return 'total-entries=3\n'
    return ''
isemon.ssh_run = fake_run
try:
    got = isemon.rosapi_probe({'host': '192.0.2.1', 'port': 22, 'mode': 'ssh',
                               'user': 'isemon-read', 'auth': 'key'}, '', '', 'PRIVATE')
    ok('tried over ssh with its key: who it is, and that it may only read',
       (got.get('ok'), got.get('identity'), got.get('version'), got.get('can_write'),
        got.get('via'), got.get('connections')), (True, 'gw', '7.16.1', False, 'ssh', 3))
    ok('...signed in with the key as the account', said_cmds[0][:2], ('key', 'isemon-read'))
    s2 = isemon.RosSsh('192.0.2.1', 22, 'isemon-read', '', 'K')
    s2.sock = True
    ok('...and how many, asked as count-only', (s2.count('/ip/route/print'), said_cmds[-1][2]),
       (7, ':put [/ip route print count-only]'))
    try:
        isemon.RosSsh('192.0.2.1', 22, 'isemon-read', '', '').connect()
        said = None
    except isemon.RosApiError as e:
        said = str(e)
    ok('...with no key kept: said so, nothing tried', 'no ssh key' in (said or ''), True)
finally:
    isemon.ssh_run = real_run
ok('the settings take ssh, with a key or a password, on 22',
   (isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ssh'}, 'gw')['port'],
    isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ssh'}, 'gw')['auth'],
    isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ssh', 'auth': 'password'},
                          'gw')['auth']), (22, 'key', 'password'))
cmds_ssh = isemon.rosapi_commands('isemon-read', '', ssh=True)
ok('what to type for ssh: a group that may read and sign in over ssh, and the key',
   ('policy=read,ssh,' in cmds_ssh and '!write' in cmds_ssh and '!api' in cmds_ssh
    and 'ssh-keys import' in cmds_ssh), True)

print('\nThe VPN as it stands, from the API')
reader.state['connected'] = True
live = reader.live()
ok('who is on it now, with where from and the address inside',
   [(c['user'], c['srcip'], c['inner']) for c in live['clients']],
   [('jnovak', '89.21.67.173', '10.9.9.2'), ('laptop', '', '')])
ok('...the tunnels: the IPsec peer and the OpenVPN client interface',
   sorted((t['kind'], t['peer']) for t in live['tunnels']),
   [('ipsec', '203.0.113.9'), ('ovpn-out', '')])
readers = isemon.RosReaders(daemon)
readers.readers['gw'] = reader
said = {'clients': [{'fw': 'gw', 'user': 'old'}, {'fw': 'hq', 'user': 'kept'}], 'tunnels': []}
got = readers.vpn_merged(said)
ok('the log\'s story of that router told by its API instead, the others\' as they were',
   sorted(c['user'] for c in got['clients']), ['jnovak', 'kept', 'laptop'])
ok('...one of them opened by its id', readers.vpn_one(live['clients'][0]['id'])['user'], 'jnovak')
reader.session.close()

print('\nA certificate of your own, kept as the ssh key is')
class MetaStore:
    def __init__(self):
        self.meta = {}
    def set_meta(self, k, v):
        self.meta[k] = v
    def get_meta(self, k, d=None):
        return self.meta.get(k, d)
    def drop_meta(self, k):
        self.meta.pop(k, None)
c2, k2, f2 = isemon.rosapi_pasted('junk\n' + cert + key)
ok('a pasted certificate with its key: both, and the same fingerprint', (c2.strip() == cert.strip(),
   'PRIVATE KEY' in k2, f2), (True, True, fp))
c3, k3, f3 = isemon.rosapi_pasted(cert)
ok('...the certificate alone: no key', (k3, f3), ('', fp))
for bad in ('', 'hello', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'):
    try:
        isemon.rosapi_pasted(bad)
        said = None
    except ValueError as e:
        said = str(e)
    ok('...refused, said why: %r' % bad[:20], bool(said), True)
ms = MetaStore()
isemon.rosapi_cert_keep(ms, 'gw', cert, key, fp)
ok('kept: pinned, the certificate, its key sealed', (ms.get_meta('rosapi_pin_gw'),
   ms.get_meta('rosapi_cert_gw') == cert, 'PRIVATE KEY' not in ms.get_meta('rosapi_certkey_gw'),
   isemon.unseal_secret(ms.get_meta('rosapi_certkey_gw')) == key), (fp, True, True, True))
isemon.rosapi_cert_keep(ms, 'gw', cert, '', fp)
ok('...one given without its key drops the old key', ms.get_meta('rosapi_certkey_gw'), None)

print('\nThe settings')
row = isemon.fw_sources_checked([
    {'name': 'gw', 'type': 'routeros', 'path': '/var/log/remote/gw', 'files': '*.log',
     'api': {'on': 1, 'host': '192.0.2.1', 'mode': 'pin', 'user': 'isemon-read',
             'password': 'x', 'every': 5}},
    {'name': 'fg', 'type': 'fortigate', 'path': '/var/log/remote/fg', 'files': '*.log',
     'api': {'on': 1, 'host': '192.0.2.2'}}])
ok('a MikroTik\'s row keeps its API, checked; any other row has none',
   (row[0]['api']['every'], row[0]['api']['port'], 'api' in row[1]), (10, 8729, False))
try:
    isemon.fw_sources_checked([{'name': 'gw', 'type': 'routeros', 'path': '/x',
                                'api': {'on': 1, 'host': ''}}])
    ok('switched on with no address is refused', False)
except ValueError as e:
    ok('switched on with no address is refused', 'address' in str(e))
masked = isemon.rosapi_masked(row)
ok('the page is never given the password, only its dots and that there is one',
   (masked[0]['api']['password'], masked[0]['api']['password_set']), ('\u2022', True))
kept = isemon.rosapi_kept_passwords(
    [{'name': 'gw', 'type': 'routeros', 'path': '/x', 'api': {'on': 1, 'host': 'a',
                                                             'password': ''}},
     {'name': 'gw2', 'type': 'routeros', 'path': '/y', 'api': {'on': 1, 'host': 'b',
                                                              'password': 'new'}}],
    [{'name': 'gw', 'api': {'password': 'sealed:1:old'}}])
ok('a password left empty is the one saved; a new one is sealed',
   (kept[0]['api']['password'], kept[1]['api']['password'].startswith(isemon.SEALED),
    isemon.unseal_secret(kept[1]['api']['password'])), ('sealed:1:old', True, 'new'))
cmds = isemon.rosapi_commands('isemon-read', '192.0.2.50')
ok('what to type on the router: a group that may only read and use the API',
   ('policy=read,api,' in cmds and '!write' in cmds and 'address=192.0.2.50' in cmds
    and 'api-ssl certificate=isemon-api.pem_0' in cmds
    and 'file-name=isemon-api.pem' in cmds), True)
isemon.CONFIG['fwlog_sources'] = row
ok('a MikroTik whose API is read has its translations on the NAT page',
   isemon.fw_nat_in_sessions(), True)
ok('the readers wanted are the MikroTiks switched on with an address',
   list(isemon.RosReaders.configured()), ['gw'])

print('\nThe page')
ok('a MikroTik\'s row has the API under it, with its switch',
   "if (one.type === 'routeros') {" in page and 'function rosApiPanel(' in page
   and "'Read more of it through its API or over ssh'" in page)
ok('...try it, make a certificate, use my own, download it, forget it',
   all(w in page for w in ("do: 'test'", "do: 'cert'", "do: 'paste'", "do: 'download'",
                           "do: 'forget'")))
ok('...drawn as the banning\'s firewall is: fields, lines of state, the key panel',
   all(w in page for w in ("var card = el('div', 'card full rosapi');",
                           "cmdButton('Make a certificate', 'key', 'admin-only')",
                           "cmdButton('Use my own', 'upload', 'admin-only')",
                           "cmdButton('Download it', 'download', 'admin-only')",
                           "cmdButton('Forget it', 'forget', 'danger admin-only')",
                           "cmdButton('Try reaching it', 'pulse', 'primary')",
                           "cmdButton('How to set it up on the router\u2026', 'info')",
                           "kvInto(kv, 'Right now'")))
ok('...the certificate as one line, as the ssh key\'s public half, and a click downloads it',
   "var code = el('code', 'copyme', file + ' ' + pin);" in page
   and "api('rosapi', {do: 'download', name: nameNow()}).then(rosApiSave)" in page
   and "'certificate' in" not in page)
ok('...over ssh, the banning\'s key panel: make, use my own, download, forget, the public half',
   all(w in page for w in ("function rosSshKeyPanel(", "do: 'keygen'", "do: 'key'",
                           "do: 'key-download'", "do: 'key-forget'",
                           "cmdButton('Make a key', 'key', 'admin-only')",
                           "'The public half. Click it to copy.'",
                           "['ssh', 'Over ssh, with a key or a password (22)']")))
ok('...the panel by the way it is reached: the certificate or the key',
   "card.appendChild(rosSshKeyPanel(cfg, nameNow, words, s, sshKey, test, need, paint));" in page)
ok('the Traffic tab has the router as it is, only where one is read',
   all(w in page for w in ('data-page="router" aria-selected="false" hidden',
                           'id="t-page-router" hidden', "'fw-router' => '/api/fw/router',",
                           "function drawOneRouter(", "b.hidden = !(mine.length || TPAGE === 'router');")))
ok('...and the daemon answers for it', "if path == '/api/fw/router':" in src)
ok('...and a new key or certificate opens the session again',
   src.count('daemon.rosapi.restart(name)') == 5)
ok('...and off, the switch is all there is of it', "if (!cfg.on) return card;" in page)
ok('...the password never shown, left as it is to keep it', "cfg.password_set ? 'set" in page)
ok('...saved only on a MikroTik\'s row', "if (one.type === 'routeros' && one.api) {" in page)
ok('the daemon is asked through the page\'s own road', "'rosapi'       => '/api/rosapi'," in page)
ok('the daemon starts and stops the readers as the settings say',
   'self.rosapi = RosReaders(self)' in src and 'self.rosapi.sync()' in src
   and 'self.rosapi.stop_all()' in src)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
