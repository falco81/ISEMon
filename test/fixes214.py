#!/usr/bin/env python3
"""1.10.214: what a MikroTik's API says, told into the Traffic tab - its
sessions' interfaces, names, MACs and people, who is busiest now, its
interfaces over a day, its VPN's bytes, WireGuard, and the VPNs it dials out
on."""
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.argv = ['isemon']
import isemon  # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


class Store(object):
    def __init__(self):
        self.meta = {}

    def get_meta(self, k, d=None):
        return self.meta.get(k, d)

    def set_meta(self, k, v):
        self.meta[k] = v


class Daemon(object):
    def __init__(self):
        self.store = Store()
        self.handed = []

    def fw_hand_in(self, many):
        self.handed.extend(many)


class Session(object):
    """A router's answers, by menu."""
    sock = True

    def __init__(self, menus):
        self.menus = menus

    def talk(self, command, args=None, proplist=None, query=None):
        if command not in self.menus:
            raise isemon.RosApiError('no such command')
        return [dict(r) for r in self.menus[command]]

    def count(self, command, query=None):
        return len(self.menus.get(command, []))


menus = {
    '/ip/address/print': [
        {'address': '192.168.40.1/24', 'network': '192.168.40.0', 'interface': 'LAN'},
        {'address': '195.189.0.26/29', 'network': '195.189.0.24', 'interface': 'VLAN108'},
        {'address': '10.10.12.10/24', 'network': '10.10.12.0', 'interface': 'vCloud',
         'dynamic': 'true'},
        {'address': '192.168.43.1/24', 'network': '192.168.43.0', 'interface': 'DMZ'}],
    '/ipv6/address/print': [{'address': '2a02:7a00:e:2::1/64', 'interface': 'LAN'}],
    '/ip/route/print': [
        {'dst-address': '0.0.0.0/0', 'immediate-gw': '195.189.0.25%VLAN108', 'active': 'true',
         'routing-table': 'main'},
        {'dst-address': '0.0.0.0/0', 'immediate-gw': '192.168.47.254%ether3-LTE',
         'active': 'true', 'routing-table': 'vrf-lte'},
        {'dst-address': '10.1.0.0/16', 'gateway': '10.10.12.1', 'active': 'true',
         'routing-table': 'main'},
        {'dst-address': '192.168.39.0/24', 'gateway': '172.16.1.4', 'active': 'false'}],
    '/ipv6/route/print': [{'dst-address': '::/0', 'immediate-gw': '2a02:7a00::31%VLAN108',
                           'active': 'true'}],
    '/ip/arp/print': [{'address': '192.168.40.140', 'mac-address': 'C8:BC:C8:E0:62:A3',
                       'interface': 'LAN'}],
    '/ipv6/neighbor/print': [],
    '/ip/dhcp-server/lease/print': [{'address': '192.168.40.140', 'host-name': 'Jan-MacBook',
                                     'mac-address': 'C8:BC:C8:E0:62:A3', 'status': 'bound'}],
    '/ip/dns/cache/print': [{'name': 'www.example.com', 'type': 'A', 'data': '93.184.216.34'},
                            {'name': 'x.example.net', 'type': 'CNAME', 'data': 'y.example'}],
    '/interface/print': [
        {'name': 'VLAN108', 'type': 'vlan', 'running': 'true', 'rx-byte': '1000',
         'tx-byte': '2000'},
        {'name': 'vCloud', 'type': 'ovpn-out', 'running': 'true', 'rx-byte': '500',
         'tx-byte': '700', 'last-link-up-time': '2026-10-18 22:43:03'},
        {'name': 'MUZabreh', 'type': 'ovpn-out', 'running': 'false', 'disabled': 'true'},
        {'name': '<ovpn-jnovak>', 'type': 'ovpn-in', 'running': 'true', 'rx-byte': '4000',
         'tx-byte': '90000'}],
    '/ppp/active/print': [{'name': 'jnovak', 'service': 'ovpn', 'caller-id': '89.21.67.173',
                           'address': '10.9.9.2', 'uptime': '1h'}],
    '/interface/ovpn-client/print': [
        {'name': 'vCloud', 'connect-to': 'vpn.vcloud.example', 'user': 'falco',
         'running': 'true'},
        {'name': 'MUZabreh', 'connect-to': '203.0.113.7', 'disabled': 'true'}],
    '/interface/wireguard/peers/print': [
        {'interface': 'wg0', 'name': 'phone', 'allowed-address': '10.7.0.2/32',
         'current-endpoint-address': '89.24.1.1', 'last-handshake': '40s', 'rx': '300',
         'tx': '400'},
        {'interface': 'wg1', 'name': 'office', 'endpoint-address': 'office.example',
         'current-endpoint-address': '198.51.100.9', 'allowed-address': '10.50.0.0/16',
         'last-handshake': '1m', 'rx': '10', 'tx': '20'},
        {'interface': 'wg0', 'name': 'old', 'allowed-address': '10.7.0.3/32',
         'last-handshake': '3h'}],
    '/ip/ipsec/active-peers/print': [],
    '/system/resource/print': [{'version': '7.23.5'}],
    '/system/health/print': [],
}
daemon = Daemon()
reader = isemon.RosReader(daemon, 'gw', {'host': 'gw', 'every': 30, 'mode': 'pin'})
s = Session(menus)
reader.session = s
reader.read_addresses(s)
reader.read_routes(s)
reader.read_arp(s)
reader.read_leases(s)
reader.read_dns(s)
reader.build_nets()
now = time.time()
reader.read_interfaces(s, now)
reader.read_vpn(s, now)
reader.read_wireguard(s, now)
reader.read_vpn_out(s, now)

print('\nA session told what the router knows')
ok('the interface an address is on: its own networks, then its routes, the longest first',
   [reader.intf_of(ip) for ip in ('192.168.40.140', '8.8.8.8', '10.1.2.3', '192.168.39.5',
                                  '2a02:7a00:e:2::5', '2001:db8::1', 'nonsense')],
   ['LAN', 'VLAN108', 'vCloud', 'VLAN108', 'LAN', 'VLAN108', ''])
ok('...only the main table\'s routes in use, and its way out is said',
   reader.router['wan'], ['VLAN108'])
f = {'srcip': '192.168.40.140', 'dstip': '93.184.216.34', 'sub': 'forward', 'fields': {}}
reader.enrich(f)
ok('a session out: in by LAN, out by the way out, the name asked for, its MAC and machine',
   (f['srcintf'], f['dstintf'], f['host'], f['fields'].get('srcmac'), f['fields'].get('srcname')),
   ('LAN', 'VLAN108', 'www.example.com', isemon.mac_written('C8:BC:C8:E0:62:A3'),
    'Jan-MacBook'))
f = {'srcip': '89.1.1.1', 'dstip': '195.189.0.26', 'sub': 'forward',
     'fields': {'tranip': '192.168.43.17'}}
reader.enrich(f)
ok('...a dst-nat: out by the interface of the server inside', (f['srcintf'], f['dstintf']),
   ('VLAN108', 'DMZ'))
f = {'srcip': '10.9.9.2', 'dstip': '192.168.40.140', 'sub': 'forward', 'fields': {}}
reader.enrich(f)
ok('...from the address its VPN gave somebody: that person', f.get('user'), 'jnovak')
f = {'srcip': '89.1.1.1', 'dstip': '195.189.0.26', 'sub': 'local', 'fields': {}, 'host': 'x'}
reader.enrich(f)
ok('...to the router itself: the way in only, and nothing said over', (f['srcintf'],
   f.get('dstintf', ''), f['host']), ('VLAN108', '', 'x'))
ok('the names its DNS answered: addresses only', reader.dns, {'93.184.216.34': 'www.example.com'})

print('\nWho is busiest now')
reader.conns_at = now - 10
menus['/ip/firewall/connection/tracking/print'] = [{'total-entries': '2'}]
menus['/ip/firewall/connection/print'] = [
    {'.id': '*1', 'src-address': '192.168.40.140:5000', 'dst-address': '93.184.216.34:443',
     'reply-src-address': '93.184.216.34:443', 'protocol': 'tcp', 'orig-bytes': '1000',
     'repl-bytes': '50000'},
    {'.id': '*2', 'src-address': '89.1.1.1:6000', 'dst-address': '195.189.0.26:443',
     'reply-src-address': '192.168.43.17:443', 'protocol': 'tcp', 'orig-bytes': '100',
     'repl-bytes': '200'}]
menus['/ipv6/firewall/connection/print'] = []
reader.read_connections(s, now)
busy = reader.router['talkers']
ok('by source, by where it went (the server inside a dst-nat), by service, as rates',
   ([b['key'] for b in busy['src']], [b['key'] for b in busy['dst']],
    busy['service'][0]['key'], busy['src'][0]['in']),
   (['192.168.40.140', '89.1.1.1'], ['93.184.216.34', '192.168.43.17'], 'tcp/443', 40000))
menus['/ip/firewall/connection/print'][0]['repl-bytes'] = '60000'
reader.read_connections(s, now + 10)
busy = reader.router['talkers']
ok('...the next look: only what it carried since', busy['src'][0]['in'], 8000)
menus['/ip/firewall/connection/print'] = []
daemon.handed.clear()
reader.read_connections(s, now + 20)
ok('the sessions that ended carry it all', sorted((f['srcintf'], f['dstintf'], f['host'])
                                                   for f in daemon.handed),
   [('LAN', 'VLAN108', 'www.example.com'), ('VLAN108', 'DMZ', '')])

print('\nIts VPN')
reader.state['connected'] = True
live = reader.live()
people = {c['user']: c for c in live['clients']}
ok('a person on it carries the bytes of the interface made for them',
   (people['jnovak']['sent'], people['jnovak']['rcvd']), (4000, 90000))
ok('a WireGuard peer heard from lately that comes in is a person; one long silent is not',
   (sorted(people), people['phone']['srcip'], people['phone']['inner'], people['phone']['kind']),
   (['jnovak', 'phone'], '89.24.1.1', '10.7.0.2', 'wireguard'))
tunnels = {t['name']: t for t in live['tunnels']}
ok('the VPNs it dials out on: where to, since when, with the bytes; one switched off is not up',
   (sorted(tunnels), tunnels['vCloud']['peer'], tunnels['vCloud']['local'],
    tunnels['vCloud']['sent'], bool(tunnels['vCloud']['since']), tunnels['vCloud']['direction']),
   (['office', 'vCloud'], 'vpn.vcloud.example', '10.10.12.10', 700, True, 'out'))
ok('...a WireGuard peer it goes to is a tunnel out', (tunnels['office']['kind'],
                                                       tunnels['office']['peer']),
   ('wireguard', '198.51.100.9'))
ok('...and every one, down too, for the Router page',
   sorted((r['name'], r['running']) for r in reader.router['vpn_out']),
   [('MUZabreh', False), ('office', True), ('vCloud', True)])
ok('a RouterOS time, 7 and 6', (bool(isemon.rosapi_when('2026-10-18 22:43:03')),
                                bool(isemon.rosapi_when('oct/18/2026 22:43:03')),
                                isemon.rosapi_when('')), (True, True, 0.0))

print('\nIts interfaces over a day')
reader.read_interfaces(s, now + 300)
menus['/interface/print'][0]['rx-byte'] = '6000'
reader.read_interfaces(s, now + 600)
rows = reader.if_hist.get('VLAN108') or []
ok('what each carried, five minutes a bucket', sum(r[1] for r in rows), 5000)
readers = isemon.RosReaders(daemon)
readers.readers['gw'] = reader
ok('...given to the page one interface at a time', readers.history('gw', 'VLAN108') == rows
   and readers.history('nope', 'x') is None, True)
snap = readers.snapshot('gw')
ok('...and the page told which have any', 'VLAN108' in snap['hist_names'], True)
readers.readers.clear()

page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE / 'isemon.py').read_text(encoding='utf-8')
print('\nThe page')
ok('the Router page has who is busiest now, the VPNs out and an interface over a day',
   all(w in page for w in ("function trBusiest(", "'VPNs it dials out on'",
                           "function trHistory(", "&hist=")))
ok('the overview says what goes through its way out now, only where one is read',
   "function tRouterCard(" in page and "id = 't-card-router'" in page)
ok('nothing of it for a firewall whose API is not read: the sessions told in the reader only',
   src.count('self.enrich(f)') == 1)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
