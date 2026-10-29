#!/usr/bin/env python3
"""1.10.203: a MikroTik's own log on the Traffic tab, and a FreeRADIUS of the
site's own - MAB, 802.1X on the LAN and on Wi-Fi, the VPN - with its VPN
refusals counted for a ban.

    ./test/fixes203.py
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
folder = Path(tempfile.mkdtemp(prefix='isemon-203-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time()
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(datetime.fromtimestamp(NOW - 120))
H = '%s gw.example.net ' % STAMP

print('\nMikroTik RouterOS')
ok('a kind of firewall, every file of a folder followed',
   ('routeros' in isemon.FW_TYPES, 'routeros' in isemon.FW_EVERY_FILE), (True, True))


def one(text):
    got = isemon.ros_parse_lines([H + text], {}, now=NOW)
    return got[0].facts if got else None


f = one('firewall,info DROP-FOR - IPv4 forward: in:LAN out:SRV, connection-state:new '
        'src-mac BC:FC:E7:D7:86:70, proto TCP (SYN), 192.168.40.12:57656->192.168.42.31:21, '
        'len 52')
ok('a refused packet: both ends, the interfaces, the prefix as its policy',
   (f['type'], f['verdict'], f['srcip'], f['srcport'], f['dstip'], f['dstport'], f['proto'],
    f['srcintf'], f['dstintf'], f['policyname'], f['dev'], isemon.fw_area(f)),
   ('traffic', 'deny', '192.168.40.12', 57656, '192.168.42.31', 21, 6, 'LAN', 'SRV',
    'DROP-FOR - IPv4', 'gw.example.net', 'session'))
ok('...the MAC and the state kept beside it',
   (f['fields'].get('srcmac'), f['fields'].get('connectionstate')),
   ('BC:FC:E7:D7:86:70', 'new'))
f = one('firewall,info DROP-SRV-IPv6 forward: in:VLAN108 out:SRV, packet-mark:Download '
        'connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
        '[2604:a880:400:d1:0:5:35a0:d001]:48918->[2a02:7a00:e::10]:5986, len 40')
ok('IPv6 in brackets with its ports',
   (f['srcip'], f['srcport'], f['dstip'], f['dstport']),
   ('2604:a880:400:d1:0:5:35a0:d001', 48918, '2a02:7a00:e::10', 5986))
f = one('firewall,info DROP-DMZ-IPv6 forward: in:VLAN108 out:DMZ, connection-state:new '
        'src-mac 44:31:92:3E:5E:CA, proto ICMP (type 128, code 0), '
        '2600:1f18:5b54:f901:5b35:832:9ace:983b->2a02:7a00:e:4::16, len 16')
ok('...and bare, with no ports', (f['srcip'], f['dstip'], f['dstport']),
   ('2600:1f18:5b54:f901:5b35:832:9ace:983b', '2a02:7a00:e:4::16', 0))
f = one('firewall,info input: in:ether1 out:(unknown 0), connection-state:new proto UDP, '
        '203.0.113.5:5353->198.51.100.1:53, len 60')
# 1.10.206: a line no word of the prefix decides is let through by default
# (`fwlog_ros_plain`), and only said where the setting says so.
ok('no prefix: let through by default, the router itself as the destination',
   (f['verdict'], f['sub'], f['dstintf']), ('allow', 'local', ''))
f = one('firewall,info ACCEPT-WEB forward: in:WAN out:DMZ, connection-state:new,dnat proto '
        'TCP (SYN), 203.0.113.5:40000->192.0.2.10:443, NAT (203.0.113.5:40000->198.51.100.1:443)'
        '->(203.0.113.5:40000->192.0.2.10:443), len 60')
ok('a pass, with its address translation', (f['verdict'], 'nat' in f['fields']),
   ('allow', True))
f = one('system,error,critical login failure for user admin from 203.0.113.77 via ssh')
ok('a refused sign-in to the router: at the firewall, earning a ban',
   (f['verdict'], f['action'], f['user'], f['srcip'], isemon.fw_area(f)),
   ('fail', 'login', 'admin', '203.0.113.77', 'admin'))
f = one('system,info,account user Admin logged in from 192.168.40.12 via winbox')
ok('a sign-in to it', (f['action'], f['user'], f['srcip'], f['fields'].get('ui'),
                       isemon.fw_area(f)),
   ('login', 'Admin', '192.168.40.12', 'winbox', 'admin'))
f = one('system,info address list entry added by ssh-cmd:zigmon@192.168.40.233 (*1D41 = /ip '
        'firewall address-list add address=47.79.13.11 list=ZigMon)')
ok('a change to the configuration, by whom and from where',
   (f['action'], f['user'], f['srcip'], f['fields'].get('cfgpath'), isemon.fw_area(f)),
   ('added', 'zigmon', '192.168.40.233', 'address list entry', 'admin'))
hold = {}
up = isemon.ros_parse_lines([H + 'ovpn,info,account jnovak logged in, 10.8.0.6 from 198.51.100.9'],
                            hold, now=NOW)[0].facts
down = isemon.ros_parse_lines([H + 'ovpn,info,account jnovak logged out, 3600 1234 5678 9 10'],
                              hold, now=NOW)[0].facts
ok('somebody\'s VPN: up with the address inside, down with how long and how much',
   (isemon.fw_area(up), up['action'], up['srcip'], up['fields'].get('assigned'),
    down['action'], down['srcip'], down['duration'], down['rcvd'], down['sent']),
   ('client-vpn', 'tunnel-up', '198.51.100.9', '10.8.0.6', 'tunnel-down', '198.51.100.9', 3600,
    1234, 5678))
f = one('ovpn,info Merit: disconnected <administrator request>')
ok('a tunnel to another site, by its interface', (isemon.fw_area(f), f['action'],
                                                  f['fields'].get('reason')),
   ('s2s-vpn', 'tunnel-down', 'administrator request'))
ok('each packet of a tunnel is left out',
   isemon.ros_parse_lines([H + 'ovpn,debug,packet sent P_ACK kid=0 sid=27977d53 DATA len=0'],
                          {}, now=NOW), [])
two = isemon.ros_parse_lines([H + 'firewall,info DROP forward: in:A out:B, proto UDP, '
                              '1.2.3.4:1->5.6.7.8:2, len 1'] * 2, {}, now=NOW)
ok('the same line twice in one second is two rows', len({r.facts['ident'] for r in two}), 2)
ok('a line that is not RouterOS\'s is not read',
   isemon.ros_parse_lines(['Oct  1 07:56:02 fw date=2026-10-01 type="traffic"'], {}), [])
fw_sources = isemon.fw_sources_checked([{'name': 'gw', 'type': 'routeros', 'path': '/tmp'}])
ok('...and the settings take it', fw_sources[0]['type'], 'routeros')

print('\nFreeRADIUS of the site\'s own')
isemon.CONFIG.update({'radius': 1, 'radius_paths': [str(folder / 'radius')],
                      'radius_lan_clients': 'sw*', 'radius_wifi_clients': '',
                      'block_tries': 2, 'block_window_min': 10})
(folder / 'radius').mkdir()
R = datetime.fromtimestamp(NOW - 60)
# The day padded with a space, as syslog and FreeRADIUS write it - and the
# hour never: `09:47`, not ` 9:47` (which made this fail every morning).
raw = R.strftime('%a %b ') + '%2d' % R.day + R.strftime(' %H:%M:%S %Y')
syslog = R.strftime('%b ') + '%2d' % R.day + R.strftime(' %H:%M:%S')
lines = [
    '%s radius radiusd: %s : Auth: (10) Login OK: [laptop/<via Auth-Type = eap>] '
    '(from client AP port 1 cli 20-E2-A8-7D-9E-4D)' % (syslog, raw),
    '%s : Auth: (11) Login OK: [aabbccddeeff/aabbccddeeff] (from client sw1 port 50124 cli '
    'AA-BB-CC-DD-EE-FF)' % raw,
    '%s : Auth: (12) Login incorrect (mschap: MS-CHAP2-Response is incorrect): '
    '[jnovak/<via Auth-Type = eap>] (from client vpngw port 0 cli 185.220.10.9)' % raw,
    '%s : Auth: (12) Login incorrect: [jnovak/<via Auth-Type = eap>] (from client vpngw port 0 '
    'cli 185.220.10.9)' % raw,
    '%s : Auth: (13) Login incorrect (pap: Password mismatch): [admin/hunter2] (from client '
    'vpngw port 0 cli 185.220.10.9)' % raw,
    '%s : Auth: (14) Login OK: [laptop/<via Auth-Type = eap>] (from client AP port 0 via TLS '
    'tunnel)' % raw,
    '%s : Auth: (15) Login incorrect (pap: Password mismatch): [eve/x] (from client vpngw port 0 '
    'cli 2A01-4F8--5)' % raw,
]
(folder / 'radius' / 'radius.log').write_text('\n'.join(lines) + '\n')
ok('its files: the log, as a source of its own',
   [(k, Path(p).name) for k, p, _s in daemon.log_files() if k.startswith('radius')],
   [('radius', 'radius.log')])
recs = daemon.parser_for('radius', str(folder / 'radius' / 'radius.log'))(lines, {}, NOW)
ok('one record per sign-in: the pair folded, the inner half of EAP left out', len(recs), 5)
ok('...the server\'s own file named after its folder', recs[1].server, 'radius')
for r in recs:
    daemon.take_record('radius', r)
rows = {r['username']: dict(r) for r in store.db.execute(
    'SELECT username, kind, ip, mac, port, device FROM failed UNION ALL '
    'SELECT username, kind, ip, mac, port, device FROM passed')}
ok('an address as the calling station is the VPN, with the address',
   (rows['jnovak']['kind'], rows['jnovak']['ip'], rows['jnovak']['mac']),
   ('radius-vpn', '185.220.10.9', ''))
ok('...an IPv6 one as well', (rows['eve']['kind'], rows['eve']['ip']),
   ('radius-vpn', '2a01:4f8::5'))
ok('the MAC as the name is MAB, on the LAN through a switch named so, at its port',
   (rows['aabbccddeeff']['kind'], rows['aabbccddeeff']['port']),
   ('radius-mab-lan', 'GigabitEthernet1/0/24'))
ok('802.1X through a client nothing says anything of is something else',
   rows['laptop']['kind'], 'radius-other')
kept = ' '.join(str(v) for t in ('failed', 'passed')
                for r in store.db.execute('SELECT * FROM %s' % t) for v in dict(r).values())
kept += ' '.join(str(store.unpack_detail(r['detail'])) for t in ('failed', 'passed')
                 for r in store.db.execute('SELECT detail FROM %s' % t))
ok('the password FreeRADIUS wrote is not kept anywhere', 'hunter2' in kept, False)
detail = ['%s' % R.strftime('%a %b %d %H:%M:%S %Y'), '\tAcct-Status-Type = Start',
          '\tUser-Name = "laptop"', '\tNAS-Port-Type = Wireless-802.11',
          '\tCalled-Station-Id = "9A-2A-6F-B2-E8-DA:Staff"',
          '\tCalling-Station-Id = "20-E2-A8-7D-9E-4D"', '\tFramed-IP-Address = 192.168.40.103',
          '\tTimestamp = %d' % int(NOW - 55), '']
for s in isemon.frad_detail_lines(detail, {}):
    daemon.take_record('radius-detail', s)
ok('the accounting puts the sign-in just before it on its door',
   store.db.execute("SELECT kind FROM passed WHERE username='laptop'").fetchone()[0],
   'radius-dot1x-wifi')
ok('...and the next one goes there straight away',
   isemon.frad_door('AP', '20-E2-A8-7D-9E-4D', 'laptop',
                    daemon.radius_medium_of('20-E2-A8-7D-9E-4D')), ('radius-dot1x-wifi', ''))
isemon.CONFIG['radius_wifi_clients'] = 'ap*'
ok('a client named as a radio is Wi-Fi', isemon.frad_door('AP', 'F4-CB-E7-D1-63-75', 'x')[0],
   'radius-dot1x-wifi')
ok('the doors are offered once something came through', sorted(daemon.radius_doors()),
   ['radius-dot1x-wifi', 'radius-mab-lan', 'radius-vpn'])

print('\nA refusal inside EAP, and what a module quoted')
peap = isemon.frad_parse_lines([
    '%s : Auth: (20) Login incorrect (mschap: MS-CHAP2-Response is incorrect): [bob/<via '
    'Auth-Type = eap>] (from client AP port 0 via TLS tunnel)' % raw,
    '%s : Auth: (21) Login incorrect (eap_peap: The users session was previously rejected: '
    'returning reject (again.) ): [bob/<via Auth-Type = eap>] (from client AP port 3 cli '
    'F4-CB-E7-D1-63-75)' % raw,
    '%s : Auth: (22) Login incorrect (rlm_pap: Cleartext password "s3cret" does not match '
    '"known good" password): [eve/s3cret] (from client vpn port 0 cli 185.1.2.3)' % raw], {})
ok('one refusal, the outer one, with the machine and what the inner one said',
   [(r.user, isemon.ise_first(r.fields, 'Calling-Station-ID'),
     isemon.ise_first(r.fields, 'Inner said')) for r in peap][:1],
   [('bob', 'F4-CB-E7-D1-63-75', 'mschap: MS-CHAP2-Response is incorrect')])
ok('...a reason with brackets in it is still read', len(peap), 2)
ok('a password a module quoted is not kept', 's3cret' in repr([r.flat() for r in peap]), False)
acct = folder / 'raddb'
(acct / 'radacct' / '192.0.2.9').mkdir(parents=True)
(acct / 'radacct' / '192.0.2.9' / 'detail-20261018').write_text('')
ok('the accounting where FreeRADIUS keeps it, radacct/<client>/',
   [Path(p).parent.name for p in daemon.radius_details(str(acct))], ['192.0.2.9'])
ok('a prefix\'s verdict is its words, not letters inside one',
   (isemon.ros_verdict('URBAN-LOG'), isemon.ros_verdict('BYPASS'), isemon.ros_verdict('in_drop'),
    isemon.ros_verdict('BLOCKED-WAN'), isemon.ros_verdict('accept-dns'),
    isemon.ros_verdict('URBAN-LOG', 'invalid')),
   ('allow', 'allow', 'deny', 'deny', 'allow', 'info'))

print('\nBanning from it')
ok('a source of its own, counted by its own pass, off until switched on',
   ('radius' in isemon.BAN_SOURCES, 'radius' in isemon.BAN_COUNTED_SOURCES,
    isemon.DEFAULTS['ban_from_radius']), (True, True, 'off'))
ok('...counting its VPN refusals and nothing else',
   sorted(ip for ip, _n, _t in store.source_failures('radius', NOW - 600, 1)),
   ['185.220.10.9', '2a01:4f8::5'])
daemon.judge_sources()
ok('switched off, nothing is banned', store.blocked_until('185.220.10.9'), None)
isemon.CONFIG['ban_from_radius'] = 'on'
daemon.judge_sources()
ok('switched on, two refusals in the window ban the address',
   store.blocked_until('185.220.10.9') is not None, True)
why = store.db.execute("SELECT why FROM blocked WHERE ip='185.220.10.9'").fetchone()[0]
ok('...saying why', 'VPN login(s) through FreeRADIUS' in why, True)

print('\nThe page')
for words in ('data-pane="radius"', 'id="pane-radius"', "isRadiusKind(kind)",
              "door: 'radius-network'", "'radius-vpn': 'FreeRADIUS VPN'",
              "['radvpn', '#ff7b72']", "'ban_from_radius'", '<b>MikroTik RouterOS</b>'):
    ok('it has %s' % words, words in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
