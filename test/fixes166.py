#!/usr/bin/env python3
"""1.10.166: every search box offers the columns of the card it is on, and
each field finds what its column SHOWS - on every door of the sign-ins and
the refusals, the domain, the bans, the Traffic page.

    ./test/fixes166.py
"""
import json
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19000 + random.randint(0, 900)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path))
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


folder = tempfile.mkdtemp(prefix='isemon-166-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time() - 600


def passed(session, kind, **more):
    row = {'session': session, 'ts': more.pop('ts', NOW), 'kind': kind, 'ip': '',
           'server': 'node1'}
    row.update(more)
    store.add_passed(row)


def failed(session, kind, **more):
    row = {'session': session, 'ts': more.pop('ts', NOW), 'kind': kind, 'ip': '',
           'server': 'node1'}
    row.update(more)
    store.add_failed(row)


def seen(mac, **facts):
    facts.update({'mac': mac, 'ts': NOW, 'status': 'Start'})
    store.note_eduroam_session(facts)


# ---- the rows ----------------------------------------------------------------
# eduroam: the record holds the controller's address; the card's Address,
# Access point, Network and VLAN are out of the accounting beside it.
passed('edu-1', 'eduroam', ip='10.250.0.5', username='jk@example.org', realm='example.org',
       mac='02-16-3B-82-20-F5', device='wlc9800', tkey='jk@example.org', server='rad1')
passed('edu-2', 'eduroam', ip='10.250.0.5', username='pn@example.net', realm='example.net',
       mac='AA-16-3B-82-20-01', device='wlc5500', tkey='pn@example.net', server='rad1')
seen('02-16-3B-82-20-F5', client='10.88.12.179', ap='AP-EAST-1', ssid='eduroam',
     vlan='1111', device='wlc9800', calls_itself='Phone One', realm='example.org',
     account='jk@example.org')
seen('AA-16-3B-82-20-01', client='10.9.9.9', ap='AP-WEST-2', ssid='eduroam-guest',
     vlan='2222', device='wlc5500', calls_itself='Pixel', realm='example.net',
     account='pn@example.net')
failed('edu-f1', 'eduroam', ip='10.250.0.5', username='jk@example.org', realm='example.org',
       mac='02-16-3B-82-20-F5', device='wlc9800', reason='the password was wrong')
# ISE wireless: the Address column is the machine's (`client`); `ip` is not.
passed('wifi-1', 'dot1x-wifi', ip='10.0.0.1', client='172.25.1.50', username='novak',
       mac='98-FC-84-E0-29-D6', device='wlc1', port='AP_7', ssid='staff',
       tkey='607|LAN_Odbor', profile='Staff')
passed('wifi-2', 'dot1x-wifi', ip='10.0.0.2', client='10.1.1.50', username='kral',
       mac='98-FC-84-E0-29-D7', device='wlc1', port='AP_8', ssid='guest',
       tkey='|Guests', profile='Guest')
passed('lan-1', 'dot1x-lan', ip='10.0.0.3', client='172.25.2.60', username='svoboda',
       mac='11-22-33-44-55-66', device='sw-a', port='Gi1/0/24', tkey='300',
       profile='LAN')
failed('wifi-f1', 'dot1x-wifi', ip='10.0.0.1', client='172.25.1.51', username='novak',
       mac='98-FC-84-E0-29-D8', device='wlc1', port='AP_9', ssid='staff',
       reason='wrong password', code='22056')
# NPS wireless: no address of its own - the controller's accounting has it.
passed('nps-1', 'nps-dot1x-wifi', ip='10.0.0.9', username='dvorak',
       mac='5C-5C-5C-5C-5C-01', device='wlc-nps', port='AP_N1', ssid='corp')
seen('5C-5C-5C-5C-5C-01', client='172.30.4.4', vlan='450', ap='AP_N1', ssid='corp',
     device='wlc-nps')
# The VPN: the Firewall column is the ACL's short name.
passed('vpn-1', 'vpn', ip='203.0.113.5', username='novak', machine='NB-01',
       acl='#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c', profile='VPN-Full', tunnel='TG-Staff',
       device='ftd-1', country='CZ')
passed('vpn-2', 'vpn', ip='203.0.113.6', username='kral', machine='NB-02',
       acl='#ACSACL#-IP-AnyConnect_OLYMPUS-EXTRA-6913329d', profile='VPN-Full',
       tunnel='TG-Staff', device='ftd-1', country='CZ')
# NPS's VPN: the Policy column is NPS's network policy, kept as the profile.
passed('npsvpn-1', 'nps-vpn', ip='203.0.113.7', username='horak', profile='Pol-VPN',
       policy='Proxy-Default', tunnel='T1', device='asa')
# TACACS+: the Commands column is rows of their own.
passed('tac-1', 'tacacs', ip='10.5.5.5', username='admin1', tkey='admin1|sw-core|tty1',
       device='sw-core', profile='priv15', ts=NOW - 300)
passed('tac-c1', 'tacacs-cmd', ip='10.5.5.5', username='admin1', tkey='admin1|sw-core|tty1',
       device='sw-core', cmd='configure terminal', verdict='allowed', ts=NOW - 290)
passed('tac-2', 'tacacs', ip='10.5.5.6', username='admin2', tkey='admin2|sw-core|tty2',
       device='sw-core', profile='priv15', ts=NOW - 200)
passed('tac-c2', 'tacacs-cmd', ip='10.5.5.6', username='admin2', tkey='admin2|sw-core|tty2',
       device='sw-core', cmd='show version', verdict='allowed', ts=NOW - 190)
# The same person signing in again on the same line: the first command is
# the earlier sitting's, not this one's.
passed('tac-3', 'tacacs', ip='10.5.5.5', username='admin1', tkey='admin1|sw-core|tty1',
       device='sw-core', profile='priv15', ts=NOW - 100)
# A sitting whose commands run past twelve hours, with the next sign-in on
# that line later still: they are its commands, as the Commands column counts.
passed('tac-5', 'tacacs', ip='10.5.5.7', username='admin5', tkey='admin5|sw-edge|tty5',
       device='sw-edge', profile='priv15', ts=NOW - 40 * 3600)
passed('tac-c5', 'tacacs-cmd', ip='10.5.5.7', username='admin5', tkey='admin5|sw-edge|tty5',
       device='sw-edge', cmd='reload', verdict='allowed', ts=NOW - 27 * 3600)
passed('tac-6', 'tacacs', ip='10.5.5.7', username='admin5', tkey='admin5|sw-edge|tty5',
       device='sw-edge', profile='priv15', ts=NOW - 20 * 3600)
# An ACL with no version on the end is shown whole, and is another firewall.
passed('vpn-3', 'vpn', ip='203.0.113.8', username='beran', machine='NB-03',
       acl='#ACSACL#-IP-AnyConnect_OLYMPUS-bar', profile='VPN-Full', tunnel='TG-Staff',
       device='ftd-1', country='CZ')
# NPS: an old sign-in of a machine whose accounting is of today is not shown
# today's address, and is not found by it.
passed('nps-2', 'nps-dot1x-wifi', ip='10.0.0.9', username='dvorak',
       mac='5C-5C-5C-5C-5C-01', device='wlc-nps', port='AP_N1', ssid='corp',
       ts=NOW - 3 * 86400)
# Token attempts: where from, the machine and the tunnel group are out of the
# RADIUS packet caught beside them.
passed('otp-1', 'otp', ip='127.0.0.1', username='mdolezal', tkey='mdolezal@example.cz',
       subtype='Valid token used', server='otp1')
passed('otp-2', 'otp', ip='127.0.0.1', username='jnovak', tkey='jnovak@example.cz',
       subtype='Scratch-token used', server='otp1', ts=NOW - 50)
failed('otp-f1', 'otp', ip='127.0.0.1', username='mdolezal', reason='Not a valid token',
       server='otp1', ts=NOW - 20)
with store.db_write() as db:
    for ident, ts, user, ip, device, tunnel, nas in (
            ('a1', NOW + 1, 'mdolezal@example.cz', '198.51.100.7', 'NB-77', 'VPN-Users',
             '10.1.1.1'),
            ('a2', NOW - 49, 'jnovak@example.cz', '198.51.100.8', 'NB-78', 'VDI', '10.1.1.2'),
            ('a3', NOW - 19, 'mdolezal@example.cz', '198.51.100.9', 'NB-79', 'VPN-Users',
             '10.1.1.1')):
        db.execute('INSERT INTO otp_asked (ident, ts, at, server, kind, username, ip, nas, '
                   'tunnel, verdict, device) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                   (ident, ts, ts, 'otp1', 'ask', user, ip, nas, tunnel, 'accept', device))
# The domain.
with store.db_write() as db:
    for ident, kind, event, account, machine, ip, process, said, obj in (
            ('w1', 'logon-failed', 4625, 'novak', 'PC-01', '10.2.2.2',
             'C:\\Windows\\System32\\lsass.exe', 'bad password', ''),
            ('w2', 'account', 4738, 'kral', '', '10.2.2.3', 'C:\\Windows\\System32\\svc.exe',
             '', 'CN=kral,OU=Staff')):
        db.execute(store.WIN_INSERT, (ident, NOW, 'dc1', event, kind, account, 0, 'EXAMPLE',
                                      '', machine, ip, '3', process, '', obj, said, '', 0, '',
                                      '', 1))

# ---- what the boxes find -------------------------------------------------------
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
TOKEN = json.loads(urllib.request.urlopen(urllib.request.Request(
    'http://127.0.0.1:%d/api/auth/login' % PORT,
    data=json.dumps({'name': 'boss', 'password': 'a-long-enough-password'}).encode(),
    headers={'X-Isemon-Token': isemon.API_TOKEN, 'Content-Type': 'application/json'},
    method='POST')).read().decode())['token']


def found(table, kind, q):
    status, said = call('/api/%s?kind=%s&hours=0&limit=100&q=%s'
                        % (table, kind, urllib.parse.quote(q)), TOKEN)
    if status != 200 or said.get('q_error'):
        return ('error', status, said.get('q_error') or said.get('error'))
    return sorted(r['session'] for r in said.get('rows') or [])


def suggests(table, kind, field, typed=''):
    status, said = call('/api/suggest?list=%s&kind=%s&field=%s&typed=%s'
                        % (table, kind, field, urllib.parse.quote(typed)), TOKEN)
    return [v['val'] for v in said.get('values') or []]


try:
    print('\nEduroam: the columns out of the accounting')
    for q in ('ip:10.88.*', 'address:10.88.12.179', 'address:10.88.0.0/16',
              'ap:AP-EAST-1', 'network:eduroam', 'vlan:1111', 'vlan:"VLAN 1111"',
              'machine:"Phone One"', 'institution:example.org', 'controller:wlc9800',
              'endpoint:02:16:3b:82:20:f5', 'name:jk@example.org', '10.88.12.179',
              'jk ap:AP-EAST*', 'address:10.88.* phone'):
        ok('%s finds the row that shows it, and only it' % q,
           found('passed', 'eduroam', q), ['edu-1'])
    ok('-address:10.88.* is everybody else', found('passed', 'eduroam', '-address:10.88.*'),
       ['edu-2'])
    ok('the controller\'s own address is not the Address column',
       found('passed', 'eduroam', 'address:10.250.0.5'), [])
    ok('the refusals: institution and controller', (
        found('failed', 'eduroam', 'institution:example.org controller:wlc9800')), ['edu-f1'])
    ok('the addresses offered are the ones the column shows',
       suggests('passed', 'eduroam', 'address'), ['10.88.12.179', '10.9.9.9'][:2]
       if suggests('passed', 'eduroam', 'address')[0] == '10.88.12.179'
       else ['10.9.9.9', '10.88.12.179'])
    ok('...and the access points, networks and VLANs',
       (sorted(suggests('passed', 'eduroam', 'ap')),
        sorted(suggests('passed', 'eduroam', 'network')),
        sorted(suggests('passed', 'eduroam', 'vlan'))),
       (['AP-EAST-1', 'AP-WEST-2'], ['eduroam', 'eduroam-guest'], ['1111', '2222']))

    print('\nThe network doors: the machine\'s address, the VLAN as it is shown')
    for q, want in (('address:172.25.*', ['wifi-1']), ('ip:172.25.1.50', ['wifi-1']),
                    ('vlan:607', ['wifi-1']), ('vlan:"VLAN 607"', ['wifi-1']),
                    ('vlan:LAN_Odbor', ['wifi-1']), ('vlan:Guests', ['wifi-2']),
                    ('vlan:6*', ['wifi-1']), ('ap:AP_7', ['wifi-1']),
                    ('network:staff', ['wifi-1']), ('controller:wlc1', ['wifi-1', 'wifi-2']),
                    ('-vlan:607', ['wifi-2'])):
        ok('dot1x-wifi %s' % q, found('passed', 'dot1x-wifi', q), want)
    ok('dot1x-lan vlan:300 and switch:sw-a',
       found('passed', 'dot1x-lan', 'vlan:300 switch:sw-a port:Gi1/0/24'), ['lan-1'])
    ok('the network door as a whole', found('passed', 'network', 'address:172.25.2.*'),
       ['lan-1'])
    ok('the refusals: address, ap and code',
       found('failed', 'dot1x-wifi', 'address:172.25.1.51 ap:AP_9 code:22056'), ['wifi-f1'])
    ok('the VLANs offered are said as the column says them',
       sorted(suggests('passed', 'dot1x-wifi', 'vlan')), ['607', 'Guests'])
    ok('NPS: the address and the VLAN out of the accounting',
       (found('passed', 'nps-dot1x-wifi', 'address:172.30.4.4'),
        found('passed', 'nps-dot1x-wifi', 'vlan:450'), found('passed', 'nps-dot1x-wifi',
                                                             '172.30.4.4')),
       (['nps-1'], ['nps-1'], ['nps-1']))
    ok('...only beside a sign-in of the same day, as the page puts it there',
       found('passed', 'nps-dot1x-wifi', 'name:dvorak'), ['nps-1', 'nps-2'])

    print('\nThe VPN: the firewall by its short name')
    for q, want in (('firewall:AnyConnect_OLYMPUS', ['vpn-1']),
                    ('firewall:AnyConnect_OLYMPUS-EXTRA', ['vpn-2']),
                    ('firewall:AnyConnect_*', ['vpn-1', 'vpn-2', 'vpn-3']),
                    ('firewall:AnyConnect_OLYMPUS-bar', ['vpn-3']),
                    ('acl:#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c', ['vpn-1']),
                    ('machine:NB-01 address:203.0.113.5', ['vpn-1']),
                    ('door:vpn name:novak', ['vpn-1'])):
        ok('vpn %s' % q, found('passed', 'vpn', q), want)
    ok('the firewalls offered are the short names',
       sorted(suggests('passed', 'vpn', 'firewall')),
       ['AnyConnect_OLYMPUS', 'AnyConnect_OLYMPUS-EXTRA', 'AnyConnect_OLYMPUS-bar'])
    ok('NPS VPN: Policy is the column headed so',
       (found('passed', 'nps-vpn', 'policy:Pol-VPN'), found('passed', 'nps-vpn',
                                                            'policy:Proxy-Default')),
       (['npsvpn-1'], []))

    print('\nTACACS+: a sitting by the commands run in it')
    ok('command:conf*', found('passed', 'tacacs', 'command:conf*'), ['tac-1'])
    ok('command:"show version"', found('passed', 'tacacs', 'command:"show version"'),
       ['tac-2'])
    ok('...not the next sitting on the same line', 'tac-3' in found(
        'passed', 'tacacs', 'command:configure*'), False)
    ok('-command:conf*', found('passed', 'tacacs', '-command:conf*'),
       ['tac-2', 'tac-3', 'tac-5', 'tac-6'])
    ok('...a command past twelve hours, before the next sign-in on the line',
       found('passed', 'tacacs', 'command:reload'), ['tac-5'])
    ok('the commands offered', sorted(suggests('passed', 'tacacs', 'command')),
       ['configure terminal', 'reload', 'show version'])
    ok('vlan: on this door is what it always was, not a VLAN',
       isemon.list_fields('passed', 'tacacs')['vlan'], ('tkey', 'text'))

    print('\nOTP: where from, the machine and the tunnel group out of the packet')
    for q, want in (('from:198.51.100.7', ['otp-1']), ('address:198.51.100.*',
                                                       ['otp-1', 'otp-2']),
                    ('machine:NB-78', ['otp-2']), ('vpngroup:VDI', ['otp-2']),
                    ('asker:10.1.1.1', ['otp-1']), ('account:mdolezal@example.cz', ['otp-1']),
                    ('how:"valid token used"', ['otp-1']), ('198.51.100.8', ['otp-2']),
                    ('NB-77', ['otp-1'])):
        ok('otp %s' % q, found('passed', 'otp', q), want)
    ok('the refusals: where from', found('failed', 'otp', 'from:198.51.100.9'), ['otp-f1'])
    ok('the country on this card is said not to be searchable, rather than finding nothing',
       found('passed', 'otp', 'country:CZ')[0], 'error')
    ok('where-from offered out of the packets',
       '198.51.100.7' in suggests('passed', 'otp', 'from'), True)

    print('\nThe domain')
    for q, want in (('from:PC-01', ['w1']), ('from:10.2.2.3', ['w2']),
                    ('through:lsass.exe', ['w1']), ('why:"bad password"', ['w1']),
                    ('why:"CN=kral,OU=Staff"', ['w2']), ('what:logon-failed', ['w1'])):
        status, got = call('/api/windows/events?hours=0&limit=50&q=%s' % urllib.parse.quote(q),
                           TOKEN)
        ok('win %s' % q, sorted(r['ident'] for r in got.get('rows') or []) if status == 200
           else ('error', status, got), want)
    ok('the domain offers From and Through as the columns show them',
       ('PC-01' in suggests('win', '', 'from') and '10.2.2.3' in suggests('win', '', 'from'),
        suggests('win', '', 'through')), (True, ['lsass.exe', 'svc.exe']))

    print('\nThe ban history: "the counting" is who banned it when nobody did')
    store.block('192.0.2.44', 60, 'by the counting', by='')
    store.block('192.0.2.45', 60, 'by hand', by='boss')
    status, got = call('/api/blocked?limit=25&q=%s' % urllib.parse.quote(
        'by:"the counting"'), TOKEN)
    ok('by:"the counting"', sorted(r['ip'] for r in got.get('history') or []),
       ['192.0.2.44'])
finally:
    api.stop() if hasattr(api, 'stop') else None

print('\nEvery field each card offers is one the daemon reads, on that door')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
node = shutil.which('node')
if node:
    start = page.index('var QC = {')
    end = page.index('/** The fields of the card a sign-in list is showing')
    script = page[start:end] + '\nconsole.log(JSON.stringify(QF_CARDS));'
    cards = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                      check=True).stdout)
    doors = {'passed': {'vpn': 'vpn', 'other': 'other', 'nps-vpn': 'nps-vpn',
                        'nps-other': 'nps-other', 'tacacs': 'tacacs', 'tacplus': 'tacplus',
                        'network': 'dot1x-lan', 'wifi': 'dot1x-wifi', 'otp': 'otp',
                        'eduroam': 'eduroam', 'radius-vpn': 'radius-vpn',
                        'radius-other': 'radius-other'},
             'failed': {'plain': 'other', 'vpn': 'vpn', 'network': 'dot1x-lan',
                        'wifi': 'nps-dot1x-wifi', 'tacplus': 'tacplus', 'otp': 'otp',
                        'eduroam': 'eduroam', 'nps-vpn': 'nps-vpn', 'nps-other': 'nps-other',
                        'radius-vpn': 'radius-vpn', 'radius-other': 'radius-other'}}
    bad = []
    for table, shapes in cards.items():
        for shape, fields in shapes.items():
            door = doors[table][shape]
            known = isemon.list_fields(table, door)
            for f in fields:
                spec = known.get(f[0])
                if not spec or (len(spec) > 2 and spec[2] == 'none'):
                    bad.append((table, shape, f[0]))
                    continue
                try:
                    isemon.ListQuery(table, '%s:x' % f[0], columns=store.columns_of(table),
                                     door=door)
                except isemon.ListQueryError as e:
                    bad.append((table, shape, f[0], str(e)))
    ok('none left out', bad, [])

    print('\nA value typed as the column shows it is put back as it is kept')
    block = page[page.index('function qShown(words)'):page.index('/** What each list')]
    tok = page[page.index('function qTokens(text)'):]
    tok = tok[:tok.index('\n}\n') + 3]
    script = ('function i18nText(s) { return s === "the token was right" ? '
              '"token byl správný" : s; }\n' + block + tok + '''
var TOKEN_WORDS = {'valid token used': ['the token was right', 'ok'],
                   'scratch-token used': ['a one-off recovery code', 'warn']};
var m = {how: qBackBy(TOKEN_WORDS)};
console.log(JSON.stringify([
  qRewrite('how:"the token was right" novak', m),
  qRewrite('how:"token byl správný"', m),
  qRewrite('-how:"a one-off recovery code"', m),
  qRewrite('how:*right*,*recovery*', m),
  qRewrite('how:"valid token used"', m),
  qRewrite('name:x', m),
  qRewrite('how:"the token was right"  door:"MAB LAN" name:a"b', m),
  qRewrite('how~recovery', m),
  qRewrite('how~valid', m)]));''')
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('in English, in the page\'s language, turned round, several, and left alone', got, [
        'how:"valid token used" novak', 'how:"valid token used"',
        '-how:"scratch-token used"',
        '(how:"valid token used" OR how:"scratch-token used")',
        'how:"valid token used"', 'name:x',
        'how:"valid token used"  door:"MAB LAN" name:a"b', 'how:"scratch-token used"',
        'how~valid'])
else:
    print('  (no node here: the page\'s own functions are not run)')

print('\nThe Traffic page: its columns\' names and words')
for q, want in (('cat:Unrated', ('((LOWER(cat) = ?))', ['unrated'])),
                ('policy:#6', ('(((policy) = ?))', [6])),
                ('verdict:"let through"', ('(verdict = ?)', ['allow'])),
                ('data:>1M', ('((sent + rcvd) > ?)', [1000000])),
                ('lasted:>1h', ('((duration) > ?)', [3600])),
                ('source:10.1.2.3', ('((srcip = ?))', ['10.1.2.3']))):
    ok(q, isemon.FwQuery(q).narrowing(), want)
if node:
    start = page.index('function tTopPage(t, term)')
    fn = page[start:page.index('\n}\n', start) + 3]
    maps = page[page.index('function tMaps() {'):]
    maps = maps[:maps.index('\n}\n') + 3]
    script = (fn + block + tok + maps + '''
function i18nText(s) { return s === 'let through' ? 'propuštěno' : s; }
var T_VERDICTS = {allow: {words: 'let through'}, deny: {words: 'refused'}};
var FG_ACTIONS = {close: 'let through, and closed normally by both sides'};
var COUNTRY_NAME = {CZ: 'Czechia', US: 'United States'};
var FG_COUNTRY_ALIAS = {'czech republic': 'CZ', 'czechia': 'CZ'};
console.log(JSON.stringify([
  tTopPage({}, 'srcip:1.2.3.4 verdict:deny,block,fail'),
  tTopPage({}, 'dstport:22 kind:traffic'),
  tTopPage({page: 'threat'}, 'x'),
  qRewrite('verdict:propuštěno srccountry:CZ', tMaps()),
  qRewrite('action:"SSL: let through, and closed normally by both sides"', tMaps()),
  qRewrite('-dstcountry:CZ', tMaps()),
  qRewrite('srccountry:private', tMaps())]));''')
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('a card row opens on every line unless it keeps to the sessions, or names its page',
       got[:3], ['all', 'list', 'threat'])
    ok('the words and the two letters put back', got[3:], [
        'verdict:allow (srccountry:CZ OR srccountry:Czechia OR srccountry:"czech republic")',
        'action:close',
        'NOT (dstcountry:CZ OR dstcountry:Czechia OR dstcountry:"czech republic")',
        'srccountry:Reserved'])

print('\nThe page')
ok('a card\'s box offers that card\'s columns',
   all(x in page for x in ("fields: function () { return qCardFields('failed', FKIND); }",
                           "fields: function () { return qCardFields('passed', PKIND); }")))
ok('a row of the Traffic cards opens where its lines are', all(x in page for x in (
    "tOpen(term, tTopPage(t, term));", "? 'list' : 'all';")))
ok('the folded addresses of a ban are searched by their address',
   "if (field === 'member') return banMembers(one);" in page)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
