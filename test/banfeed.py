#!/usr/bin/env python3
"""The VPN through NPS judged, and the ban list published (1.10.99).

The first half feeds the daemon NPS lines written the way a real site's are -
a FortiGate's SSL VPN asking a Windows NPS about passwords (a password spray,
names that are not accounts from a handful of addresses), and Aruba access
points asking about 802.1X on the Wi-Fi - forwarded by syslog, which escapes
the carriage return NPS ends each line with as `#015`. The addresses and
names are made up; the shape of every column is the real one.

The second half is the published list: which addresses it carries, in which
format, and who may fetch it.

    ./test/banfeed.py
"""
import hashlib
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon  # noqa: E402

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
    print('\n' + words)


BASE = {
    'blacklist': 1, 'block_mode': 'temporary', 'block_tries': 3,
    'block_window_min': 60, 'block_lots': 0, 'block_bogus_tries': 0,
    'block_ladder': '15, 60, forever', 'feeds_ban': 0, 'geo': 0,
    'mikrotik_host': '', 'watch_devices': '', 'passed_devices': '',
    'never_block': '', 'never_block_countries': '', 'read_passed': 1,
    'judge_max_age_h': 0, 'debug': False, 'judge_nps_vpn': 1,
    'banfeed': 0, 'banfeed_format': 'ftd', 'banfeed_temporary': 1,
    'banfeed_family': 'both', 'banfeed_from': '', 'banfeed_auth': 'none',
    'banfeed_user': 'isemon', 'banfeed_password': '',
}
FOLDERS = []


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-banfeed-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'banfeed.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'banfeed.log'
    isemon.CONFIG.update(BASE)
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    return store, daemon


SEQ = [314700]
POLICY = 'Použít ověřování systému Windows pro všechny uživatele'


def nps_line(when, packet, values):
    """One line as NPS writes it and rsyslog forwards it."""
    row = [''] * len(isemon.NPS_COLUMNS)
    col = isemon.NPS_COL
    row[col['Computer-Name']] = 'DC03'
    row[col['Service-Name']] = 'IAS'
    row[col['Record-Date']] = time.strftime('%m/%d/%Y', time.localtime(when))
    row[col['Record-Time']] = time.strftime('%H:%M:%S', time.localtime(when))
    row[col['Packet-Type']] = str(packet)
    for name, value in values.items():
        row[col[name]] = str(value)
    quoted = {'Computer-Name', 'Service-Name', 'User-Name', 'Fully-Qualified-User-Name',
              'Called-Station-Id', 'Calling-Station-Id', 'Framed-IP-Address',
              'NAS-Identifier', 'NAS-IP-Address', 'Client-IP-Address',
              'Client-Friendly-Name', 'Connect-Info', 'Class', 'Acct-Session-Id',
              'Proxy-Policy-Name', 'Policy-Name'}
    text = ','.join(('"%s"' % v) if (v and name in quoted) else v
                    for name, v in zip(isemon.NPS_COLUMNS, row))
    stamp = time.strftime('%b %d %H:%M:%S', time.localtime(when))
    return '%s dc03 nps: %s#015' % (stamp, text)


def vpn_try(when, name, addr, accepted=False):
    """A FortiGate SSL VPN asking about one password, and the answer."""
    SEQ[0] += 1
    klass = '311 1 192.0.2.6 09/09/2026 13:10:54 %d' % SEQ[0]
    session = '4d4b%04x' % (SEQ[0] % 65536)
    ask = nps_line(when, 1, {
        'User-Name': name, 'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name,
        'Called-Station-Id': '192.0.2.254', 'Calling-Station-Id': addr,
        'Framed-IP-Address': addr, 'NAS-Identifier': 'FG-EXAMPLE',
        'NAS-IP-Address': '192.0.2.254', 'Client-Vendor': '0',
        'Client-IP-Address': '192.0.2.254', 'Client-Friendly-Name': 'EXAMPLE-FG',
        'NAS-Port-Type': '5', 'Connect-Info': 'vpn-ssl', 'Authentication-Type': '4',
        'Reason-Code': '0', 'Class': klass, 'Acct-Session-Id': session,
        'Proxy-Policy-Name': POLICY, 'Provider-Type': '1'})
    answer = nps_line(when, 2 if accepted else 3, {
        'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name, 'Client-Vendor': '0',
        'Client-IP-Address': '192.0.2.254', 'Client-Friendly-Name': 'EXAMPLE-FG',
        'Authentication-Type': '4', 'Reason-Code': '0' if accepted else '16',
        'Class': klass, 'Acct-Session-Id': session, 'Proxy-Policy-Name': POLICY,
        'Provider-Type': '1'})
    return [ask, answer]


def wifi_try(when, name, ap):
    """An Aruba access point asking about 802.1X, refused."""
    SEQ[0] += 1
    klass = '311 1 192.0.2.6 09/09/2026 13:10:54 %d' % SEQ[0]
    ask = nps_line(when, 1, {
        'User-Name': name, 'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name,
        'Called-Station-Id': 'fc7ff1cbf13c', 'Calling-Station-Id': '4eaf29bb9da0',
        'NAS-Identifier': 'EXAMPLE_LAN', 'NAS-IP-Address': '192.0.2.42', 'NAS-Port': '0',
        'Client-Vendor': '0', 'Client-IP-Address': '192.0.2.42',
        'Client-Friendly-Name': ap, 'NAS-Port-Type': '19', 'Service-Type': '2',
        'Authentication-Type': '4', 'Reason-Code': '0', 'Class': klass,
        'Proxy-Policy-Name': 'WIFI-LAN', 'Provider-Type': '1'})
    answer = nps_line(when, 3, {
        'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name, 'Client-Vendor': '0',
        'Client-IP-Address': '192.0.2.42', 'Client-Friendly-Name': ap,
        'Authentication-Type': '4', 'Reason-Code': '16', 'Class': klass,
        'Proxy-Policy-Name': 'WIFI-LAN', 'Provider-Type': '1'})
    return [ask, answer]


def take(daemon, lines):
    got = isemon.nps_parse_lines(lines, {}, now=time.time())
    for rec in got:
        daemon.take_record('nps', rec)
    return got


NOW = time.time() - 600

# ---------------------------------------------------------------------------
title('The lines as a syslogged NPS writes them')
store, daemon = fresh()
recs = isemon.nps_parse_lines(vpn_try(NOW, 'admin', '203.0.113.10'), {}, now=time.time())
ok('one refusal from one request and its answer', len(recs), 1)
ok('...at the VPN door', recs[0].door, 'nps-vpn')
ok('...from the address the FortiGate says', recs[0].ip, '203.0.113.10')
ok('rsyslog’s #015 is not read as the value of the last column',
   any('#015' in str(v) for vs in recs[0].fields.values() for v in vs), False)
wifi = isemon.nps_parse_lines(wifi_try(NOW, 'someone', 'AP02'), {}, now=time.time())
ok('the Wi-Fi is its own door', [r.door for r in wifi], ['nps-dot1x-wifi'])

# ---------------------------------------------------------------------------
title('A password spray on the VPN through NPS is banned')
lines = []
for n, name in enumerate(['admin', 'ken', 'manager']):
    lines += vpn_try(NOW + n, name, '203.0.113.10')
take(daemon, lines)
ok('three refusals from one address: banned', store.blocked_until('203.0.113.10') is not None)
take(daemon, vpn_try(NOW + 5, 'susan', '203.0.113.11')
     + vpn_try(NOW + 6, 'wendy', '203.0.113.11'))
ok('two: not yet', store.blocked_until('203.0.113.11'), None)
lines = []
for n in range(6):
    lines += wifi_try(NOW + n, 'someone', 'AP03')
take(daemon, lines)
ok('the Wi-Fi is written down', store.rows_in('failed') >= 11, True)
ok('...and never judged: nothing else is banned',
   sorted(r['ip'] for r in store.blocked_all()), ['203.0.113.10'])
ok('an accepted sign-in is a login, not a refusal',
   bool(take(daemon, vpn_try(NOW + 9, 'realuser', '198.51.100.7', accepted=True))
        and store.blocked_until('198.51.100.7') is None), True)
ok('the reason says what was tried', 'failed VPN login' in (
    [r['why'] for r in store.blocked_all() if r['ip'] == '203.0.113.10'] or [''])[0], True)

title('The watch list is ISE’s and does not switch NPS off')
isemon.CONFIG['watch_devices'] = 'FTD-VPN'
take(daemon, sum((vpn_try(NOW + 20 + n, 'x%d' % n, '203.0.113.14') for n in range(3)), []))
ok('with the default FTD-VPN on the watch list, still banned',
   store.blocked_until('203.0.113.14') is not None)
ok('the counting agrees', len(store.failed_recent('203.0.113.14', 3600, at=NOW + 60,
                                                  devices=daemon.watch_devices())), 3)
isemon.CONFIG['watch_devices'] = ''

title('An EAP conversation somebody walked away from is not an attempt')
for n in range(4):
    store.add_failed({'session': 'gone/%d' % n, 'ts': NOW + 30 + n, 'ip': '203.0.113.12',
                      'username': 'someone', 'kind': 'nps-vpn', 'code': 'abandoned',
                      'reason': isemon.NPS_ABANDONED, 'device': 'EXAMPLE-FG'})
ok('not counted', len(store.failed_recent('203.0.113.12', 3600, at=NOW + 60)), 0)
ok('...not in the counting on the page',
   [r['ip'] for r in store.counting_now(NOW - 60)].count('203.0.113.12'), 0)

title('Switched off, the VPN through NPS is only written down')
isemon.CONFIG['judge_nps_vpn'] = 0
ok('the condition is exactly what it always was', isemon.judged_sql(),
   "(kind='vpn' OR kind IS NULL)")
take(daemon, sum((vpn_try(NOW + 40 + n, 'y%d' % n, '203.0.113.13') for n in range(4)), []))
ok('four refusals, no ban', store.blocked_until('203.0.113.13'), None)
ok('...and none counted', len(store.failed_recent('203.0.113.13', 3600, at=NOW + 60)), 0)
isemon.CONFIG['judge_nps_vpn'] = 1
ok('on again, they are counted', len(store.failed_recent('203.0.113.13', 3600,
                                                         at=NOW + 60)), 4)

title('Going back over everything weighs them too')
walked = list(store.failed_for_judging(0))
ok('the VPN through NPS is in the walk', sum(1 for r in walked if r['kind'] == 'nps-vpn'),
   3 + 2 + 3 + 4)
ok('...in time order', [r['ts'] for r in walked] == sorted(r['ts'] for r in walked), True)
ok('...without the Wi-Fi and without the abandoned', any(
    r['kind'] not in ('nps-vpn', 'vpn', None) for r in walked), False)
ok('the count says the same', store.how_many_to_judge(0), len(walked))
got = daemon.rescan(read_files=False)
ok('the pass bans the one that was switched off at the time',
   store.blocked_until('203.0.113.13') is not None)
ok('...and not the abandoned', store.blocked_until('203.0.113.12'), None)
top = store.top_attackers(NOW - 60, 20)
ok('the front page lists the addresses trying the VPN through NPS',
   '203.0.113.10' in [r['ip'] for r in top], True)
ok('...and not the abandoned', '203.0.113.12' in [r['ip'] for r in top], False)
names = [r['username'] for r in store.top_users(NOW - 60, 50)]
ok('...and the names they tried', 'manager' in names, True)

# ---------------------------------------------------------------------------
title('The published list')
store, daemon = fresh()
now = time.time()
store.block('203.0.113.50', None, 'by hand', auto=False)
store.block('203.0.113.51', now + 900, 'for a while', auto=True)
store.block('198.51.100.0/24', None, 'folded', auto=True)
store.block('2001:db8::66', None, 'six', auto=False)
store.block('203.0.113.52', None, 'whitelisted since', auto=False)
store.block('203.0.113.53', now - 60, 'ran out', auto=True)
isemon.CONFIG['never_block'] = '203.0.113.52'


def serve(**kw):
    kw.setdefault('key', '')
    return daemon.banfeed_serve(**kw)


ok('off: nothing, and a 404', serve()[0], 404)
isemon.CONFIG['banfeed'] = 1
status, body, kind, count = serve()
ok('on and open: no key, no password, the list', status, 200)
ok('...for an FTD, one to a line, in address order', body,
   '198.51.100.0/24\n203.0.113.50\n203.0.113.51\n2001:db8::66\n')
ok('...the whitelisted and the run out are not in it', ('203.0.113.52' in body,
                                                          '203.0.113.53' in body), (False, False))
ok('the same shape for a FortiGate', serve(fmt='fortigate')[1], body)
ok('the MD5 the FMC asks first', serve(md5=True)[1].strip(),
   hashlib.md5(body.encode()).hexdigest())
ok('...and it does not change between two fetches', serve(md5=True)[1], serve(md5=True)[1])
ok('one family', serve(family='ipv4')[1], '198.51.100.0/24\n203.0.113.50\n203.0.113.51\n')
ok('...or the other', serve(family='6')[1], '2001:db8::66\n')
plain = serve(fmt='plain')[1]
ok('the plain list starts with comments for a person',
   (plain.startswith('# '), plain.rstrip().endswith('2001:db8::66')), (True, True))
got = json.loads(serve(fmt='json')[1])
ok('JSON: every address, with the end of its ban',
   [(a['address'], a['until'] is None) for a in got['addresses']],
   [('198.51.100.0/24', True), ('203.0.113.50', True), ('203.0.113.51', False),
    ('2001:db8::66', True)])
ok('...and nothing about who or why', any('why' in a for a in got['addresses']), False)
ok('a format nobody knows is a 400', serve(fmt='csv')[0], 400)
daemon._banfeed_cache = {}
isemon.CONFIG['banfeed_temporary'] = 0
ok('for good only', serve()[1], '198.51.100.0/24\n203.0.113.50\n2001:db8::66\n')
isemon.CONFIG['banfeed_temporary'] = 1
daemon._banfeed_cache = {}
isemon.CONFIG['blacklist'] = 0
ok('the blacklist off: the list is empty, not missing', serve()[:2], (200, ''))
isemon.CONFIG['blacklist'] = 1
daemon._banfeed_cache = {}

title('Who may fetch it')
isemon.CONFIG['banfeed_from'] = '192.0.2.0/28, 2001:db8:1::5'
ok('an address inside the ranges', serve(client='192.0.2.9')[0], 200)
ok('...and the one IPv6 address', serve(client='2001:db8:1::5')[0], 200)
ok('one outside', serve(client='192.0.2.99')[0], 403)
ok('...said out loud', daemon.banfeed_state()['refused'] >= 1, True)
isemon.CONFIG['banfeed_from'] = ''

title('A key in the URL, for the FMC')
isemon.CONFIG['banfeed_auth'] = 'key'
key = daemon.banfeed_key(make=True)
ok('a long one', len(key) >= 40, True)
ok('...kept where only this user reads it',
   oct(daemon.banfeed_key_path().stat().st_mode & 0o777), '0o600')
ok('without it: refused', serve()[0], 403)
ok('a wrong one: refused', serve(key=key[:-1] + ('A' if key[-1] != 'A' else 'B'))[0], 403)
ok('the right one', serve(key=key)[0], 200)
ok('the page is given it only as an administrator',
   ('key' in daemon.banfeed_state(False), daemon.banfeed_state(True).get('key')),
   (False, key))
new = daemon.banfeed_new_key(by='test')
ok('a new key: the old one stops working', (serve(key=key)[0], serve(key=new)[0]), (403, 200))

title('A user name and a password, for a FortiGate')
isemon.CONFIG['banfeed_auth'] = 'basic'
isemon.CONFIG['banfeed_user'] = 'fortigate'
isemon.CONFIG['banfeed_password'] = 'correct-horse-battery'
ok('nothing sent: asked for them', serve()[0], 401)
ok('a wrong password', serve(user='fortigate', password='nope')[0], 401)
ok('a wrong name', serve(user='other', password='correct-horse-battery')[0], 401)
ok('the key does not stand in for them', serve(key=new)[0], 401)
ok('the right pair', serve(user='fortigate', password='correct-horse-battery')[0], 200)
ok('the password is never handed to the page',
   'correct-horse-battery' in json.dumps(daemon.banfeed_state(True)), False)
ok('...and it is kept as a secret', 'banfeed_password' in isemon.SECRET_KEYS, True)
isemon.CONFIG['banfeed_auth'] = 'none'

title('Settings that do not go together are refused')


def refused(values):
    try:
        isemon.check_settings_together(dict(isemon.CONFIG, **values))
        return False
    except ValueError:
        return True


ok('basic with a short password', refused({'banfeed_auth': 'basic',
                                           'banfeed_password': 'short'}), True)
ok('basic with a colon in the name', refused({'banfeed_auth': 'basic', 'banfeed_user': 'a:b',
                                              'banfeed_password': 'x' * 20}), True)
ok('basic done properly', refused({'banfeed_auth': 'basic', 'banfeed_user': 'fg',
                                   'banfeed_password': 'x' * 20}), False)
try:
    isemon.check_setting('banfeed_from', '192.0.2.1, not-an-address')
    ok('banfeed_from refuses what is not an address', False)
except ValueError:
    ok('banfeed_from refuses what is not an address', True)

title('Who fetched it is kept')
serve(client='192.0.2.9', fmt='ftd', md5=True)
state = daemon.banfeed_state(True)
ok('the address and how', [(f['from'], f['md5']) for f in state['fetched']][:1],
   [('192.0.2.9', True)])
ok('the choices are named for people',
   isemon.BANFEED_FORMAT_WORDS['ftd'].startswith('Cisco FTD'), True)
ok('who fetched it can be forgotten', daemon.banfeed_forget(by='a test') >= 1, True)
state = daemon.banfeed_state(True)
ok('...and the lines under Fetched by start again from nothing',
   (state['fetched'], state['refused']), ([], 0))
serve(client='192.0.2.9', fmt='ftd', md5=True)
ok('...and the next fetch is written down as the first',
   [f['n'] for f in daemon.banfeed_state(True)['fetched']], [1])
going = (getattr(daemon, '_behind', {}) or {}).get('banfeed-note')
if going is not None:
    going.join(10)                       # written behind the fetch (1.10.187)
ok('...after a restart as well', isemon.Storage.meta_json(store, 'banfeed_seen', {}) != {},
   True)

for f in FOLDERS:
    shutil.rmtree(f, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
