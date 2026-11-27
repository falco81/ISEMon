#!/usr/bin/env python3
"""1.10.383: an address's own lists hold its token attempts and nobody else's.

A token row carries the box that asked and that box's port (`asked_as`), and
every session through the box takes its turn with the same port. Matched on
that alone, the popup of one address listed hundreds of other people's token
attempts from all of time, while its own numbers above said 3 and 2.

    ./test/fixes383_lists.py
"""
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
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


folder = Path(tempfile.mkdtemp(prefix='isemon-383-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
NOW = time.time()
ME, OTHER, BOX = '203.0.113.44', '198.51.100.66', '10.9.9.9:4000'

store.add_failed({'session': 'v1', 'ts': NOW - 300, 'ip': ME, 'username': 'anovak',
                  'kind': 'vpn', 'device': 'FTD'})
store.add_passed({'session': 'v2', 'ts': NOW - 200, 'ip': ME, 'username': 'anovak',
                  'kind': 'vpn', 'device': 'FTD'})
# Two token sign-ins through the same box and port: anovak from this address,
# bdvorak an hour earlier from another one.
for session, ts, user in (('o1', NOW - 100, 'anovak'), ('o2', NOW - 3700, 'bdvorak')):
    store.add_passed({'session': session, 'ts': ts, 'ip': '127.0.0.1', 'username': user,
                      'kind': 'otp', 'server': 'otp1', 'tkey': user + '@example.cz',
                      'asked_as': BOX, 'subtype': 'Valid token used'})
store.add_failed({'session': 'o3', 'ts': NOW - 3650, 'ip': '127.0.0.1', 'username': 'bdvorak',
                  'kind': 'otp', 'server': 'otp1', 'asked_as': BOX,
                  'reason': 'the token was wrong'})
with store.db_write() as db:
    for ident, ts, user, ip, verdict in (('k1', NOW - 100, 'anovak@example.cz', ME, 'accept'),
                                         ('k2', NOW - 3700, 'bdvorak@example.cz', OTHER,
                                          'accept'),
                                         ('k3', NOW - 3650, 'bdvorak@example.cz', OTHER,
                                          'reject')):
        db.execute('INSERT INTO otp_asked (ident, ts, at, server, kind, username, ip, nas, '
                   'verdict, rid) VALUES (?,?,?,?,?,?,?,?,?,?)',
                   (ident, ts, ts, 'otp1', 'ask', user, ip, '10.9.9.9', verdict, BOX))

rows, total = store.passed_rows(ip=ME, limit=100)
ok('this address\'s sign-ins: its VPN one and its own token one',
   sorted(r['session'] for r in rows), ['o1', 'v2'])
rows, total = store.failed_rows(ip=ME, limit=100)
ok('...its refusals: no token refusal of somebody else through the same box',
   sorted(r['session'] for r in rows), ['v1'])
rows, total = store.passed_rows(ip=OTHER, limit=100)
ok('the other address has its own', sorted(r['session'] for r in rows), ['o2'])
seen = {d['kind']: d for d in store.address_seen(ME)['doors']}
ok('...and the chips above the list count the same',
   (seen['vpn']['failed'], seen['vpn']['passed'], seen['otp']['passed']), (1, 1, 1))

print('The cards and what they open')
for i, name in enumerate(['admin', 'Admin', 'ADMIN']):
    store.add_failed({'session': 't%d' % i, 'ts': NOW - 50 - i, 'ip': '198.51.100.20',
                      'username': name, 'kind': 'tacacs', 'device': 'sw1'})
got = {r['said'].lower(): r['failed'] for r in store.door_subjects('tacacs', NOW - 3600, 'username')}
ok('a name in any case is one row of a card', got, {'admin': 3})
rows, _n = store.failed_rows(username='Admin', kind='tacacs', limit=100)
ok('...as many as its popup lists', len(rows), 3)
for i, name in enumerate(['cnovak', 'CNovak']):
    store.add_failed({'session': 'u%d' % i, 'ts': NOW - 40 - i, 'ip': '198.51.100.21',
                      'username': name, 'kind': 'vpn'})
store.add_failed({'session': 'u9', 'ts': NOW - 30, 'ip': '198.51.100.21',
                  'username': 'cnovak', 'kind': None})
top = {r['username'].lower(): r['tries'] for r in store.top_users(NOW - 3600)}
rows, _n = store.failed_rows(username='cnovak', kind='judged', limit=100)
ok('the busiest names: one row a name, and its popup lists what it counted',
   (top.get('cnovak'), len(rows)), (3, 3))
store.add_failed({'session': 'm1', 'ts': NOW - 20, 'ip': '10.0.0.5', 'username': 'host/pc9',
                  'kind': 'dot1x-wifi', 'mac': ''})
store.add_failed({'session': 'm2', 'ts': NOW - 21, 'ip': '10.0.0.5', 'username': 'host/pc9',
                  'kind': 'dot1x-wifi', 'mac': '3C-52-82-00-00-0C'})
rows, _n = store.failed_rows(username='host/pc9', kind='network', nomac=True, limit=100)
ok('a machine counted by its account opens the rows with no MAC',
   [r['session'] for r in rows], ['m1'])
store.add_passed({'session': 'd1', 'ts': NOW - 199, 'ip': ME, 'username': '#ACSACL#-IP-x',
                  'kind': 'dacl'})
seen = store.address_seen(ME)
ok('an address\'s chips: no ACL counted as a sign-in, and each asks ip: exactly',
   (sum(d['passed'] for d in seen['doors']), sorted({d['q'] for d in seen['doors']})),
   (2, ['ip:' + ME]))
ok('...nor among the names that got in',
   [n['name'] for n in store.names_from(ME, 'passed')], ['anovak'])
store.add_failed({'session': 'c1', 'ts': NOW - 10, 'ip': '198.51.100.30', 'country': 'NL',
                  'username': 'x', 'kind': 'vpn'})
store.add_failed({'session': 'c2', 'ts': NOW - 10 * 86400, 'ip': '198.51.100.31',
                  'country': 'NL', 'username': 'x', 'kind': 'vpn'})
store.add_failed({'session': 'c3', 'ts': NOW - 10, 'ip': '198.51.100.32', 'country': 'NL',
                  'username': 'x', 'kind': 'tacacs'})
ok('the country picker counts the door and the window the list shows',
   store._countries_now('failed', ('vpn',), NOW - 86400).get('NL'), 1)

src = (ROOT / 'isemon.py').read_text()
page = (ROOT / 'web' / 'index.php').read_text()
print('The domain')
ok('a card\'s row opens exactly what it counted', "ask.exact = '1';" in page
   and 'exact=one(\'exact\') == \'1\'' in src)
ok('...a part with nothing in it is asked as nothing, not left out',
   "'ask': {k: (str(one[k] or '') or '-') for k in" in src)
ok('the brute card and its list: the same refusals',
   "kind=refused, routine='0', weighed='1')" in src)
ok('accounts locked: one account however written',
   "return len({win_fold_account(r['account']) for r in rows} - {''})" in src)
ok('the lockout\'s popup: the span and the refusals counted above it',
   "'&before=1800&after=60&bad=1'" in page and 'quiet=one(\'bad\') == \'1\')' in src)
print('The page')
ok('"Open the ..." keeps the window a popup counted in', "windowSet(hours.id, also.win);" in page)
ok('...and a card\'s "never got on"', 'fSettledArg()' in page)
ok('the network doors open as themselves, not the VPN', "DOOR_SAYS[k] = {kind: k" in page)
ok('a bar of the chart is the span to the next one', 'series[i + 1].ts - p.ts' in page)
ok('the names asked for open every line with the name',
   "term: function (v) { return 'host:' + tQuote(v); }}," in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
