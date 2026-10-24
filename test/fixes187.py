#!/usr/bin/env python3
"""1.10.187: a sign-out that cannot sign everybody out, the settings replaced
in one go, refreshes that cannot pile up, router writes one at a time, and
the popups and the find box answered without walking all of history.

    ./test/fixes187.py
"""
import json
import random
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
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


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-187-')
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

print('\nSigning out')
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('other', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
try:
    boss = call('/api/auth/login', 'POST', {'name': 'boss',
                                            'password': 'a-long-enough-password'})[1]['token']
    other = call('/api/auth/login', 'POST', {'name': 'other',
                                             'password': 'another-long-password'})[1]['token']
    status, _said = call('/api/auth/logout', 'POST', {})
    ok('a sign-out with no session at all is answered', status, 200)
    ok('...and signs nobody else out', len(store.sessions()), 2)
    call('/api/auth/logout', 'POST', {}, session=other)
    ok('a sign-out ends that one sign-in', [s['name'] for s in store.sessions()], ['boss'])
    ok('an empty name ends nothing either', store.drop_session(name='  '), 0)
    status, _said = call('/api/sessions', 'POST', {'drop_all': True}, session=boss)
    ok('"end every sign-in" still ends them all', (status, len(store.sessions())), (200, 0))
finally:
    api.stop() if hasattr(api, 'stop') else None

print('\nThe settings read again')
isemon.CONFIG_FILE.write_text(json.dumps({'retain_failed_days': 77}), encoding='utf-8')
store.settings_write({'block_tries': 9}, [], by='test')
seen = []
real_saved = store.settings_saved


def slow_saved():
    # What another thread sees while the database is being asked.
    seen.append((isemon.CONFIG.get('block_tries'), isemon.CONFIG.get('retain_failed_days')))
    return real_saved()


store.settings_saved = slow_saved
daemon._config_stamp = None
daemon._settings_serial = None
isemon.CONFIG['block_tries'] = 9
daemon.settings_changed_underneath()
store.settings_saved = real_saved
ok('while the database is asked, the settings in use are still the whole of them',
   seen[:1], [(9, isemon.DEFAULTS.get('retain_failed_days'))])
ok('...and afterwards the file and the saved settings are both in them',
   (isemon.CONFIG.get('retain_failed_days'), isemon.CONFIG.get('block_tries')), (77, 9))


def broken():
    raise isemon.DbError('the database closed')


before = dict(isemon.CONFIG)
store.settings_serial, real_serial = broken, store.settings_serial
daemon._settings_retry_at = 0
daemon.reread_asked.set()
daemon.settings_changed_underneath()
store.settings_serial = real_serial
ok('a database away while they are read leaves them exactly as they were',
   isemon.CONFIG == before, True)
daemon.reread_asked.clear()

print('\nAnswers worked out again behind the pages')
gate = threading.Event()
made = []


def slowly():
    made.append(1)
    gate.wait(5)
    return 'new'


with daemon._slow_lock:
    for n in range(daemon.REFRESH_MOST + 10):
        daemon._slow['t187/%d' % n] = (time.time() - 3600, 'old')
for n in range(daemon.REFRESH_MOST + 10):
    daemon.held('t187/%d' % n, 1, slowly, stale_for=86400)
time.sleep(0.3)
ok('never more than so many at once, however many are stale',
   len(made) <= daemon.REFRESH_MOST, True)
ok('...and the stale answer is handed out meanwhile', daemon.held('t187/1', 1, slowly,
                                                                   stale_for=86400), 'old')
gate.set()
ok('a directory lookup does not take one of the database’s turns',
   'who/'.startswith(isemon.Daemon.NOT_THE_DATABASE), True)
real_start = threading.Thread.start


def refuse(self):
    raise RuntimeError("can't start new thread")


threading.Thread.start = refuse
try:
    ok('a thread the machine will not start is said, not raised into the loop',
       daemon.behind('t187', lambda: None), False)
finally:
    threading.Thread.start = real_start

print('\nThe firewalls fetching the ban list')
isemon.CONFIG.update({'banfeed': 1})
daemon.banfeed_fetched('192.0.2.50', 'ftd', 3, False)
for _ in range(50):
    if store.meta_json('banfeed_seen', {}):
        break
    time.sleep(0.05)
ok('who fetched it is written down behind the fetch',
   '192.0.2.50' in (store.meta_json('banfeed_seen', {}) or {}), True)
ok('...not while every other fetch waits', "self.behind('banfeed-note'" in source, True)

print('\nOne writer to the router at a time')
ok('a purge, the owed clearing and every sync take the same lock',
   ('with self._mikrotik_lock:\n            return self._mikrotik_purge_now(' in source,
    'with self._mikrotik_lock:              # one writer at a time\n'
    '                    # ...and what is owed read again' in source), (True, True))
ok('two Banned pages at once start one count, not two',
   "with self._per_ban_lock:\n            lanes = self.__dict__.setdefault('_per_ban_going'"
   in source, True)
ok('a ban remembered for the ladder is never lost to the tidying',
   source.count('with self._blocked_times_lock:') >= 2, True)
ok('a first look at a firewall window gives its turn up while it waits',
   'gate_off_while(lambda: done.wait(self.FW_READY_WAIT_S))' in source, True)
ok('the country ranges are replaced without the lock every log waits for',
   "with self._ranges_write, self.db_write(own='alone') as db:" in source, True)
lo, fam = isemon.pack_address('192.0.2.0')
hi, _fam = isemon.pack_address('192.0.2.255')
ok('...and still are replaced', (store.put_geo_streamed(iter([(lo, hi, fam, 'CZ')])),
                                 store.db.execute('SELECT cc FROM geo_ranges').fetchone()['cc']),
   (1, 'CZ'))

print('\nThe box at the top')
now = time.time()
store.add_failed({'session': 'f187-1', 'ts': now - 30, 'ip': 'fe80::1', 'username': 'u',
                  'kind': 'vpn', 'device': 'D'})
ok('an address typed in capitals is found', [a['ip'] for a in store.find_addresses('FE80')],
   ['fe80::1'])
ok('...and in small letters', [a['ip'] for a in store.find_addresses('fe80')], ['fe80::1'])
ok('names: one statement a table for every name shown, not two a name',
   "'WHERE username IN (%s) GROUP BY username'" in source, True)
ok('a count that takes too long gives way to the addresses in order',
   ("'SELECT DISTINCT ip FROM %s WHERE ip >= ? AND ip < ? '" in source,
    isemon.Storage.FIND_COUNT_S), (True, 3))

print('\nThe popups')
ok('a domain event is looked for on its own day', ("store.win_detail(one('ident'), at"
                                                    in source, "'&ts=' + encodeURIComponent(r.ts)"
                                                    in page), (True, True))
ok('...and found without its moment, as before', store.win_detail('nothing-187'), None)
ok('an account’s story reads the columns it shows, not the packed record',
   "sql = ('SELECT ' + self.WIN_ROW_COLUMNS + ' FROM win_events WHERE event IN (%s) '"
   in source, True)
story = daemon.address_story('fe80::1')
again = daemon.address_story('fe80::1')
ok('an address’s story is kept a moment, a copy each time',
   (story == again, story is not again), (True, True))
daemon.bump()
ok('...and asked afresh once anything has changed',
   'addr/%s/%d' % ('fe80::1', daemon._serial) in daemon._slow, False)
ok('a lockout’s machines kept half a minute against the account and the window',
   "daemon.held('blame/' + json.dumps(" in source, True)
ok('the VPN session popup kept a quarter of a minute', "'fw/vpn1/%s/%s'" in source, True)
ok('a VPN door is two comparisons in every lookup of one',
   source.count("COALESCE(kind, 'vpn') = ? ORDER BY ts DESC LIMIT 1"), 0)

print('\nCache keys')
# ...and per page since 1.10.207.
ok('the firewall’s fields kept per window', "'fw/inside/%d/%s' % (hours, area)" in source, True)
ok('a person’s card kept per realm and name, not joined with dashes',
   "daemon.held('who/' + json.dumps([only," in source, True)
ok('secrets=0 is not a yes', "whole = str(one('secrets') or '').strip().lower() in "
   "('1', 'true', 'yes', 'on')" in source, True)

print('\nThe page')
ok('the Domain page asks again after the answer, never while one is out',
   ('var WIN_FLYING = 0;' in page, 'if (again && WIN_FLYING' in page), (True, True))
ok('...and the list under it waits for its search rather than starting it again',
   "{lane: 'win-events', quiet: quietly === true}" in page, True)
ok('the front page and Traffic stop what was asked before when somebody asks again',
   ("QUIET_TICK ? undefined : {lane: 'ov-dashboard'}" in page,
    "quiet ? undefined : {lane: 'fw-overview'}" in page), (True, True))
ok('the router’s read is numbered', 'if (mine !== ROUTER_ASKED) return;' in page, True)
ok('bans not on the router are paged, with the count of all of them',
   ("key: 'router-missing'" in page, "'not_carried_n': missing_n" in source), (True, True))
ok('names past the first four hundred are asked next', 'PTR_WANT = PTR_WANT.concat(later);'
   in page, True)
ok('a day’s bar on Traffic is named after its UTC day',
   'pad2(dd.getUTCDate())' in page, True)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
