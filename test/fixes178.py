#!/usr/bin/env python3
"""1.10.178: the loop's slow chores behind it, the lists downloaded before
the write is taken, a failed copy not tried again all night, the old rows of
the ban history let go, fewer reads of the same window, and the Domain page's
filters, popups and refresh.

    ./test/fixes178.py
"""
import os
import shutil
import sqlite3
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


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

folder = tempfile.mkdtemp(prefix='isemon-178-')
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
isemon.CONFIG.update({'api_port': 19971, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time()

print('\nThe slow chores behind the loop')
ran = threading.Event()
release = threading.Event()


def slow():
    ran.set()
    release.wait(5)


ok('a chore starts behind the loop', daemon.behind('t', slow), True)
ran.wait(2)
ok('...and a second one of the same name is skipped while it runs',
   daemon.behind('t', slow), False)
release.set()
daemon._behind['t'].join(3)
ok('...and runs again once the first is done', daemon.behind('t', lambda: None), True)
daemon._behind['t'].join(3)


def broken():
    raise RuntimeError('boom')


ok('a chore that raises is said, not lost with its thread', daemon.behind('b', broken), True)
daemon._behind['b'].join(3)
ok('the loop hands its chores over rather than doing them',
   all(x in source for x in ("self.behind('house', self._house_pass)",
                             "self.behind('fold', self.fold_due",
                             "self.behind('lists', self._lists_pass)",
                             "self.behind('directory', self._directory_pass)")), True)
ok('...and a stop waits a moment for the housekeeping',
   "('the housekeeping', ('_behind', 'house'), 15)" in source, True)

print('\nThe lists downloaded before the write')
inside = []


def ranges():
    for k in range(3000):
        inside.append(bool(getattr(store._local, 'writing', 0)))
        lo = bytes([10, 0, k // 256, k % 256])
        yield (lo, lo, 4, 'ZZ')


kept = store.put_ranges_streamed('geo_ranges', ranges(), tag_column='cc')
ok('every range was written', kept > 0, True)
ok('...and none of the download happened inside the write', any(inside), False)
left = [p for d in (tempfile.gettempdir(), folder) for p in os.listdir(d)
        if p.startswith('isemon-ranges-')]
ok('...and the spool file is gone again', left, [])


def half():
    yield (b'\x0b\x00\x00\x01', b'\x0b\x00\x00\x01', 4, 'CZ')
    raise OSError('the line dropped')


before = store.db.execute('SELECT COUNT(*) AS n FROM geo_ranges').fetchone()['n']
try:
    store.put_ranges_streamed('geo_ranges', half(), tag_column='cc')
    fell = False
except OSError:
    fell = True
ok('a download that falls over half way says so', fell, True)
ok('...and leaves the table as it was',
   store.db.execute('SELECT COUNT(*) AS n FROM geo_ranges').fetchone()['n'], before)
left = [p for d in (tempfile.gettempdir(), folder) for p in os.listdir(d)
        if p.startswith('isemon-ranges-')]
ok('...and no spool file behind it', left, [])

print('\nA failed copy is not tried again every five minutes')
isemon.CONFIG.update({'backup_daily': 1, 'backup_at': '00:00'})
calls = []
real_dump, real_ready, real_backup = store.dump, store.dump_ready, store.backup


def failing(*a, **k):
    calls.append(1)
    raise OSError('No space left on device')


store.dump_ready = lambda: (True, '')
store.dump = failing
store.backup = failing
daemon.backup_due(wait=True)
ok('the copy failed', len(calls), 2)
ok('...and the failure is remembered for the day', bool(daemon._backup_failed), True)
daemon.backup_due()
time.sleep(0.2)
ok('...so the next pass does not start it again', len(calls), 2)
daemon._backup_failed = (daemon._backup_failed[0], time.time() - 7200, 1)
daemon.backup_due()
if daemon._backup_thread is not None:
    daemon._backup_thread.join(5)
ok('...but an hour or more later it does', len(calls), 4)
ok('...and the wait grows with each failure', daemon._backup_failed[2], 2)
store.dump, store.dump_ready, store.backup = real_dump, real_ready, real_backup
isemon.CONFIG['backup_daily'] = 0
ok('a big database on a server gets no row-by-row copy instead',
   'PORTABLE_MOST_BYTES' in source and 'if self._too_big_to_copy():' in source, True)

print('\nOne clean-up at a time')
isemon.Daemon._TIDY_LOCK.acquire()
try:
    got = daemon.tidy_old_rows()
finally:
    isemon.Daemon._TIDY_LOCK.release()
ok('a pass that finds one going is skipped', got.get('busy'), True)
ok('...and says nothing went', got.get('gone'), 0)
ok('...and with none going it runs', daemon.tidy_old_rows().get('busy'), None)

print('\nThe ban history let go of')
old = NOW - 400 * 86400
with store.db_write() as db:
    for k in range(5):
        db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) '
                   'VALUES (?,?,?,?,?,?)', (old + k, '192.0.2.%d' % k, 'blocked', 'x', 1, ''))
    db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?,?,?,?,?,?)',
               (NOW - 3600, '192.0.2.99', 'blocked', 'x', 1, ''))
isemon.CONFIG.update({'retain_events_days': 180, 'block_ladder_forget_days': 30})
daemon.tidy_old_rows()
n_old = store.db.execute('SELECT COUNT(*) AS n FROM block_events WHERE ts < ?',
                         (NOW - 200 * 86400,)).fetchone()['n']
ok('a year-old ban history is let go of', n_old, 0)
ok('...and last hour\'s is kept',
   store.db.execute("SELECT COUNT(*) AS n FROM block_events WHERE ip='192.0.2.99'")
   .fetchone()['n'], 1)
with store.db_write() as db:
    db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?,?,?,?,?,?)',
               (old, '192.0.2.50', 'blocked', 'x', 1, ''))
isemon.CONFIG['block_ladder_forget_days'] = 0
daemon.tidy_old_rows()
ok('...but not where the ladder never forgets',
   store.db.execute("SELECT COUNT(*) AS n FROM block_events WHERE ip='192.0.2.50'")
   .fetchone()['n'], 1)
isemon.CONFIG['block_ladder_forget_days'] = 30
ok('the ban history has an index on when each ban ended',
   'blocked_log_ended' in dict(isemon.Storage.LATER_INDEXES), True)
have = set(store.dialect.index_names(store.db))
ok('...and it is made', 'blocked_log_ended' in have, True)

print('\nA table held to its cap, counted before the write')
with store.db_write() as db:
    for k in range(30):
        db.execute('INSERT INTO eduroam_seen (mac, ts) VALUES (?,?)',
                   ('aa:bb:cc:00:00:%02x' % k, NOW - k))
ok('a table under its cap takes no write', store.tidy_capped('eduroam_seen', 'ts', 100), 1)
ok('...and loses nothing',
   store.db.execute('SELECT COUNT(*) AS n FROM eduroam_seen').fetchone()['n'], 30)
store.tidy_capped('eduroam_seen', 'ts', 10)
ok('one over it is cut to the cap',
   store.db.execute('SELECT COUNT(*) AS n FROM eduroam_seen').fetchone()['n'] <= 11, True)
ok('...and no count is made inside a write any more',
   "left = db.execute('SELECT COUNT(*) AS n FROM ptr')" not in source, True)

print('\nThe bans among those over the bar, in one statement')
store.block('203.0.113.7', None, 'test')
store.block('203.0.113.8', time.time() - 5, 'ran out')
ok('a live ban is found, a spent one is not',
   store.banned_among(['203.0.113.7', '203.0.113.8', '203.0.113.9']), {'203.0.113.7'})
ok('...and the whole list is no longer read every five seconds for it',
   'out_now = self.store.banned_among(over)' in source, True)

print('\nWaiters on a slow answer do not all ask it again')
isemon.Daemon.HELD_WAIT_S, was = 0.3, isemon.Daemon.HELD_WAIT_S
going = threading.Event()
asked = []


def dear():
    asked.append(1)
    going.wait(3)
    return {'n': 1}


first = threading.Thread(target=lambda: daemon.held('t178', 60, dear))
first.start()
time.sleep(0.1)
try:
    daemon.held('t178', 60, dear)
    said = 'answered'
except sqlite3.Error as e:
    said = 'busy' if isemon.statement_stopped(e) else str(e)
going.set()
first.join(3)
isemon.Daemon.HELD_WAIT_S = was
ok('a waiter whose first asker is still going is told it is busy', said, 'busy')
ok('...and the question was asked once', len(asked), 1)

print('\nFolding: the homes found by their own subnets')
isemon.CONFIG.update({'fold_least': 4, 'fold_widest': 24, 'blacklist': 1})
for k in range(1, 6):
    store.block('203.0.113.%d' % (20 + k), None, 'test')
store.block('198.51.100.0/24', None, 'test')
store.block('198.51.100.33', None, 'test')
plan = daemon.fold_plan()
nets = {g['net']: (g['existing'], sorted(m['ip'] for m in g['members'])) for g in plan['groups']}
ok('five neighbours make a street', nets.get('203.0.113.0/24', (None, []))[0], False)
ok('...with all of them in it', len(nets.get('203.0.113.0/24', (None, []))[1]) >= 5, True)
ok('an address inside a standing subnet goes into it',
   nets.get('198.51.100.0/24'), (True, ['198.51.100.33']))
ok('the plan is made once for an automatic fold',
   "said = self._fold_apply(by='by itself', plan=plan)" in source, True)

print('\nThe Domain page')
ok('the filters are counted over the dates picked', 'win_shape(since, machines, kinds, until)'
   in source, True)
ok('...and kept under them', "int(at_from) // 60" in source, True)
ok('...and not at all for a popup', "extra = {} if one('choices') == '0'" in source, True)
ok('the popups ask without them', page.count('choices=0') >= 5, True)
ok('the lockout popup asks for the refusals', '&before=3600&after=900&bad=1' in page, True)
ok('the Domain page is drawn again when something moved',
   "if (TAB === 'windows' && Date.now() - WIN_TICK_AT > 30000)" in page, True)
ok('an emptied search box drops the answer on its way',
   page.index('++FIND.seq;\n  clearTimeout(FIND_KEEP_SOON);\n  if (!q) {') > 0, True)
ok('the overall answer is kept under the machine-accounts setting',
   "'winsec/%d/%d' % (hours, 1 if int(CONFIG.get('winsec_machines')" in source, True)
ok('a machine has an index over its folded name',
   'win_machine_lc' in dict(isemon.Storage.LATER_INDEXES), True)
ok('an IPv4 address is asked of its index', "sql += ' AND ip = ?'" in source, True)
ok('the identical events are counted per controller', "newest_of[server] = " in source, True)

print('\nWhat is already there, asked inside the write')
failed = []


class Broken(object):
    def execute(self, *a, **k):
        raise sqlite3.OperationalError('gone')


class Holder(object):
    db = Broken()
    dialect = store.dialect
    HERE_WINDOW_S = 60

    def is_split(self, t):
        return False


got = isemon.Storage.already_here(Holder(), ['a', 'b'], failed=failed)
ok('a failure is said into the caller\'s own list', failed, [True])
ok('...and everything is taken as there', got, {'a', 'b'})
ok('...asked inside the write, not before it',
   source.index('with self.db_write() as db:\n                    # Which of them are genuinely new')
   > 0, True)

print('\nOne address, however it is written')
store.block('2001:db8::5', None, 'test')
said = daemon.address_story('2001:DB8::5')
ok('typed in capitals, it is the banned address', (said.get('ip'), said.get('blocked')),
   ('2001:db8::5', True))
said = daemon.address_story('::ffff:203.0.113.7')
ok('...and written the IPv6 way, the IPv4 one', (said.get('ip'), said.get('blocked')),
   ('203.0.113.7', True))
with store.db_write() as db:
    for k in range(70):
        db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?,?,?,?,?,?)',
                   (NOW - k, '203.0.113.70', 'blocked', 'x', 1, ''))
    db.execute('INSERT INTO block_events (ts, ip, what, why, auto, by) VALUES (?,?,?,?,?,?)',
               (NOW - 9999, '203.0.113.7', 'blocked', 'mine', 1, ''))
said = daemon.address_story('203.0.113.7')
ok('its own history is found whatever its neighbours did',
   ('mine' in [s['why'] for s in said['story']],
    {s['ip'] for s in said['story']}), (True, {'203.0.113.7'}))

store.block('198.18.0.0/24', None, 'a street')
said = daemon.address_story('198.18.0.0/24')
ok('a banned subnet still has its own story', [x['ip'] for x in said['story']][:1],
   ['198.18.0.0/24'])

print('\nThe counts per controller kept over a restart')
hold = {isemon.WINSEC_SEEN_KEY: {'at': 100.0, 'parts': {0: 'k|2|100'}, 'of': {0: 'dc1'},
                                 'newest_of': {'dc1': 100.0}}}
back = isemon.LogTail.unpack_hold(isemon.LogTail.pack_hold(hold))
ok('which controller each count is of comes back',
   (back[isemon.WINSEC_SEEN_KEY].get('of'), back[isemon.WINSEC_SEEN_KEY].get('newest_of')),
   ({0: 'dc1'}, {'dc1': 100.0}))

print('\nAdministrators')
daemon.add_user('boss', 'Pa55word-long-enough!', role='fulladmin')
daemon.add_user('old', 'Pa55word-long-enough!', role='fulladmin')
store.put_user('old', disabled=True)
for one in list(store.users()):
    if one['name'] not in ('boss', 'old') and one['role'] == 'fulladmin':
        store.drop_user(one['name'])
try:
    daemon.set_role('old', 'readonly')
    said = 'changed'
except Exception as e:
    said = str(e)
ok('a switched-off full administrator can be made something else', said, 'changed')
try:
    daemon.drop_user('old')
    said = 'gone'
except Exception as e:
    said = str(e)
ok('...and removed', said, 'gone')
try:
    daemon.drop_user('boss')
    said = 'gone'
except Exception as e:
    said = 'refused'
ok('the last one that can sign in still cannot', said, 'refused')

print('\nThe catalogue written a thousand at a time')
ok('each thousand is a write of its own',
   "for at in range(0, len(rows), 1000):\n                lump = rows[at:at + 1000]\n"
   "                with Db.patiently" in source, True)
ok('a whole day is let go of with a short wait for its turn, a few times over',
   (isemon.Storage.LETGO_LOCK_MS < 1000, isemon.Storage.LETGO_TRIES > 1), (True, True))

print('\nThe Banned page')
store.block('192.0.2.200', None, 'test')
st1 = daemon.bans_stamp()
with store.db_write() as db:
    db.execute("UPDATE blocked SET hits = COALESCE(hits,0) + 5 WHERE ip='192.0.2.200'")
ok('a ban turned away once more does not move the stamp', daemon.bans_stamp(), st1)
many = [{'name': 'u%d' % k, 'tries': 1} for k in range(25)]
daemon.per_ban('names', [], 600, lambda ips: {})
daemon._per_ban['names']['192.0.2.200'] = (time.time(), many)
row = next(r for r in daemon._blocked_list_now() if r['ip'] == '192.0.2.200')
ok('each ban carries its first six names', (len(row['names']), row['names_cut']), (6, True))
asked = []
daemon._per_ban['names']['192.0.2.200'] = (time.time() - 9999, many[:2])
got = daemon.per_ban('names', ['192.0.2.200'], 600,
                     lambda ips: asked.append(list(ips)) or time.sleep(0.3)
                     or {'192.0.2.200': many[:3]})
ok('names gone stale are handed out as they were', len(got['192.0.2.200']), 2)
daemon._per_ban_going['names'].join(3)
ok('...and asked again behind the page', (asked, len(daemon._per_ban['names']['192.0.2.200'][1])),
   ([['192.0.2.200']], 3))
ok('the page reads the whole list once a minute, not every twenty seconds',
   'Date.now() - BANS_AT < 60000' in page, True)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
