#!/usr/bin/env python3
"""1.10.196: a source of bans is off, only watched, or on. Watched, it counts
and makes its bans as if it banned, and carries none of them: no firewall, no
published list, no access list, no step on the ladder and no floor under the
counting. Switched on, every one of them still running is carried at once.

    ./test/fixes196.py
"""
import shutil
import sys
import tempfile
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
folder = tempfile.mkdtemp(prefix='isemon-196-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'blacklist': 1,
                      'block_tries': 3, 'block_window_min': 10, 'watch_devices': '',
                      'block_ladder': '10, 60, forever', 'fold_least': 2})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)


def carried():
    return sorted(isemon.same_address(r['ip']) for r in daemon._blocked_for_router())


def feed():
    daemon._banfeed_cache = {}
    return sorted(w for w, _r in daemon.banfeed_entries())


def fails(ip, tag, n=4):
    t = time.time()
    with store.db_write() as db:
        for i in range(n):
            db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, ip) '
                       "VALUES (?, ?, 'dc1', 4625, 'logon-failed', 'administrator', ?)",
                       ('%s%d' % (tag, i), t - 60 + i, ip))


print('\nThree states')
ok('the words a value can be said in',
   [isemon.ban_mode_of(v) for v in (0, 1, 2, '0', '1', '2', True, False, 'on', 'watch',
                                    'off', 'Ban', 'monitor', '', None, 'nonsense')],
   ['off', 'on', 'watch', 'off', 'on', 'watch', 'on', 'off', 'on', 'watch', 'off', 'on',
    'watch', 'off', 'off', 'off'])
ok('the old ones stay as they were, the new ones off',
   [isemon.DEFAULTS['ban_from_%s' % k] for k in isemon.BAN_SOURCES],
   ['on', 'on', 'off', 'off', 'off', 'off', 'on'])
ok('a setting saved as 0 or 1 by a version before is read as off or on',
   [isemon.check_setting('ban_from_win', v) for v in (0, 1, '2', 'watch', 'ON')],
   ['off', 'on', 'watch', 'watch', 'on'])
try:
    isemon.check_setting('ban_from_manual', 'watch')
    refused = False
except ValueError:
    refused = True
ok('a ban made by hand is meant: it cannot be only watched', refused)
ok('...even said through an older word for it', isemon.ban_source_mode('manual') in
   ('on', 'off'))
ok('every source with three states has the words for them',
   all(daemon.CHOICE_WORDS.get('ban_from_%s' % k) for k in isemon.BAN_SOURCES), True)

print('\nWatched: counted and made, carried nowhere')
daemon.save_settings({'ban_from_win': 'watch'}, by='test')
ok('saved as watched', (isemon.CONFIG['ban_from_win'], isemon.ban_source_mode('win')),
   ('watch', 'watch'))
ok('...and counted, not banning', (sorted(isemon.ban_sources_on()),
                                   sorted(isemon.ban_sources_watched()),
                                   'win' in isemon.ban_sources_counted()),
   (['ise', 'manual', 'nps'], ['win'], True))
fails('81.200.11.7', 'w')
made = daemon.judge_sources()
row = store.blocked_one('81.200.11.7') or {}
ok('the domain makes its ban', (made, row.get('src')), (1, 'win'))
ok('...which is only watched', isemon.ban_row_watched(row), True)
ok('...carried to no firewall', '81.200.11.7' in carried(), False)
ok('...put in no published list', any('81.200.11.7' in w for w in feed()), False)
ok('...and not a step on the ladder', store.blocked_before('81.200.11.7'), 0)
with store.db_write() as db:
    what = [r['what'] for r in db.execute(
        "SELECT what FROM block_events WHERE ip='81.200.11.7'")]
ok('...written down as watched', what, ['watched'])
with store.db_write() as db:
    events = [dict(r) for r in db.execute(
        "SELECT kind, detail FROM events WHERE detail LIKE '%81.200.11.7%'")]
ok('...said as what it would have been', any(
    (e['kind'] == 'watch' and 'only watched' in e['detail']) for e in events), True)
ok('...and not as a ban', any(e['kind'] == 'block' for e in events), False)
listed = {r['ip']: r for r in daemon._blocked_list_now()}
one = listed.get('81.200.11.7') or {}
ok('the Banned page shows it, marked watched', (one.get('src_off'), one.get('src_watch')),
   (True, ['win']))
state = {s['key']: s for s in daemon.ban_sources_state()['sources']}
ok('the card says the mode', (state['win']['mode'], state['ise']['mode'],
                              state['fw']['mode']), ('watch', 'on', 'off'))
ok('the count in the header is of what is carried',
   "'carried-n2/%s' % self.bans_stamp()" in source
   and 'rows = self.ban_effective(self.store.blocked_all())' in source, True)

print('\nIts end moves no floor')
fails('81.200.11.8', 'v')
daemon.judge_sources()
before = store.let_back_in_at('81.200.11.8')
store.unblock('81.200.11.8', by='test')
ok('a watched ban taken off does not reset the counting',
   store.let_back_in_at('81.200.11.8'), before)
with store.db_write() as db:
    what = [r['what'] for r in db.execute(
        "SELECT what FROM block_events WHERE ip='81.200.11.8' ORDER BY ts")]
ok('...and is written down as a watch ended', what, ['watched', 'watch ended'])

print('\nSwitched on: carried at once')
daemon.save_settings({'ban_from_win': 'on'}, by='test')
ok('what it was watching is carried now', '81.200.11.7' in carried(), True)
ok('...and in the published list', any('81.200.11.7' in w for w in feed()), True)
ok('...no longer marked watched', isemon.ban_row_watched(store.blocked_one('81.200.11.7')),
   False)
daemon.save_settings({'ban_from_win': 'off'}, by='test')
ok('switched off, it is kept and carried nowhere',
   (store.blocked_one('81.200.11.7') is not None, '81.200.11.7' in carried()), (True, False))
fails('81.200.11.9', 'u')
ok('...and counts nothing at all', (daemon.judge_sources(),
                                    store.blocked_one('81.200.11.9')), (0, None))

print('\nThe command line and the page')
ok('the command line says the three', '--set ban_from_win=on | watch | off' in source)
ok('a three-way switch rather than a dropdown', ('function banModeSwitch' in page,
                                                 '.sw3[data-mode="watch"]' in page), (True, True))
ok('switching from watched to on asks first, with how many',
   "Carry what they have been watching" in page and "one.mode === 'watch'" in page)
ok('the Banned page has a group for what is only watched',
   "'Only watched: what they would keep out'" in page)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
