#!/usr/bin/env python3
"""1.10.371: round five - what reviewing the four rounds before found, and
the pages' popups.

    ./test/fixes371_speed.py
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


folder = Path(tempfile.mkdtemp(prefix='isemon-371-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'winsec': 1, 'winsec_rollup': 1})
store = isemon.Storage(isemon.DB_FILE)
db = store.db
NOW = time.time()
src = (ROOT / 'isemon.py').read_text()
page = (ROOT / 'web' / 'index.php').read_text()

print('A catalogue filling begun by an older version, carried on here')
for n, cc in enumerate(['CZ', 'DE', 'US', 'FR']):
    store.add_failed({'session': 'f/%d' % n, 'ts': NOW - (4 - n) * 3600, 'ip': '198.51.100.%d' % n,
                      'username': 'u%d' % n, 'kind': 'vpn', 'country': cc})
with store._seen_lock:
    store._seen_pending = {}
db.execute('DELETE FROM seen_values')
db.commit()
# As 1.10.366 left it: building, half way, with no word of its columns.
store.set_meta('seen_state', 'building')
store.set_meta('seen_build_until', repr(NOW))
store.set_meta('seen_built_failed', repr(NOW - 2.5 * 3600))
for key in ('seen_build_cols', 'seen_wanted'):
    store.drop_meta(key)
store._seen_said = (0.0, '')
store._seen_filled = (0.0, None)
ok('carried on to the end', store.seen_build(), True)
ok('...the countries not believed, the rows before it never having been noted for them',
   store.seen_usable('failed', 'country'), False)
ok('...filled in by themselves', store.seen_build(), True)
ok('...believed then, and every one of them', (store.seen_usable('failed', 'country'),
                                                sorted(store.seen_values_of('failed', 'country'))),
   (True, ['CZ', 'DE', 'FR', 'US']))

print('Counting ahead of time: an event years back is no walk of every hour between')
HOUR = 3600
top = int(NOW // HOUR) * HOUR
store.note_win_events([{'ident': 'w%d' % n, 'ts': top - 2 * 86400 + n * 900, 'server': 'DC1',
                        'event': 4625, 'kind': 'logon-failed', 'account': 'a%d' % (n % 3),
                        'machine': 'PC1', 'ip': '10.0.0.1'} for n in range(40)]
                      + [{'ident': 'old', 'ts': top - 3 * 365 * 86400, 'server': 'DC1',
                          'event': 4624, 'kind': 'logon', 'account': 'stray', 'machine': 'PC9',
                          'ip': '10.0.0.9'}])
began = time.time()
total = store.roll_build_now('test')
took = time.time() - began
ok('every event counted', total, 41)
ok('...in seconds, not the 26 000 empty hours between', took < 30)
ok('...and it proves', store.roll_prove(), [])

print('The rest')
ok('an index built behind the daemon no longer holds every writer for its length',
   'with self._write:\n                        apart.execute(text)' in src, False)
ok('ANALYZE only where SQLite can limit it', 'if sqlite3.sqlite_version_info >= (3, 32):' in src)
ok('Refresh on Disk and logs reads the sizes again', 'dbi = store_db(store, fresh=fresh)' in src
   and 'if kept and not fresh and time.time() - kept[0] < 3600:' in src)
ok('the CLI says the restart though it came and went between two looks',
   "if (st == 'rebooting' or row.get('rebooted')) and last != 'rebooting' and not quiet:" in src
   and "else 'updated - restarting, as it needs'))" in src)
ok('a popup closed gives its parent back its own title to be known by',
   'src: $(\'modal-title\').dataset.src,' in page
   and "$('modal-title').dataset.src = frame.src;" in page)
ok('the find box: a list still asked for never drawn over the person card',
   "++FIND.seq;\n  stopLane('find');" in page)
ok('acme: a search the box no longer holds narrows nothing',
   "if (String(AM.text || '').trim() !== q) return;" in page)
ok('the name card\'s "Everything about it" counts the window, not all time',
   'peekName({username: d.name});' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
