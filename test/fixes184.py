#!/usr/bin/env python3
"""1.10.184: nothing the pages or the reader do waits for what it need not -
the firewall's own serial, counts not thrown away for the firewall's writes,
waiting not holding a turn, a failed question not asked again by everybody,
positions not saved past refused lines, the country database in memory.

    ./test/fixes184.py
"""
import ipaddress
import random
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
folder = tempfile.mkdtemp(prefix='isemon-184-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nThe firewall’s own serial')
was = daemon._serial
daemon.bump('fw')
ok('a lot of firewall lines does not move the serial every page watches', daemon._serial, was)
ok('...it moves its own', getattr(daemon, '_serial_fw', 0), 1)
ok('the writer moves only that one', "daemon.bump('fw')" in source, True)
ok('the page reloads on it only on the Traffic page (and the front page, now and then)',
   'var fwReload = fwMoved && (TAB === \'traffic\'' in page, True)
ok('...and status says both', "'serial_fw': getattr(self, '_serial_fw', 0)," in source, True)

print('\nThe counts of the refusals are not thrown away for the firewall’s writes')
w = store._writes
store.note_fw_events([])
ok('nothing written, nothing moved', store._writes, w)
ok('the firewall’s and the domain’s writes are counted apart',
   ('self._writes_fw = ' in source, 'self._writes_win = ' in source), (True, True))

print('\nA question that failed is not asked again by everybody waiting on it')
asked = []
going = threading.Event()


def failing():
    asked.append(1)
    going.wait(2)
    raise sqlite3.OperationalError('could not extend file: no space left')


first = threading.Thread(target=lambda: _try(lambda: daemon.held('t184', 60, failing)))
said = []


def _try(fn):
    try:
        fn()
        said.append('answered')
    except sqlite3.Error as e:
        said.append(str(e))


first.start()
time.sleep(0.2)
second = threading.Thread(target=lambda: _try(lambda: daemon.held('t184', 60, failing)))
second.start()
time.sleep(0.2)
going.set()
first.join(5)
second.join(5)
ok('the waiter is told what the first ran into', said,
   ['could not extend file: no space left'] * 2)
ok('...and the question was asked once', len(asked), 1)

print('\nWaiting on somebody else’s answer does not hold a turn')
ok('the turn is given up while waiting, and taken again only to ask',
   'API_GATE.leave()\n                _GATED.held = False\n            mine.wait(self.HELD_WAIT_S)'
   in source, True)
ok('...and taken again before going on, answered or not',
   'if gave_turn and (got or mine.is_set()):' in source, True)
ok('a question stopped by whoever asked it is not told to the others',
   'if not isinstance(e, AskedToStop) and not statement_stopped(e):' in source, True)
ok('at least two questions at a time', isemon.API_GATE.most >= 2, True)

print('\nWhere the files had got to is not saved past refused lines')
daemon.hand_back('win', [{'ident': 'w1', 'ts': 1}])
ok('lines handed back are owed', daemon.owed(), True)
real = store.note_win_events
store.note_win_events = lambda many: len(many)
daemon.flush_win_events()
store.note_win_events = real
ok('...until a flush writes everything waiting', daemon.owed(), False)
daemon.owe('fw', 3)
ok('the firewall’s are owed until a lot after them is written', daemon.owed(), True)
ok('...the writer saves no positions meanwhile',
   'if wrote and tails is not None and not daemon.owed()' in source, True)
ok('...counting a lot the reader has taken but not handed over yet as not holding them',
   "+ (1 if getattr(self, '_fw_in_hand', False) else 0))" in source, True)
daemon.owe('fw', None)
ok('...and at most once a second while lots are waiting',
   'or time.time() - self.saved_at >= self.SAVE_EVERY_S' in source, True)

print('\nThe country database in memory')
geo, where, step = [], 0, 1 << 20
codes = ['CZ', 'SK', 'PL', 'DE', 'AT']
while where < (1 << 32) - step:
    geo.append((ipaddress.IPv4Address(where).packed,
                ipaddress.IPv4Address(where + step - 1).packed, 4,
                codes[(where // step) % len(codes)]))
    where += step
store.put_geo(geo)
store.country_of('1.2.3.4')                  # starts reading them in
for _ in range(100):
    if store.geo_index() is not None:
        break
    time.sleep(0.05)
ok('the ranges are held in memory', store.geo_index() is not None, True)
r = random.Random(4)
wrong = 0
for _ in range(500):
    ip = str(ipaddress.IPv4Address(r.getrandbits(32)))
    packed = ipaddress.IPv4Address(ip).packed
    row = store.db.execute('SELECT cc, hi FROM geo_ranges WHERE family=4 AND lo<=? '
                           'ORDER BY lo DESC LIMIT 1', (packed,)).fetchone()
    want = row['cc'] if row is not None and row['hi'] >= packed else ''
    if store.country_of(ip) != want:
        wrong += 1
ok('...and say what the table says, every time', wrong, 0)
store.put_geo(geo[:10])
ok('replaced, the memory is let go of', store.geo_index(), None)

print('\nSmaller things')
ok('a rotated file’s records are kept when the new one cannot be opened yet',
   "            # moved past, an empty answer here lost them for good" in source, True)
ok('the catalogue is not written from inside a lot’s write',
   "if into is None and many > 20000 and not getattr(self._local, 'writing', 0):" in source,
   True)
ok('...nor on the loop', "self.behind('seen', self.store.seen_flush" in source, True)
ok('the domain’s controllers are asked behind the reader',
   "self.behind('controllers', self.note_controllers," in source, True)
ok('the front page’s questions carry the asker’s limit',
   'with statement_limit(limit):\n                    out[name] = call()' in source, True)
ok('...and the page does not ask again while one is out',
   'if (QUIET_TICK && DASH_FLYING' in page, True)
ok('a search asked again behind the page keeps its own words',
   'lambda frozen=dict(asked): ask(**frozen))' in source, True)
ok('the first status after a start does not wait for the dear counts',
   ("empty={'failed': 0, 'passed': 0, 'failed_vpn': 0, 'passed_vpn': 0," in source,
    "var tf = (s.totals || {}).failed || {}" in page), (True, True))
names = dict(isemon.Storage.LATER_INDEXES)
ok('a device picked, and the ban history in its order, have indexes',
   all(k in names for k in ('failed_device_ts', 'passed_device_ts', 'blocked_log_order')),
   True)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
