#!/usr/bin/env python3
"""1.10.172: four thousand lines a second.

The firewall's lines written behind the reader, made ready by the reader
and written by a thread of its own - in the order they were read, with
where the files had got to saved only once they are; lots waiting merged
into one write; a write of the firewall's own tables on a database server
not waiting for every other write; the reader not resting between passes
while it is behind; the savepoints of ISE's records in one round trip; and
the database page saying when the server's own cache is too small.

    ./test/fixes172.py
"""
import json
import random
import shutil
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
folder = tempfile.mkdtemp(prefix='isemon-172-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'a.db'
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'fwlog_keep_allowed': 1,
                      'fwlog_sources': [{'name': 'fg', 'kind': 'fortigate', 'path': folder,
                                         'zone': 'UTC'}]})
NOW = int(time.time()) - 600
R = random.Random(172)


def fg_line(k, at=None):
    at = NOW + (k % 500) if at is None else at
    return ('Oct  1 07:56:02 fw.example.cz date=2026-10-01 time=07:56:02 devname="FG-EX" '
            'devid="FGT00EXAMPLE0001" eventtime=%d%09d tz="+0000" logid="0000000013" '
            'type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.%d.%d '
            'srcport=%d srcintf="LAN" dstip=198.51.100.%d dstport=%d dstintf="wan1" '
            'srccountry="Reserved" dstcountry="Denmark" sessionid=%d proto=6 action="%s" '
            'policyid=%d policyname="P%d" service="HTTPS" duration=%d sentbyte=%d '
            'rcvdbyte=%d' % (at, k, k % 7, k % 200, 1024 + k, k % 50, R.choice((443, 80, 53)),
                             10000 + k, R.choice(('close', 'deny', 'client-rst')), k % 4,
                             k % 4, k % 90, R.randrange(10 ** 6), R.randrange(10 ** 7)))


def facts(lines):
    out = []
    for r in isemon.fg_parse_lines(lines):
        if r is not None and hasattr(r, 'facts'):
            r.facts['fw'] = 'fg'
            out.append(r.facts)
    return out


def state(store):
    rows = sorted(tuple(r) for r in (
        (x['ident'], x['ts'], x['srcip'], x['dstport'], x['verdict'], x['sent'], x['rcvd'])
        for x in store.db.execute('SELECT * FROM fw_events')))
    roll = sorted((r['span'], r['at'], r['dim'], r['val'], r['verdict'], r['n'], r['sent'],
                   r['rcvd']) for r in store.db.execute('SELECT * FROM fw_roll'))
    return rows, roll


lines = [fg_line(k) for k in range(3000)]
lines += lines[100:300]                        # read twice

print('\nMade ready by the reader, written by the writer: the same rows and counts')
a = isemon.Storage(Path(folder) / 'a.db')
b = isemon.Storage(Path(folder) / 'b.db')
for at in range(0, len(lines), 700):
    a.note_fw_events(facts(lines[at:at + 700]))
    b.note_fw_events(b.fw_prepare(facts(lines[at:at + 700])))
ok('every row and every counted bucket alike', state(a), state(b))
ok('...and each line once', len(state(b)[0]), 3000)

print('\nThe writer behind the reader')
c = isemon.Storage(Path(folder) / 'c.db')
d = isemon.Daemon(c)
saved = []
real_set = c.set_meta


def watch_set(key, value):
    if key == 'tails':
        saved.append((value, c.db.execute('SELECT COUNT(*) AS n FROM fw_events')
                      .fetchone()['n']))
    return real_set(key, value)


c.set_meta = watch_set
d._fw_writer = isemon.FwWriter(d)
d._fw_behind_thread = threading.get_ident()
gate = isemon.FW_WRITING
gate.acquire()                                  # the writer held up by a write
done = []
for k, at in enumerate(range(0, 2400, 600)):
    with d._win_waiting_lock:
        d._fw_waiting = facts(lines[at:at + 600] + lines[at:at + 50])
    t0 = time.time()
    if k < 2:
        d.flush_fw_events(tails='{"pass": %d}' % k)
        done.append(time.time() - t0 < 1.0)
ok('the reader hands a lot over and goes on', done, [True, True])
time.sleep(0.3)
gate.release()
d._fw_writer.drain(30)
ok('...each written once, whatever was waiting', c.db.execute(
    'SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'], 1200)
ok('where the files had got to is saved once the lines are written, never before',
   [(json.loads(v)['pass'], n) for v, n in saved], [(0, 600), (1, 1200)])
d._fw_behind_thread = None
with d._win_waiting_lock:
    d._fw_waiting = facts(lines[1200:1800])
ok('a write from anywhere else waits for the writer and then writes there and then',
   d.flush_fw_events(), 600)
ok('...so the rows land in the order they were read',
   c.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'], 1800)

print('\nLots waiting are written as one, each line once')
e = isemon.Storage(Path(folder) / 'e.db')
f_ = isemon.Storage(Path(folder) / 'f.db')
de = isemon.Daemon(e)
de._fw_writer = isemon.FwWriter(de)
gate.acquire()
de._fw_writer.submit(e.fw_prepare(facts(lines[0:600])), None)
time.sleep(0.2)
for at in (600, 1200):
    de._fw_writer.submit(e.fw_prepare(facts(lines[at:at + 600])), '{"at": %d}' % at)
taken = de._fw_writer.q.qsize()
gate.release()
de._fw_writer.drain(30)
de._fw_writer.submit(e.fw_prepare(facts(lines[1500:2100])), '{"at": 1500}')
de._fw_writer.drain(30)
ok('two lots were waiting, and were taken together', taken, 2)
for at in (0, 600, 1200, 1500):
    f_.note_fw_events(facts(lines[at:at + 600]))
ok('the same rows and counts as written one lot after another', state(e), state(f_))
ok('...and the newest positions are the ones saved', json.loads(e.get_meta('tails') or '{}'),
   {'at': 1500})
ok('nothing is left waiting', (de._fw_writer.busy(), de._fw_writer.idle.is_set()), (0, True))

print('\nA lot that could not be written')
h = isemon.Storage(Path(folder) / 'h.db')
dh = isemon.Daemon(h)
dh._fw_writer = isemon.FwWriter(dh)
real_note = h.note_fw_events
h.note_fw_events = lambda many: (_ for _ in ()).throw(RuntimeError('a line nobody planned for'))
h.set_meta('tails', '{"was": 1}')
dh._fw_writer.submit(h.fw_prepare(facts(lines[0:300])), (h.tails_epoch, '{"now": 2}'))
dh._fw_writer.drain(30)
ok('is handed back to be tried again', len(getattr(dh, '_fw_waiting', None) or ()), 300)
ok('...and where the files had got to is not saved past it',
   json.loads(h.get_meta('tails')), {'was': 1})
ok('...without a precomputed row left on it',
   any('_row' in f for f in dh._fw_waiting), False)
h.note_fw_events = real_note
dh._fw_writer.submit(h.fw_prepare(dh._fw_waiting), (h.tails_epoch, '{"now": 3}'))
dh._fw_waiting = []
dh._fw_writer.drain(30)
ok('the next try writes it, and then the positions',
   (h.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'],
    json.loads(h.get_meta('tails'))), (300, {'now': 3}))
ok('the writer is still there after a failure', dh._fw_writer.thread.is_alive())
h.set_meta('tails', '{}')
old_epoch = h.tails_epoch
h.forget_tails('fwlog')
ok('an erase of positions moves the epoch on', h.tails_epoch > old_epoch)
h.set_meta('tails', '{"after": "erase"}')
dh._fw_writer.submit(isemon.PreparedLot(), (old_epoch, '{"before": "erase"}'))
dh._fw_writer.drain(30)
ok('...so positions taken before it are not saved after it',
   json.loads(h.get_meta('tails')), {'after': 'erase'})
ok('waiting for the writer is for what was handed over before, and returns',
   dh._fw_writer.drain(5))

print('\nA write of the firewall’s own tables on a database server')
g = isemon.Storage(Path(folder) / 'g.db')
w = g.db_write(own=True)
with w:
    pass
if g.dialect.name == 'sqlite':
    ok('on the file it takes the lock every write takes', w.locked)
ok('the firewall’s lines are written so', "with self.db_write(own=True) as db:" in source)
if g.dialect.name != 'sqlite':
    other = []
    g._write.acquire()
    t = threading.Thread(target=lambda: (g.db_write(own=True).__enter__(), other.append(1)))
    t.start()
    t.join(5)
    g._write.release()
    ok('on %s it does not wait for it' % g.dialect.name, other, [1])

print('\nThe reader, while it is behind, and the interpreter')
ok('it comes straight back for more, after a breath', isemon.Daemon.FW_MORE_WAIT_S <= 0.05)
ok('each thread is let in within a millisecond', isemon.Daemon.SWITCH_S <= 0.002)
ok('a transaction adds up twenty thousand lines’ buckets', isemon.Storage.FW_WRITE_LOT,
   20000)
at = source.index("joined = store.dialect.name == 'postgres'")
ok('a record refused inside, on PostgreSQL, is still undone on its own',
   'if raw.get_transaction_status() == 3:' in source[at:at + 3000])
ok('ISE’s savepoints in one round trip on PostgreSQL, and only there',
   "RELEASE SAVEPOINT isemon_take; SAVEPOINT isemon_take" in source[at:at + 6000]
   and "if open_point:\n                        cur.execute('RELEASE SAVEPOINT isemon_take')"
   in source[at:at + 8000])

print('\nThe server’s own cache')
if g.dialect.name == 'sqlite':
    ok('nothing to say on the file', g.server_cache(), None)
ok('the database page says it, where it is too small', 'var cache = d.cache;' in page
   and "if (cache && cache.low)" in page)
if g.dialect.name != 'sqlite':
    said = g.server_cache()
    ok('on %s: how much, against how big' % g.dialect.name,
       set(said or {}) >= {'engine', 'setting', 'cache', 'size', 'low'})

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
