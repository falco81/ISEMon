#!/usr/bin/env python3
"""1.10.175: five thousand lines a second with the page being searched at
the same time - the readers made cheaper, the searches given a limit and a
turn, records kept while the database is away; and the bugs found on the way.

    ./test/fixes175.py
"""
import bisect
import ipaddress
import random
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import zlib
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

folder = tempfile.mkdtemp(prefix='isemon-175-')
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
isemon.CONFIG.update({'api_port': 19950, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
R = random.Random(175)
NOW = time.time()

print('\nFortiGate pairs, read by one expression')


def fg_by_hand(line):
    """What fg_fields gave before, walked a character at a time: a quote
    inside a quoted value written as \\" and read as "."""
    text = line[line.find('date='):]
    out, k = {}, 0
    while k < len(text):
        m = re.match(r'\s*([A-Za-z0-9_]+)=', text[k:])
        if not m:
            break
        k += m.end()
        if k < len(text) and text[k] == '"':
            j, buf = k + 1, ''
            while j < len(text) and text[j] != '"':
                if text[j] == '\\' and j + 1 < len(text):
                    buf += text[j + 1]
                    j += 2
                    continue
                buf += text[j]
                j += 1
            out[m.group(1)] = buf
            k = j + 1
        else:
            j = k
            while j < len(text) and not text[j].isspace():
                j += 1
            out[m.group(1)] = text[k:j]
            k = j
    return out


line = ('Oct  1 07:56:02 fw1 date=2026-10-01 time=07:56:02 devname="FG one" logid="0000000013" '
        'type="traffic" subtype="forward" srcip=10.0.0.1 msg="said \\"no\\" twice" '
        'empty="" dstport=443 app="A=B c"')
got = isemon.fg_fields(line)
want = fg_by_hand(line)
ok('every pair the same as walked by hand',
   {k: v for k, v in got.items() if not k.startswith('_')}, want)
ok('...a quoted value with a space and an equals sign kept whole', got.get('app'), 'A=B c')
ok('...an empty one empty', got.get('empty'), '')

print('\nAn FTD head with two stamps, remembered by the whole head')
isemon._FTD_WHEN.clear()
h1 = 'Oct  1 18:23:54 relay : Oct 01 2026 18:23:50 ftd1 : %FTD-6-302014: '
h2 = 'Oct  1 18:23:54 relay : Oct 01 2026 18:23:52 ftd1 : %FTD-6-302014: '
a, b = isemon.ftd_when(h1), isemon.ftd_when(h2)
ok('two heads with the same relay stamp read as their own moments', round(b - a), 2)
ok('...the same as read without remembering', (a, b),
   (isemon._ftd_when(h1), isemon._ftd_when(h2)))
ok('...and the unit comes with it', isemon.ftd_head(h1)[1], isemon.ftd_host(h1))

print('\nWhat is kept as a row, and what is counted')
event = {'type': 'event', 'verdict': 'info', 'fields': {'_count': '0', 'msgid': '111008'}}
traffic = {'type': 'traffic', 'verdict': 'allow', 'fields': {'_count': '0', 'msgid': '430003'}}
fw_kept = isemon.Storage.fw_kept
ok('the firewall’s own event counted elsewhere is still kept as a line',
   fw_kept(event, False), True)
ok('...a session line counted elsewhere is not kept', fw_kept(traffic, True), False)
ok('...and carries no bytes of its own',
   isemon.fw_carried(dict(traffic, sent=1000000, rcvd=5)), (0, 0, 0))

print('\nISE’s names for refused VPN lines, found by halving')
names = {}
for k in range(3000):
    ip = '45.0.%d.%d' % (k % 3, k % 2)
    names.setdefault(ip, []).append((NOW - R.uniform(0, 3600), 'p%d' % (k % 50)))
for got in names.values():
    got.sort(key=lambda x: x[0])
daemon.fw_vpn_refusal = lambda f: True


def slow(f, ise_names):
    ts, best = float(f['ts']), None
    for at, name in ise_names.get(str(f['srcip']), ()):
        if ts - 120 <= at <= ts + 30 and (best is None or at > best[0]):
            best = (at, name)
    return best[1] if best else None


same = 0
for k in range(500):
    f = {'type': 'event', 'srcip': '45.0.%d.%d' % (k % 4, k % 2),
         'ts': NOW - R.uniform(0, 3800), 'fields': {}}
    daemon.fw_name_from(f, names)
    same += f.get('user') == slow(f, names)
ok('the same name as reading every one, five hundred times over', same, 500)
del daemon.fw_vpn_refusal

print('\nAn address range searched in the database, exactly')
rows = []
for k in range(600):
    rows.append({'ident': 'r-%03d' % k, 'ts': NOW - k, 'type': 'traffic', 'sub': 'forward',
                 'action': 'close', 'verdict': 'deny', 'area': 'session', 'fw': 'f',
                 'srcip': '10.%d.%d.%d' % (k % 3, k % 7, k % 250),
                 'dstip': '192.0.2.%d' % (k % 9), 'dstport': 443, 'proto': 6,
                 'sent': 1, 'rcvd': 1, 'detail': '{}'})
store.note_fw_events(rows)
for net in ('10.1.0.0/16', '10.0.4.0/22', '10.2.3.0/26', '10.0.0.7/32', '10.0.0.0/8'):
    n = ipaddress.ip_network(net)
    clause, args = isemon.fw_range_sql(['srcip'], n)
    found = {r[0] for r in store.db.execute(
        'SELECT ident FROM fw_events WHERE ' + clause, args)}
    want = {r['ident'] for r in rows if ipaddress.ip_address(r['srcip']) in n}
    ok('%s: the rows inside it and no others' % net, found, want)
ok('...wider than /8 left to the reading back', isemon.fw_range_sql(
    ['srcip'], ipaddress.ip_network('10.0.0.0/7')), None)

print('\nA limit on a statement, and the database being away')
with isemon.statement_limit(25):
    ok('a limit is set inside', isemon._STATEMENT_LIMIT.s, 25)
    with isemon.statement_limit(120):
        ok('...a wider one inside that', isemon._STATEMENT_LIMIT.s, 120)
    ok('...and back after it', isemon._STATEMENT_LIMIT.s, 25)
ok('...and none after all of them', getattr(isemon._STATEMENT_LIMIT, 's', 0), 0)
ok('a stopped statement is seen as one',
   isemon.statement_stopped(sqlite3.Error('canceling statement due to statement timeout')))
ok('a database restarting is the database away',
   isemon.db_away(sqlite3.Error('terminating connection due to administrator command')))
ok('...a record refused is not', isemon.db_away(sqlite3.Error('value too long')), False)
ok('...nor anything that is not the database’s', isemon.db_away(ValueError('gone away')),
   False)

daemon.HELD_MOST = 50
daemon.hold_records(list(range(40)), 'away')
daemon.hold_records(list(range(40, 70)), 'away')
held = daemon.take_held()
ok('records held while it is away, the oldest let go past the most', held, list(range(20, 70)))
ok('...handed over once', daemon.take_held(), [])

ok('a connection can carry its limit', '_limit_s' in isemon.Db.__slots__)
if store.dialect.name != 'sqlite':
    print('\nThe limit on a server (%s)' % store.dialect.name)
    store.release()
    with isemon.statement_limit(25):
        store.db.execute('SELECT 1').fetchone()
        conn = store.db
        ok('a statement under a limit sets it on its connection', conn._limit_s, 25)
        store.release()
    ok('...and the connection goes back to the pool without it',
       any(c is conn for c, _ in store._pool) and conn._limit_s, 0)
    store.release()
    conn = store.db
    store.db.execute('SELECT 1').fetchone()
    store.release()
    ok('a clean connection with no limit goes back to the pool too',
       any(c is conn for c, _ in store._pool))
    sleep = 'SELECT pg_sleep(4)' if store.dialect.name == 'postgres' else 'SELECT SLEEP(4)'
    began = time.time()
    stopped = None
    with isemon.statement_limit(1):
        try:
            store.db.execute(sleep).fetchall()
        except sqlite3.Error as e:
            stopped = e
    ok('...a statement past its limit is stopped by the server, and seen as stopped',
       (stopped is not None and isemon.statement_stopped(stopped), time.time() - began < 3.5),
       (True, True))
    store.release()
    with isemon.statement_limit(1):
        store.db.execute('SELECT 1').fetchone()
    try:
        with store.db_write() as db:
            db.execute(sleep.replace('4', '2'))
        written = True
    except sqlite3.Error:
        written = False
    ok('...and a write after it on the same connection works under none', written)
    store.release()

print('\nA lot of refusals: asked once a lot, taken without savepoints')


def failed_lines(ts, ip, user, seq, device='FTD-VPN', host='ise2'):
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) + '.500 +02:00'
    head = ('%s 0229674592 5400 NOTICE Failed-Attempt: Authentication failed, ConfigVersionId=86, '
            'Device IP Address=172.22.0.137, UserName=%s, Protocol=Radius, '
            'NetworkDeviceName=%s, Calling-Station-ID=%s, Tunnel-Client-Endpoint=(tag=0) %s, '
            'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=CORPNET, AcsSessionID=%s/569337134/%d,'
            % (when, user, device, ip, ip, host, seq))
    return ['Sep 23 13:27:47 %s CISE_Failed_Attempts %010d 1 0 %s' % (host, seq, head)]


isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10, 'watch_devices': 'FTD-VPN',
                      'block_ladder': '10, 60, forever', 'judge_max_age_h': 24,
                      'block_bogus_tries': 4, 'block_lots': 12, 'block_mode': 'temporary',
                      'mikrotik1': 0})
isemon.CONFIG.setdefault('blacklist', 1)


def refusals(seed):
    r = random.Random(seed)
    out, ts = [], NOW - 1800
    for k in range(400):
        ts += r.random() * 3
        ip = '198.51.100.%d' % min(30, int(r.paretovariate(1.1)))
        user = r.choice(['admin', 'root', 'user%d' % r.randrange(9), 'test'])
        out.extend(failed_lines(ts, ip, user, 5000 + k))
    return [('ise', rec) for rec in isemon.ise_parse_lines(out)]


def outcome(st):
    return (sorted((r['ip'], r['what']) for r in st.db.execute('SELECT ip, what FROM block_events')),
            sorted((r['ip'], r['until'] is None, int(r['hits'] or 0))
                   for r in st.db.execute('SELECT ip, until, hits FROM blocked')),
            sorted(r['key'] for r in st.db.execute("SELECT key FROM meta WHERE key LIKE 'blocked!_%' "
                                                   "ESCAPE '!'")))


def fresh_pair(name):
    isemon.DB_FILE = Path(folder) / name
    st = isemon.Storage(isemon.DB_FILE)
    return st, isemon.Daemon(st)


items = refusals(175)
one_store, one = fresh_pair('one.db')
for kind, rec in items:                  # a record at a time, nothing held
    one.take_record(kind, rec)
lot_store, lot = fresh_pair('lot.db')
lot.take_records(refusals(175))
print('  (%d ban events, %d bans, %d marks)' % tuple(len(x) for x in outcome(lot_store)))
ok('the same bans, hits and marks as a record at a time', outcome(lot_store),
   outcome(one_store))
ok('...and some were banned and went on trying', (len(outcome(lot_store)[1]) > 0,
                                                  sum(h for _, _, h in outcome(lot_store)[1]) > 0),
   (True, True))

bad_store, bad = fresh_pair('bad.db')
real_add = bad_store.add_failed
refused = {'n': 0}


def add_failed(row):
    if row['session'].endswith('/5010'):
        refused['n'] += 1
        raise sqlite3.IntegrityError('this one is refused')
    return real_add(row)


bad_store.add_failed = add_failed
mixed = refusals(175)[:40]
fw = isemon.FwEvent(NOW, {'ident': 'fw-1', 'ts': NOW, 'srcip': '192.0.2.1', 'type': 'traffic'})
mixed.insert(20, ('fw', fw))
bad._fw_waiting = []
got = bad.take_records(mixed)
ok('one refused record in a lot: the others all taken', got, 39)
ok('...the refused one tried without savepoints, with them, and on its own', refused['n'], 3)
ok('...and a firewall line in the same lot put aside once',
   [f.get('ident') for f in bad._fw_waiting], ['fw-1'])
bad_said = outcome(bad_store)
ref_store, ref = fresh_pair('ref.db')
ref_add = ref_store.add_failed
ref_store.add_failed = lambda row: (_ for _ in ()).throw(sqlite3.IntegrityError('refused')) \
    if row['session'].endswith('/5010') else ref_add(row)
for kind, rec in refusals(175)[:40]:
    try:
        ref.take_record(kind, rec)
    except sqlite3.Error:
        pass
ok('...the bans and hits the same as a record at a time', bad_said, outcome(ref_store))

print('\nThe packed detail')
text = '{"msg": "Teardown TCP connection", "srcintf": "outside", "n": 1}' * 3
packed = store.pack_detail(text)
ok('packed and unpacked is what it was', store.unpack_detail(packed), text)
ok('...from more than one thread’s worth of packing',
   all(store.unpack_detail(store.pack_detail(text + str(k))) == text + str(k)
       for k in range(50)))

print('\nAn address written the IPv6 way')
ok('::ffff:198.51.100.7 is 198.51.100.7', isemon.same_address('::ffff:198.51.100.7'),
   '198.51.100.7')

print('\nThe page')
ok('the router’s user is written as text', page.count('htmlText(') >= 2)
ok('an older answer to the status tick is dropped', 'TICK_SEQ' in page)
ok('a search stopped at its limit is said quietly where nobody asked', 'stoppedError()' in page)
ok('a range ban has a button to let the range in', 'Let the range in' in page)

print('\nThe source')
ok('a search on the page has a limit', 'statement_limit(API_STATEMENT_S if gated' in source)
ok('what is worked out behind the page takes a turn', 'BEHIND_TURNS' in source)
ok('where the files had got to is not saved while records are held',
   'tails=None if holding' in source)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
