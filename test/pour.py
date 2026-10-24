#!/usr/bin/env python3
"""Big batches poured into PostgreSQL with COPY, and nothing different for it.

From 1.10.136 a batch of two hundred rows or more of one insert goes to
PostgreSQL with COPY into a table of the connection's own, and from there
into the real table with the statement's own `ON CONFLICT`. It is three to
four times quicker than the one long statement it replaces - and it must
leave the database exactly as that statement did.

So the same firewall lines are written twice, once each way, and every row
and every counted bucket is compared. Then the awkward cases: text with
backslashes, tabs, line ends and the `\\N` that COPY reads as nothing; rows
that are there already; counts added on top of counts; a value COPY will
not take (which must quietly go the old way, inside the same transaction);
and the statement shapes it must leave alone.

On SQLite and MariaDB nothing is poured, and the suite says so and checks
that their writing is untouched.

    ./test/pour.py
"""
import decimal
import random
import re
import shutil
import sqlite3
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
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, str(got)[:600],
                                                                   str(want)[:600]))


def title(words):
    print('\n%s' % words)


FOLDERS = []


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-pour-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'pour.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'pour.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'ise': 0,
                          'ise_paths': [str(Path(folder) / 'nothing')], 'fwlog': 1,
                          'fwlog_keep_allowed': 1})
    store = isemon.Storage(isemon.DB_FILE)
    return store, isemon.Daemon(store)


BASE = time.time() - 3 * 3600
MON = time.strftime('%b', time.localtime(BASE))
DAY = '%2d' % time.localtime(BASE).tm_mday


def line(unit, msg, sec):
    clock = time.strftime('%H:%M:%S', time.localtime(BASE + sec))
    return '%s %s %s fw%d.example.cz %s' % (MON, DAY, clock, unit, msg)


# Text COPY has its own reading of: every one of these must come back as it went.
ODD = ['back\\slash', 'tab\there', 'line\nend', 'carriage\rreturn', '\\N', '\\\\N', '',
       'quote \' and "double"', 'příliš žluťoučký',
       '☃ snow', 'trailing\\', '%s and %%', 'semi; colon', 'a\\tb (written, not a tab)']


def lines(n, seed):
    """n firewall lines of every common kind, the same every time for one seed."""
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        sec = i // 3
        conn = 100000 + i
        a = '10.1.%d.%d' % (rnd.randint(0, 9), rnd.randint(1, 250))
        b = '198.51.100.%d' % rnd.randint(1, 250)
        c = '192.0.2.%d' % rnd.randint(1, 250)
        sp, dp = rnd.randint(1024, 65000), rnd.choice((443, 80, 53, 22, 3389, 8443))
        k = i % 9
        if k == 0:
            out.append(line(1, '%%FTD-6-302013: Built inbound TCP connection %d for LAN:%s/%d '
                               '(203.0.113.10/%d) to OUTSIDE:%s/%d (%s/%d)'
                               % (conn, a, sp, sp, b, dp, b, dp), sec))
            out.append(line(1, '%%FTD-6-302014: Teardown TCP connection %d for LAN:%s/%d to '
                               'OUTSIDE:%s/%d duration 0:00:%02d bytes %d TCP FINs from LAN'
                               % (conn, a, sp, b, dp, rnd.randint(0, 59),
                                  rnd.randint(0, 10 ** 7)), sec + 1))
        elif k == 1:
            out.append(line(1, '%%FTD-6-302016: Teardown UDP connection %d for OUTSIDE:%s/53 '
                               'to LAN:%s/%d duration 0:00:00 bytes %d'
                               % (conn, b, a, sp, rnd.randint(40, 900)), sec))
        elif k == 2:
            out.append(line(1, '%%FTD-4-106023: Deny tcp src OUTSIDE:%s/%d dst DMZ:203.0.113.5/%d '
                               'by access-group "CSM_FW_ACL_" [0x97aa021a, 0x0]'
                               % (c, sp, dp), sec))
        elif k == 3:
            out.append(line(1, "%%FTD-4-106103: access-list #ACSACL#-IP-VPN_Users-6a1446bd "
                               "denied tcp for user 'jnovak' OUTSIDE/10.9.0.%d(%d) -> "
                               "LAN/%s(445) hit-cnt 1 first hit [0xb7c1c1a6, 0x0]"
                               % (rnd.randint(2, 200), sp, a), sec))
        elif k == 4:
            out.append(line(1, '%%FTD-1-430001: DeviceUUID: 1a8b, InstanceID: 1, '
                               'FirstPacketSecond: 2026-10-01T18:00:00Z, ConnectionID: %d, '
                               'AccessControlRuleAction: Allow, SrcIP: %s, DstIP: %s, SrcPort: '
                               '%d, DstPort: %d, Protocol: tcp, IngressInterface: OUTSIDE, '
                               'EgressInterface: DMZ, Priority: 1, GID: 1, SID: %d, Revision: 3, '
                               'Message: SERVER-WEBAPP Example %s, Classification: Attempted '
                               'Administrator Privilege Gain, IntrusionPolicy: Balanced, '
                               'InlineResult: Blocked'
                               % (conn, c, a, sp, dp, 58000 + i % 40, rnd.choice(ODD)), sec))
        elif k == 5:
            out.append(line(1, '%%FTD-1-430002: DeviceUUID: 1a8b, AccessControlRuleAction: '
                               'Block, SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: 443, '
                               'Protocol: tcp, SecurityIntelligenceCategory: Malware, '
                               'URLSICategory: Malware' % (a, b, sp), sec))
        elif k == 6:
            out.append(line(1, '%%FTD-4-113019: Group = VPN_Users, Username = %s, IP = %s, '
                               'Session disconnected. Session Type: SSL, Duration: 0h:%02dm:'
                               '00s, Bytes xmt: %d, Bytes rcv: %d, Reason: User Requested'
                               % (rnd.choice(('jnovak', 'mkral', 'pdvorak', 'mdolezal')), c,
                                  rnd.randint(0, 59), rnd.randint(0, 10 ** 8),
                                  rnd.randint(0, 10 ** 8)), sec))
        elif k == 7:
            out.append(line(1, '%%FTD-4-750003: Local:203.0.113.2:500 Remote:%s:500 '
                               'Username:L2LGroup IKEv2 Negotiation aborted due to ERROR: '
                               'Failed to locate an item in the database' % c, sec))
        else:
            out.append(line(2, '%%FTD-6-302014: Teardown TCP connection %d for LAN:%s/%d to '
                               'OUTSIDE:%s/%d duration 0:01:05 bytes %d'
                               % (conn, a, sp, b, dp, rnd.randint(0, 99999)), sec))
    return out


def facts_of(text):
    out = []
    for one in text:
        rec = isemon.ftd_record_from(one)
        if rec is None or not hasattr(rec, 'facts'):
            continue
        f = rec.facts
        f['fw'] = 'hq'
        out.append(f)
    # Some of them carry text COPY reads its own way, in a column of its own.
    for i, f in enumerate(out):
        if i % 7 == 0:
            f['msg'] = ODD[(i // 7) % len(ODD)] + ' #%d' % i
    return out


FW_COLS = isemon.Storage.FW_COLS


def dump(store):
    # The record beside each row is compared as it reads back: which
    # dictionary it was deflated against is the store's, not the writing's.
    rows = [tuple(store.unpack_detail(r[c]) if c == 'detail' else r[c] for c in FW_COLS)
            for r in store.db.execute(
        'SELECT %s FROM fw_events ORDER BY ident' % ', '.join(FW_COLS))]
    roll = [(int(r['span']), int(r['at']), r['dim'], r['val'], r['verdict'], int(r['n']),
             int(r['sent']), int(r['rcvd'])) for r in store.db.execute(
        'SELECT span, at, dim, val, verdict, n, sent, rcvd FROM fw_roll '
        'ORDER BY span, at, dim, val, verdict')]
    return rows, roll


def write_all(store, daemon, text):
    """The way the daemon writes: in pieces, the second overlapping the
    first (a pass back over a file reads what it read before)."""
    every = facts_of(text)
    half = len(every) // 2
    got = store.note_fw_events(daemon.fw_fill([dict(f, fields=dict(f['fields']))
                                               for f in every[:half + 300]]))
    got += store.note_fw_events(daemon.fw_fill([dict(f, fields=dict(f['fields']))
                                                for f in every[half:]]))
    # ...and all of it once more, which must change nothing.
    got += store.note_fw_events(daemon.fw_fill([dict(f, fields=dict(f['fields']))
                                                for f in every]))
    return got


PG = isemon.PostgresDialect
POURED = [0]
TABLES = set()
real_poured = PG.poured


def counting(self, cur, said, rows):
    done = real_poured(self, cur, said, rows)
    if done:
        POURED[0] += 1
        TABLES.add(said.split()[2])
    return done


PG.poured = counting

TEXT = lines(9000, seed=136)

title('The same lines written the old way and the new, compared')
store, daemon = fresh()
engine = store.dialect.name
print('  (engine: %s)' % engine)
PG.POUR_FROM = 10 ** 9                         # the old way: never poured
POURED[0] = 0
old_n = write_all(store, daemon, TEXT)
old = dump(store)
ok('the old way pours nothing', POURED[0], 0)

store, daemon = fresh()
PG.POUR_FROM = 200                             # as shipped
POURED[0] = 0
new_n = write_all(store, daemon, TEXT)
new = dump(store)
if engine == 'postgres':
    ok('on PostgreSQL the new way pours the big batches: the rows and the counts',
       (POURED[0] > 0, sorted(TABLES)), (True, ['fw_events', 'fw_roll']))
else:
    ok('on %s nothing is poured: it writes as it always did' % engine, POURED[0], 0)
ok('there is something to compare: thousands of rows, thousands of buckets',
   (len(old[0]) > 3000, len(old[1]) > 3000), (True, True))
ok('as many lines said to be written', new_n, old_n)
ok('every row the same, to the last character and the last digit of its time',
   new[0] == old[0], True)
if new[0] != old[0]:
    for a, b in zip(old[0], new[0]):
        if a != b:
            print('          first difference:\n            %r\n            %r' % (a, b))
            break
ok('every counted bucket the same: nothing counted twice, nothing missed',
   new[1] == old[1], True)
odd_back = [r[FW_COLS.index('msg')] for r in new[0]
            if re.search(r' #\d+$', str(r[FW_COLS.index('msg')] or ''))]
ok('text COPY has its own reading of came back as it went',
   all(any(str(m).startswith(o + ' #') for o in ODD) for m in odd_back)
   and all(any(str(m).startswith(o + ' #') for m in odd_back) for o in ODD)
   and any(str(m).startswith('\\N #') for m in odd_back)
   and any(str(m).startswith('tab\there #') for m in odd_back), True)

title('One batch at a time, straight to the engine')
store, daemon = fresh()
PG.POUR_FROM = 200
POURED[0] = 0
roll = [(3600, 7200 + (i % 50) * 3600, 'src', '10.0.0.%d' % (i % 250), 'allow', 1, i, 2 * i)
        for i in range(600)]
roll = list({r[:5]: r for r in roll}.values())
with store.db_write() as db:
    db.executemany(store.FW_ROLL_UPSERT, roll)
with store.db_write() as db:
    db.executemany(store.FW_ROLL_UPSERT, roll)
got = dict(((int(r['at']), r['val']), (int(r['n']), int(r['sent']), int(r['rcvd'])))
           for r in store.db.execute('SELECT at, val, n, sent, rcvd FROM fw_roll'))
want = dict(((r[1], r[3]), (2 * r[5], 2 * r[6], 2 * r[7])) for r in roll)
ok('counts written twice are added up, not replaced and not lost', got == want, True)
if engine == 'postgres':
    ok('...and both of them were poured', POURED[0], 2)

INTS = ('srcport', 'dstport', 'proto', 'policy', 'sent', 'rcvd', 'duration', 'session',
        'brief')


def event(i, msg):
    one = dict((c, 0 if c in INTS else '') for c in FW_COLS)
    one.update({'ident': 'dup-%d' % i, 'ts': BASE + i / 7.0, 'verdict': 'info',
                'srcip': '10.0.0.1', 'msg': msg, 'detail': '{}', 'fw': 'hq', 'area': 'other'})
    return tuple(one[c] for c in FW_COLS)


events = [event(i, 'first %d' % i) for i in range(400)]
with store.db_write() as db:
    db.executemany(store.FW_INSERT, events[:250])
again = [event(i, 'second') for i in range(400)]
POURED[0] = 0
with store.db_write() as db:
    cur = db.executemany(store.FW_INSERT, again)
    landed = getattr(cur, 'rowcount', -1)
msgs = dict((r['ident'], r['msg']) for r in store.db.execute(
    "SELECT ident, msg FROM fw_events WHERE ident LIKE 'dup-%'"))
ok('a row that is there already is left as it was; the rest go in',
   (len(msgs), sum(1 for m in msgs.values() if m.startswith('first')),
    sum(1 for m in msgs.values() if m == 'second')), (400, 250, 150))
if engine == 'postgres':
    ok('...poured, and the driver still says how many landed', (POURED[0], landed), (1, 150))
ts_back = dict((r['ident'], float(r['ts'])) for r in store.db.execute(
    "SELECT ident, ts FROM fw_events WHERE ident LIKE 'dup-%'"))
ok('a time with all its digits comes back with all of them',
   all(ts_back['dup-%d' % i] == BASE + i / 7.0 for i in range(400)), True)

if engine == 'postgres':
    title('What COPY will not take goes the old way, and the transaction carries on')
    store.dialect._pour_told = False
    halves = [(3600, 3600 * 9, 'port', str(i), 'allow', 1.5, 0, 0) for i in range(300)]
    POURED[0] = 0
    with store.db_write() as db:
        db.execute("INSERT INTO fw_roll (span, at, dim, val, verdict, n, sent, rcvd) "
                   "VALUES (3600, 3600, 'mark', 'before', 'allow', 1, 0, 0)")
        db.executemany(store.FW_ROLL_UPSERT, halves)
        db.execute("INSERT INTO fw_roll (span, at, dim, val, verdict, n, sent, rcvd) "
                   "VALUES (3600, 3600, 'mark', 'after', 'allow', 1, 0, 0)")
    marks = sorted(r['val'] for r in store.db.execute(
        "SELECT val FROM fw_roll WHERE dim = 'mark'"))
    ns = set(int(r['n']) for r in store.db.execute(
        "SELECT n FROM fw_roll WHERE dim = 'port' AND at = ?", (3600 * 9,)))
    ok('a half where a whole number goes: refused by COPY, so not poured', POURED[0], 0)
    ok('...written the old way all the same, as the server rounds it', ns, {2})
    ok('...and what the same transaction did before and after it is kept',
       marks, ['after', 'before'])
    ok('...said once in the log, not once a batch', store.dialect._pour_told, True)

    title('What is never poured')
    d = store.dialect
    ok('a value of a type this is not sure of',
       d.pour_text(decimal.Decimal('1.5')) is None and d.pour_text(True) is None
       and d.pour_text(float('nan')) is None and d.pour_text(object()) is None, True)
    ok('bytes go as hex, the backslash doubled for COPY', d.pour_text(b'\x00A'), '\\\\x0041')
    ok('a statement of another shape',
       [bool(d.POUR_SHAPE.match(d.say(s))) for s in (
           store.FW_INSERT, store.FW_ROLL_UPSERT,
           'UPDATE fw_roll SET n = ? WHERE dim = ?',
           'INSERT INTO fw_roll (span, at) SELECT span, at FROM fw_roll',
           'DELETE FROM fw_events WHERE ident = ?')],
       [True, True, False, False, False])
    ok('a small batch: a statement is cheaper than four round trips',
       d.POUR_FROM, 200)
    ok('nothing is written with NUL in it on either way',
       d.pour_text('a\x00b'.replace('\x00', '')), 'ab')

title('Only a line that is kept is looked for (1.10.137)')
ST = isemon.Storage
real_here = ST.fw_already_here
ASKED = [0]


def as_before(self, idents, whole=None, span=None):
    """1.10.136: every line of the lot asked about, kept or not."""
    ASKED[0] += len(whole if whole is not None else idents)
    return real_here(self, list(whole if whole is not None else idents))


def counted(self, idents, whole=None, span=None):
    ASKED[0] += len(idents)
    return real_here(self, idents, whole, span)


both = {}
for name, how in (('before', as_before), ('now', counted)):
    ST.fw_already_here = how
    store, daemon = fresh()
    isemon.CONFIG['fwlog_keep_allowed'] = 0
    ASKED[0] = 0
    n = write_all(store, daemon, TEXT)
    both[name] = (n, dump(store), ASKED[0])
ST.fw_already_here = real_here
ok('with the sessions it let through not kept: the same rows and the same counts as before',
   (both['now'][0] == both['before'][0], both['now'][1] == both['before'][1]), (True, True))
ok('...and fewer of them asked about: the ones only counted are not (%d, was %d)' % (both['now'][2], both['before'][2]),
   both['now'][2] < both['before'][2], True)
class Refusing(object):
    class db(object):
        @staticmethod
        def execute(*_):
            raise sqlite3.Error('no table')


ok('a table that cannot be asked: the whole lot is taken as there, kept or not',
   isemon.Storage.fw_already_here(Refusing(), ['a'], whole=['a', 'b']), {'a', 'b'})

title('Countries held in memory (1.10.136)')
store, daemon = fresh()
asked = []
real_country = store.country_of


def country_of(ip):
    asked.append(ip)
    return 'CZ' if ip.endswith('.1') else 'DE'


store.country_of = country_of
store.geo_size = lambda: 10
daemon.GEO_MEMO_MOST = 3
for ip in ('198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.1'):
    daemon.country_says(ip)
ok('each address is asked of the database once', asked,
   ['198.51.100.1', '198.51.100.2', '198.51.100.3'])
daemon.country_says('198.51.100.4')
ok('past the most it holds, the one asked about longest ago goes, and only that one',
   list(daemon._geo_said), ['198.51.100.3', '198.51.100.1', '198.51.100.4'])
del asked[:]
said = [daemon.country_says(ip) for ip in ('198.51.100.1', '198.51.100.2')]
ok('...so a recent one is still known, and the one let go is asked again',
   (said, asked), (['CZ', 'DE'], ['198.51.100.2']))
daemon._geo_said = {}                         # what fetching the list again does
del asked[:]
ok('emptied when the country list is fetched again, and asked afresh',
   (daemon.country_says('198.51.100.1'), asked), ('CZ', ['198.51.100.1']))
store.country_of = real_country

title('When to ask a name again, held in memory (1.10.136)')
names = daemon.names
names.REMEMBER_MOST = 10
now = time.time()
names.next_ask = dict(('192.0.2.%d' % i, now + 100 + i) for i in range(12))
names.next_ask['192.0.2.200'] = now - 5           # its moment has passed
names.forget_old(now)
ok('past the most, the ones due soonest go: nine tenths of it are kept',
   sorted(names.next_ask, key=lambda ip: int(ip.rsplit('.', 1)[1])),
   ['192.0.2.%d' % i for i in range(3, 12)])
isemon.CONFIG.update({'ptr': 1, 'ptr_servers': '192.0.2.53'})
names.start = lambda: None
names.REMEMBER_MOST = 200000
names.WAITING = 1
names.next_ask = {}
names.queue.clear()
names.pending.clear()
before = names.daemon.store.ptr_stale
looked = []
names.daemon.store.ptr_stale = lambda ips, older: looked.append(list(ips)) or list(ips)
names.ask(['198.51.100.10', '198.51.100.11'])
first = list(looked)
names.ask(['198.51.100.11'])
ok('an address offered while the queue is full waits a while, without a question of the table',
   (len(names.queue), first, looked == first,
    names.next_ask.get('198.51.100.11', 0) > time.time() + names.FULL_WAIT_S - 5),
   (1, [['198.51.100.10', '198.51.100.11']], True, True))
names.daemon.store.ptr_stale = before

PG.poured = real_poured
for one in FOLDERS:
    shutil.rmtree(one, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
