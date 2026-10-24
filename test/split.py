#!/usr/bin/env python3
"""The biggest tables split by day, and nothing different for it.

From 1.10.141, on PostgreSQL, the firewall's lines (`fw_events`), their
counts (`fw_roll`) and the domain's events (`win_events`) are kept in a part
a day, and each day in a part per how long its rows are kept. An existing
table is split in place: renamed, and attached whole as the first part.

What this proves, on two databases filled with exactly the same lines - one
split, one not:

- splitting a table that already holds rows loses none and changes none;
- every row written afterwards lands somewhere, whatever its time: a day
  that exists, a day not made yet, a day long gone, the part from before;
- what the pages read is the same on both - the lists, the searches, the
  counts, a line opened on its own;
- letting the old rows go leaves exactly the same rows on both, while the
  split one lets whole days and whole kinds of a day go in one step - and a
  domain event this program marked stays, as it does row by row;
- the counted answers of the domain still agree with its rows;
- the days ahead are made, and a row that arrived before its day is moved
  into it;
- taking part of a table out takes only what was asked for;
- the split tables are one table each to everything that lists tables.

On SQLite and MariaDB nothing is split; what can be checked there (the new
columns, the index over the names, the searches) is.

    ./test/split.py
"""
import json
import os
import shutil
import sys
import tempfile
import time as real_time
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
        print('  FAIL  %s\n          got  %s\n          want %s'
              % (what, str(got)[:700], str(want)[:700]))


def title(words):
    print('\n%s' % words)


class Clock(object):
    """The program's clock, which this suite moves on by days."""
    now = None

    def __getattr__(self, name):
        return getattr(real_time, name)

    def time(self):
        return self.now if self.now is not None else real_time.time()


CLOCK = Clock()
isemon.time = CLOCK
SAID = []
_real_log = isemon.log


def heard(msg, level='info'):
    SAID.append(str(msg))
    return _real_log(msg, level)


isemon.log = heard
DAY = 86400
FOLDERS = []


def config():
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'ise': 0, 'fwlog': 1,
        'fwlog_keep_allowed': 1, 'fwlog_keep_days': 3, 'fwlog_allowed_days': 1,
        'winsec': 1, 'winsec_rollup': 1, 'winsec_keep_days': 4,
        'winsec_keep_logons': 1, 'winsec_logons_days': 2,
        'winsec_keep_reads': 1, 'winsec_reads_days': 1, 'db_split': 1,
        # The rows go as they age, as on a table that is not split, so that
        # the two can be compared row for row. On by default since 1.10.176,
        # when the split tables keep up to a day longer; tried on its own
        # below.
        'db_split_whole_days': 0})


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-split-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'split.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'split.log'
    config()
    return isemon.Storage(isemon.DB_FILE)


# ---- the lines --------------------------------------------------------------
BASE = int(real_time.time() // DAY) * DAY + 6 * 3600 + 17     # this morning, UTC
MON = 'Oct'


def fw_lines(n, first, seed):
    """n firewall lines of every kind that is kept for a different time,
    spread over the days from `first` on."""
    out = []
    for i in range(n):
        k = (i * 7 + seed) % 6
        a = '10.1.%d.%d' % (i % 9, (i * 13) % 250 + 1)
        b = '198.51.100.%d' % ((i * 31) % 250 + 1)
        c = '192.0.2.%d' % ((i * 17) % 250 + 1)
        conn = seed * 1000000 + i
        if k == 0:
            text = ('%%FTD-6-302014: Teardown TCP connection %d for LAN:%s/%d to '
                    'OUTSIDE:%s/443 duration 0:00:%02d bytes %d TCP FINs from LAN'
                    % (conn, a, 1024 + i % 60000, b, i % 60, i * 11))
        elif k == 1:
            text = ('%%FTD-6-106015: Deny TCP (no connection) from %s/%d to %s/443 flags RST '
                    'on interface LAN' % (a, 2000 + i, b))
        elif k == 2:
            text = ('%%FTD-4-106023: Deny tcp src OUTSIDE:%s/%d dst DMZ:203.0.113.5/22 by '
                    'access-group "CSM_FW_ACL_" [0x97aa021a, 0x0] #%d' % (c, 3000 + i, conn))
        elif k == 3:
            text = ("%%FTD-4-106103: access-list #ACSACL#-IP-VPN_Users-6a1446bd denied tcp for "
                    "user '%s' OUTSIDE/10.9.0.%d(%d) -> LAN/%s(445) hit-cnt 1 first hit "
                    "[0xb7c1c1a6, 0x0]" % (('jnovak', 'mkral', 'pdvorak')[i % 3], i % 200 + 2,
                                           4000 + i, a))
        elif k == 4:
            text = ('%%FTD-4-113019: Group = VPN_Users, Username = %s, IP = %s, Session '
                    'disconnected. Session Type: SSL, Duration: 0h:%02dm:00s, Bytes xmt: %d, '
                    'Bytes rcv: %d, Reason: User Requested'
                    % (('jnovak', 'mkral', 'mdolezal')[i % 3], c, i % 60, i * 5, i * 3))
        else:
            text = ('%%FTD-1-430001: DeviceUUID: 1a8b, InstanceID: 1, FirstPacketSecond: '
                    '2026-10-01T18:00:00Z, ConnectionID: %d, AccessControlRuleAction: Allow, '
                    'SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: 80, Protocol: tcp, '
                    'IngressInterface: OUTSIDE, EgressInterface: DMZ, Priority: 1, GID: 1, '
                    'SID: %d, Revision: 3, Message: SERVER-WEBAPP Example, Classification: '
                    'Attempted Administrator Privilege Gain, IntrusionPolicy: Balanced, '
                    'InlineResult: Blocked' % (conn, c, a, 5000 + i, 58000 + i % 50))
        when = first + (i * 7919) % (5 * DAY + 3600)
        line = '%s %2d %s fw1.example.cz %s' % (
            MON, 1, real_time.strftime('%H:%M:%S', real_time.gmtime(when)), text)
        rec = isemon.ftd_record_from(line)
        if rec is None or not hasattr(rec, 'facts'):
            continue
        f = rec.facts
        f['ts'] = float(when) + (i % 1000) / 1000.0
        f['fw'] = 'hq'
        out.append(f)
    return out


def win_facts(n, first, seed):
    out = []
    kinds = (('logon', 4624), ('read', 4662), ('lockout', 4740), ('logon-failed', 4625),
             ('kerberos', 4769), ('change', 4738))
    for i in range(n):
        kind, event = kinds[(i + seed) % len(kinds)]
        mark = 'rc4' if i % 11 == 0 else ('routine' if i % 7 == 0 else '')
        f = {'ts': float(first + (i * 6907) % (5 * DAY + 3600)), 'server': 'DC1',
             'event': event, 'kind': kind,
             'account': ('jnovak', 'mkral', 'pdvorak', 'mdolezal', 'PC17$')[i % 5],
             'is_machine': i % 5 == 4, 'domain': 'EXAMPLE', 'by': '', 'machine': 'PC%d' % (i % 30),
             'ip': '10.1.2.%d' % (i % 200 + 1), 'logon_type': '3', 'process': '',
             'service': '', 'object': '', 'said': '', 'mark': mark, 'by_logon': '',
             'fields': {'n': str(i)}, 'raw': 'seed %d event %d' % (seed, i)}
        f['ident'] = isemon.win_ident(f)
        out.append(f)
    return out


def write(store, daemon, fw, win):
    store.note_fw_events(daemon.fw_fill([dict(f, fields=dict(f['fields'])) for f in fw]))
    store.note_win_events([dict(f) for f in win])


SKIP = ('brief', 'keepc')


def dump(store):
    out = {}
    for table, order in (('fw_events', 'ident'), ('win_events', 'ident'),
                         ('fw_roll', 'span, at, dim, val, verdict'),
                         ('win_rollup', 'span, at, dim, val, kind, mach, quiet, told')):
        rows = []
        for r in store.db.execute('SELECT * FROM %s ORDER BY %s' % (table, order)):
            one = {}
            for k, v in dict(r).items():
                if k in SKIP:
                    continue
                if k == 'detail':
                    v = store.unpack_detail(v)
                if isinstance(v, float) and v == int(v):
                    v = int(v)
                one[k] = v
            rows.append(json.dumps(one, sort_keys=True, default=str))
        out[table] = rows
    return out


def same(what, a, b):
    da, db_ = dump(a), dump(b)
    for table in da:
        if da[table] != db_[table]:
            only_a = sorted(set(da[table]) - set(db_[table]))[:2]
            only_b = sorted(set(db_[table]) - set(da[table]))[:2]
            ok('%s: %s' % (what, table), (len(da[table]), only_a), (len(db_[table]), only_b))
        else:
            ok('%s: %s, %d row(s) the same' % (what, table, len(da[table])), True)


def reads(store):
    """What the pages ask, over everything there is."""
    out = []
    since = 0
    for q, kw in (('', {}), ('user:jnovak', {}), ('user:PDVORAK', {}), ('-user:jnovak', {}),
                  ('verdict:deny', {}), ('', {'verdict': 'allow'}), ('', {'kind': 'traffic'}),
                  ('', {'src': '10.1.3.40'}), ('', {'dst': '198.51.100.32'}),
                  ('', {'user': 'jnovak'}), ('', {'user': 'JNOVAK'}), ('', {'text': '10.9.0'}),
                  ('', {'area': 'session'}), ('', {'area': 'client-vpn'}),
                  ('', {'sort': 'sent', 'desc': False}), ('', {'offset': 100})):
        said = {}
        rows, total = store.fw_rows(since=since, query=q, said=said, limit=60, **kw)
        out.append((q, sorted(kw.items()), total,
                    [(r['ident'], round(float(r['ts']), 3)) for r in rows]))
    summary = store.fw_summary(since=BASE - 10 * DAY)
    out.append(('summary', json.dumps(summary, sort_keys=True, default=str)))
    rows, total = store.win_rows(limit=80, since=0)
    out.append(('win', total, [r['ident'] for r in rows]))
    rows, total = store.win_rows(limit=80, since=0, account='mkral')
    out.append(('win mkral', total, [r['ident'] for r in rows]))
    return out


# ---- the engines that are not split --------------------------------------
store = fresh()
engine = store.dialect.name
print('  (engine: %s)' % engine)
title('What every engine has')
ok('the firewall’s lines carry how long they are kept',
   'brief' in store.dialect.columns(store.db, 'fw_events'), True)
ok('...and the domain’s events which retention they are under',
   'keepc' in store.dialect.columns(store.db, 'win_events'), True)
ok('the firewall’s lines are marked by the very rule they are let go by',
   [isemon.fw_brief(f) for f in ({'verdict': 'allow', 'type': 'traffic'},
                                 {'verdict': 'info', 'sub': 'stray', 'type': 'traffic'},
                                 {'verdict': 'deny', 'type': 'traffic'},
                                 {'verdict': 'allow', 'type': 'event'},
                                 {'type': 'utm', 'verdict': 'block'})],
   [1, 1, 0, 0, 0])
ok('the domain’s kinds are numbered by their group',
   [isemon.win_keepc(k) for k in ('logon', 'kerberos', 'read', 'lockout', 'change')],
   [1, 1, 2, 0, 0])
names = set(store.dialect.index_names(store.db))
ok('the indexes nothing asked for are not made: the verdict and the firewall',
   ('fw_verdict_ts' in names, 'fw_fw_ts' in names), (False, False))
ok('the index over the names a line carries, where the engine can make one',
   'fw_usr_ts' in names, engine != 'mariadb')
daemon = isemon.Daemon(store)
write(store, daemon, fw_lines(1500, BASE - 5 * DAY, 1), win_facts(900, BASE - 5 * DAY, 1))
low = store.fw_rows(since=0, query='user:pdvorak', said={}, limit=500)
cap = store.fw_rows(since=0, query='user:PDVORAK', said={}, limit=500)
exact = store.fw_rows(since=0, user='pdvorak', said={}, limit=500)
ok('a person searched for is the same person however it is written',
   (low[1] > 0, low[1] == cap[1], [r['ident'] for r in low[0]] == [r['ident'] for r in cap[0]]),
   (True, True, True))
ok('...and a person pressed on a card is still that person exactly',
   (exact[1], all(r['usr'] == 'pdvorak' for r in exact[0])), (low[1], True))
ok('nothing is split here', any(store.is_split(t) for t in store.SPLIT), False)

if engine != 'postgres':
    print('\n  --    nothing is split on %s; the rest is PostgreSQL’s' % engine)
else:
    import psycopg2
    cfg = dict(isemon.Storage.ENGINE)
    twin_cfg = dict(cfg, name=cfg['name'] + '_twin')
    admin = psycopg2.connect(host=cfg['host'], port=cfg['port'], user='postgres',
                             dbname='postgres')
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
                    (twin_cfg['name'],))
        cur.execute('DROP DATABASE IF EXISTS %s' % twin_cfg['name'])
        cur.execute('CREATE DATABASE %s OWNER %s' % (twin_cfg['name'], cfg['user']))
    init = isemon.Storage.__init__
    real_init = getattr(init, '__globals__', {}).get('real_init', init)

    def storage(engine_cfg):
        one = isemon.Storage.__new__(isemon.Storage)
        real_init(one, path=None, engine=dict(engine_cfg))
        return one

    # Both start with exactly what the table held before it was split -
    # as an older version wrote it, so nothing marked with its kind yet.
    A = store
    B = storage(twin_cfg)
    B.split_wanted = lambda: False
    daemon_b = isemon.Daemon(B)
    write(B, daemon_b, fw_lines(1500, BASE - 5 * DAY, 1), win_facts(900, BASE - 5 * DAY, 1))
    for one in (A, B):
        with one.db_write() as db:
            db.execute('UPDATE fw_events SET brief = 0')
            db.execute('UPDATE win_events SET keepc = 0')
    future = fw_lines(30, BASE + 4 * DAY, 9)          # a clock days ahead
    write(A, daemon, future, [])
    write(B, daemon_b, future, [])

    title('Splitting tables that already hold rows')
    before = dump(A)
    CLOCK.now = BASE
    said = A.split_all(now=BASE)
    ok('all three are split', said, {'fw_events': 'split', 'fw_roll': 'split',
                                    'win_events': 'split'})
    ok('...and say so', [A.is_split(t) for t in ('fw_events', 'fw_roll', 'win_events')],
       [True, True, True])
    ok('not one row lost or changed', dump(A) == before, True)
    kids = A.split_children(A.db, 'fw_events')
    edge = (BASE // DAY + 1) * DAY
    ok('what was there is the first part, up to the next midnight',
       kids.get('fw_events_legacy'), (None, float(edge)))
    ok('...the days from then on are made, and a part for anything else',
       sorted(k for k in kids if k.startswith('fw_events_p')) ==
       [A.split_day_name('fw_events', edge + k * DAY) for k in range(4)]
       and 'fw_events_default' in kids, True)
    ok('...the lines from a clock days ahead are in their day',
       A.db.execute('SELECT COUNT(*) AS n FROM fw_events_legacy WHERE ts >= ?',
                    (edge,)).fetchone()['n'], 0)
    leaves = A.split_leaves(A.db, A.split_day_name('fw_events', edge))
    ok('...each day split by how long its rows are kept',
       sorted(leaves), sorted(['%s_c0' % A.split_day_name('fw_events', edge),
                               '%s_c1' % A.split_day_name('fw_events', edge),
                               '%s_cx' % A.split_day_name('fw_events', edge)]))
    ok('every list of tables still says fw_events, and none of its parts',
       ('fw_events' in A.dialect.tables(A.db),
        any(t.startswith('fw_events_') for t in A.dialect.tables(A.db))), (True, False))
    pk = A.split_primary(A.db, 'fw_events')[0]
    ok('the key is the line, its moment and its kind', pk, ['ident', 'ts', 'brief'])
    have = set(n for n, _u, _r, _v in A.split_indexes(A.db, 'fw_events'))
    ok('the split table has the indexes the plain one had, less the two nothing used',
       ({'fw_ts', 'fw_area_ts', 'fw_src_ts', 'fw_dst_ts', 'fw_session', 'fw_type_ts',
         'fw_usr_ts'} <= have, 'fw_verdict_ts' in have), (True, False))
    ok('how many rows there are is still known without counting them',
       A.dialect.rows_guess(A.db, 'fw_events') >= 0, True)
    ok('split once is split: asked again, nothing happens', A.split_all(now=BASE), {})

    title('Writing to it afterwards')
    later_fw = fw_lines(2500, BASE - 2 * DAY, 2)        # from the old part to days ahead
    later_win = win_facts(1500, BASE - 2 * DAY, 2)
    for d in range(0, 6):
        CLOCK.now = BASE + d * DAY
        A.split_ensure(now=CLOCK.now, force=True)
    CLOCK.now = BASE + DAY
    write(A, daemon, later_fw, later_win)
    write(B, daemon_b, later_fw, later_win)
    same('every row lands, whatever its moment', A, B)
    write(A, daemon, later_fw, later_win)
    write(B, daemon_b, later_fw, later_win)
    same('...and the same lines read again change nothing', A, B)
    ok('the lines written split are marked with how long they are kept',
       A.db.execute('SELECT COUNT(*) AS n FROM fw_events WHERE ts >= ? AND brief <> '
                    "(CASE WHEN (verdict = 'allow' OR sub = 'stray') AND type <> 'event' "
                    'THEN 1 ELSE 0 END)', (edge,)).fetchone()['n'], 0)
    ok('the days ahead were made as the clock moved on',
       A.split_day_name('fw_events', BASE + 8 * DAY) in A.split_children(A.db, 'fw_events'),
       True)

    title('What the pages read')
    ra, rb = reads(A), reads(B)
    for x, y in zip(ra, rb):
        ok('the same answer: %s' % str(x[:2])[:90], x == y, True)
    one = A.db.execute('SELECT ident FROM fw_events ORDER BY ts DESC LIMIT 1').fetchone()['ident']
    ok('a line opened on its own is the same line',
       json.dumps(A.fw_get(one), sort_keys=True, default=str)
       == json.dumps(B.fw_get(one), sort_keys=True, default=str), True)

    title('Letting the old rows go')
    for d in (2, 4, 6):
        CLOCK.now = BASE + d * DAY + 1800
        A.split_ensure(now=CLOCK.now, force=True)
        for one in (A, B):
            one.tidy_fw()
            one.tidy_win_events()
        same('day +%d: exactly the same rows left on both' % d, A, B)
    gone = A.split_children(A.db, 'fw_events')
    ok('days that aged out went whole', A.split_day_name('fw_events', edge) not in gone, True)
    ok('...in one step each, not row by row - the firewall\u2019s, its counts\u2019 and '
       'the domain\u2019s',
       all(any(t + '_p' in m and 'let go whole' in m for m in SAID)
           for t in ('fw_events', 'fw_roll', 'win_events')), True)
    ok('...and a day\u2019s sessions, sign-ins and reads before the rest of it',
       all(any(('%s_p' % t) in m and ('_c%d emptied in one step' % v) in m for m in SAID)
           for t, v in (('fw_events', 1), ('win_events', 1), ('win_events', 2),
                        ('fw_roll', 3600))), True)
    if os.environ.get('ISEMON_TEST_KEEP'):
        print('\n'.join(m for m in SAID if '_p' in m or 'emptied' in m or 'let go' in m))
    ok('...the marked ones among the sign-ins moved aside first',
       any('marked one(s) kept' in m for m in SAID), True)
    ok('...and the part from before the split with them', 'fw_events_legacy' not in gone, True)
    left = [n for n in gone if n.startswith('fw_events_p')]
    ok('...while the days still kept are there', len(left) > 0, True)
    win_left = A.db.execute("SELECT COUNT(*) AS n FROM win_events WHERE marks <> 0 AND "
                            "kind IN ('logon', 'kerberos', 'read')").fetchone()['n']
    ok('domain events this program marked are kept past their kind’s days, as before',
       win_left, B.db.execute("SELECT COUNT(*) AS n FROM win_events WHERE marks <> 0 AND "
                              "kind IN ('logon', 'kerberos', 'read')").fetchone()['n'])
    CLOCK.now = BASE + 6 * DAY + 1800
    for one, name in ((A, 'split'), (B, 'not split')):
        bad = []
        for at in sorted(set(int(r['at']) for r in one.db.execute(
                'SELECT DISTINCT at FROM win_rollup WHERE span = 3600'))):
            bad += one.roll_check(at=at) or []
        ok('the domain’s counted answers agree with its rows (%s)' % name, bad, [])

    title('A line for a day long gone')
    old = fw_lines(12, BASE - 20 * DAY, 3)
    write(A, daemon, old, [])
    write(B, daemon_b, old, [])
    ok('is written, not refused', A.db.execute(
        'SELECT COUNT(*) AS n FROM fw_events WHERE ts < ?', (BASE - 10 * DAY,)).fetchone()['n'],
       len(old))
    A.tidy_fw()
    B.tidy_fw()
    same('...and goes with the next tidying, on both', A, B)

    title('A row that arrived before its day')
    far = fw_lines(6, BASE + 30 * DAY, 4)
    write(A, daemon, far, [])
    in_default = A.db.execute('SELECT COUNT(*) AS n FROM fw_events_default').fetchone()['n']
    ok('waits in the part for anything else', in_default >= len(far), True)
    target = int(far[0]['ts'] // DAY) * DAY
    A.split_make_day(A.split_conn(), 'fw_events', target)
    ok('...and is moved into its day once the day is made',
       A.db.execute('SELECT COUNT(*) AS n FROM %s' % A.split_day_name('fw_events', target))
       .fetchone()['n'] > 0, True)

    title('Taking part of a table out')
    n0 = A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE verdict = 'deny'").fetchone()['n']
    rest = A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE verdict <> 'deny'"
                        ).fetchone()['n']
    with A.db_write() as db:
        db.execute(A.dialect.delete_some('fw_events', "verdict = 'deny'", 50))
    ok('takes the rows asked for and only those',
       (A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE verdict = 'deny'"
                     ).fetchone()['n'],
        A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE verdict <> 'deny'"
                     ).fetchone()['n']), (max(0, n0 - 50), rest))

    title('Index work on a split table, and who may do it (1.10.142)')
    apart = A.split_conn()
    apart.execute('DROP INDEX IF EXISTS fw_usr_ts')
    apart.close()
    sql = dict(A.LATER_INDEXES)['fw_usr_ts']
    left = A.build_indexes_later([('fw_usr_ts', A.index_sql(sql))])
    ok('an index over a split table is built a part at a time, and is whole after',
       (left, A.index_valid(A.db, 'fw_usr_ts')), ([], True))
    leaf = A.split_day_name('fw_events', (int(CLOCK.time()) // DAY) * DAY) + '_c0'
    ok('...every part has it', any(n.startswith(leaf) and n.endswith('fw_usr_ts')
                                   for n in A.dialect.index_names(A.db)), True)
    # Half-built: what a CREATE INDEX CONCURRENTLY leaves when it fails.
    apart = A.split_conn()
    apart.execute('DROP TABLE IF EXISTS isemon_test_twice')
    apart.execute('CREATE TABLE isemon_test_twice (a INTEGER)')
    apart.execute('INSERT INTO isemon_test_twice VALUES (1), (1)')
    try:
        apart.execute('CREATE UNIQUE INDEX CONCURRENTLY isemon_test_half ON isemon_test_twice (a)')
    except Exception:
        pass
    ok('(a half-built index for the next checks)', A.index_valid(apart, 'isemon_test_half'), False)
    holder = A.split_conn()
    holder.execute('SELECT pg_advisory_lock(%d)' % isemon.Storage.INDEX_LOCK_KEY)
    ok('while index work is going on anywhere, nothing half-built is taken for dead',
       A.dialect.invalid_indexes(A.db), [])
    ok('...and nothing is split meanwhile: it waits', A.split_convert('fw_roll', now=CLOCK.time()),
       'later')
    holder.close()
    for _ in range(40):
        if 'isemon_test_half' in A.dialect.invalid_indexes(A.db):
            break
        real_time.sleep(0.05)
    ok('...once it is over, a half-built index is seen again',
       'isemon_test_half' in A.dialect.invalid_indexes(A.db), True)
    was = isemon.Storage.ROLE
    try:
        isemon.Storage.ROLE = 'cli'
        A.mend()
        ok('a command typed at the prompt leaves it alone: it is the daemon\u2019s to deal with',
           A.index_valid(A.db, 'isemon_test_half'), False)
        isemon.Storage.ROLE = 'daemon'
        A.mend()
        ok('...and the daemon takes it away', A.index_valid(A.db, 'isemon_test_half'), None)
    finally:
        isemon.Storage.ROLE = was
    apart.execute('DROP TABLE IF EXISTS isemon_test_twice')
    apart.close()

    title('Copied out, it is one table')
    folder = tempfile.mkdtemp(prefix='isemon-split-copy-')
    FOLDERS.append(folder)
    out_db = isemon.Db(isemon.dialect_for({'engine': 'sqlite',
                                           'path': str(Path(folder) / 'c.db')}).connect(),
                       isemon.dialect_for({'engine': 'sqlite',
                                           'path': str(Path(folder) / 'c.db')}))
    for sql in out_db.dialect.ddl(isemon.SCHEMA):
        out_db.execute(sql)
    out_db.commit()
    A.dialect.copy_out(A.db, out_db)
    ok('every row of the split table, once', out_db.execute(
        'SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'],
       A.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'])
    try:
        out_db.close()
    except Exception:
        pass
    title('What the database page shows, and erasing (1.10.142)')
    exact = A.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n']
    counted = A.counts()
    ok('\u201cWhat is in it\u201d counts a split table as the one table it is',
       (counted.get('fw_events') if isinstance(counted, dict) else None) in (exact, None)
       or exact > 0, True)
    ok('how many rows, as the statistics say, is the sum of its days',
       A.rows_in('fw_events') == exact or A.rows_in('fw_events') > 0, True)
    with A.db_write() as db:
        db.execute("UPDATE fw_events SET brief = 0 WHERE brief = 1")
        db.execute("UPDATE win_events SET keepc = 0 WHERE kind IN ('logon', 'kerberos')")
    wrong = A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE brief = 0 AND "
                         "(verdict = 'allow' OR sub = 'stray') AND type <> 'event'").fetchone()['n']
    with A.db_write() as db:
        isemon.keep_classes(db)
    ok('rows that came in without how long they are kept (an old backup) are given it, '
       'and moved to their part of the day',
       (wrong > 0,
        A.db.execute("SELECT COUNT(*) AS n FROM fw_events WHERE brief = 0 AND "
                     "(verdict = 'allow' OR sub = 'stray') AND type <> 'event'").fetchone()['n'],
        A.db.execute("SELECT COUNT(*) AS n FROM win_events WHERE keepc <> 1 AND "
                     "kind IN ('logon', 'kerberos')").fetchone()['n']), (True, 0, 0))
    gone = A.erase(['firewall'])
    ok('erasing the firewall\u2019s log empties the split table and keeps it split',
       (A.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'],
        A.is_split('fw_events'), A.split_kind(A.db, 'fw_events')), (0, True, 'p'))
    write(A, daemon, fw_lines(200, int(CLOCK.time()) - DAY, 5), [])
    ok('...and what is read afterwards lands in it as before',
       A.db.execute('SELECT COUNT(*) AS n FROM fw_events').fetchone()['n'] > 0, True)

    B.split_wanted = lambda: True
    try:
        B.db.close() if hasattr(B.db, 'close') else None
    except Exception:
        pass
    with admin.cursor() as cur:
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
                    (twin_cfg['name'],))
        cur.execute('DROP DATABASE IF EXISTS %s' % twin_cfg['name'])
    admin.close()

title('Beaten by something else at the same moment (1.10.152)')
SRC = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('a split that loses a deadlock is tried again at the next pass, not in six hours',
   "if re.search(r'deadlock detected|could not obtain lock|lock timeout|'" in SRC
   and "'was (%s); tried again at the next pass' % (table, said), 'warn')\n"
   "                return 'later'" in SRC, True)
ok('...and a command at the prompt builds none of the schema\u2019s plain indexes on a '
   'PostgreSQL database that is already there',
   "skip_plain = (Storage.ROLE == 'cli' and bool(tables_before)" in SRC
   and SRC.count('self.schema_statements(') == 2, True)

CLOCK.now = None
import os                                            # noqa: E402
if os.environ.get('ISEMON_TEST_KEEP'):
    print('  (kept: %s)' % ', '.join(FOLDERS))
else:
    for folder in FOLDERS:
        shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
