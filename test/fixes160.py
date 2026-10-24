#!/usr/bin/env python3
"""What 1.10.160 changed, each checked against what it replaced.

Records taken several hundred to a transaction, the faster questions a
busy installation asks of a big database, and the words the page uses for
counts - every one compared with the slower or older answer on the same
rows.

    ./test/fixes160.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
FOLDERS = []


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


BASE = {
    'blacklist': 1, 'block_mode': 'temporary', 'block_tries': 3,
    'block_window_min': 60, 'block_lots': 0, 'block_bogus_tries': 0,
    'block_ladder': '15, 60, forever', 'feeds_ban': 0, 'geo': 0,
    'mikrotik_host': '', 'mikrotik1': 0, 'mikrotik2': 0, 'watch_devices': '',
    'passed_devices': '', 'never_block': '', 'never_block_countries': '', 'read_passed': 1,
    'judge_max_age_h': 0, 'debug': False, 'judge_nps_vpn': 1, 'banfeed': 0,
}


def fresh(**cfg):
    folder = tempfile.mkdtemp(prefix='isemon-160-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'f.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update(BASE)
    isemon.CONFIG.update(cfg)
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    daemon.feed_wanted = lambda: []
    return store, daemon


SEQ = [514700]
POLICY = 'Use Windows authentication for all users'


def nps_line(when, packet, values):
    row = [''] * len(isemon.NPS_COLUMNS)
    col = isemon.NPS_COL
    row[col['Computer-Name']] = 'DC03'
    row[col['Service-Name']] = 'IAS'
    row[col['Record-Date']] = time.strftime('%m/%d/%Y', time.localtime(when))
    row[col['Record-Time']] = time.strftime('%H:%M:%S', time.localtime(when))
    row[col['Packet-Type']] = str(packet)
    for name, value in values.items():
        row[col[name]] = str(value)
    quoted = {'Computer-Name', 'Service-Name', 'User-Name', 'Fully-Qualified-User-Name',
              'Called-Station-Id', 'Calling-Station-Id', 'Framed-IP-Address',
              'NAS-Identifier', 'NAS-IP-Address', 'Client-IP-Address',
              'Client-Friendly-Name', 'Connect-Info', 'Class', 'Acct-Session-Id',
              'Proxy-Policy-Name', 'Policy-Name'}
    text = ','.join(('"%s"' % v) if (v and name in quoted) else v
                    for name, v in zip(isemon.NPS_COLUMNS, row))
    stamp = time.strftime('%b %d %H:%M:%S', time.localtime(when))
    return '%s dc03 nps: %s#015' % (stamp, text)


def vpn_try(when, name, addr, accepted=False):
    SEQ[0] += 1
    klass = '311 1 192.0.2.6 09/09/2026 13:10:54 %d' % SEQ[0]
    session = '4d4b%04x' % (SEQ[0] % 65536)
    ask = nps_line(when, 1, {
        'User-Name': name, 'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name,
        'Called-Station-Id': '192.0.2.254', 'Calling-Station-Id': addr,
        'Framed-IP-Address': addr, 'NAS-Identifier': 'FG-EXAMPLE',
        'NAS-IP-Address': '192.0.2.254', 'Client-Vendor': '0',
        'Client-IP-Address': '192.0.2.254', 'Client-Friendly-Name': 'EXAMPLE-FG',
        'NAS-Port-Type': '5', 'Connect-Info': 'vpn-ssl', 'Authentication-Type': '4',
        'Reason-Code': '0', 'Class': klass, 'Acct-Session-Id': session,
        'Proxy-Policy-Name': POLICY, 'Provider-Type': '1'})
    answer = nps_line(when, 2 if accepted else 3, {
        'Fully-Qualified-User-Name': 'EXAMPLE_NT\\' + name, 'Client-Vendor': '0',
        'Client-IP-Address': '192.0.2.254', 'Client-Friendly-Name': 'EXAMPLE-FG',
        'Authentication-Type': '4', 'Reason-Code': '0' if accepted else '16',
        'Class': klass, 'Acct-Session-Id': session, 'Proxy-Policy-Name': POLICY,
        'Provider-Type': '1'})
    return [ask, answer]


def records(n, now):
    lines = []
    for i in range(n):
        lines += vpn_try(now - 1800 + i, ('jnovak', 'mkral', 'admin')[i % 3],
                         '203.0.113.%d' % (i % 7 + 1), accepted=(i % 5 == 0))
    return isemon.nps_parse_lines(lines, {}, now=time.time())


def picture(store):
    failed = sorted((r['ip'], r['username'], round(float(r['ts']))) for r in store.db.execute(
        'SELECT ip, username, ts FROM failed'))
    passed = store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n']
    banned = sorted(r['ip'] for r in store.db.execute('SELECT ip FROM blocked'))
    return failed, int(passed), banned


print('\nRecords taken several hundred to a transaction')
NOW = time.time()
recs = records(60, NOW)
one_store, one_daemon = fresh()
one_new = sum(1 for rec in recs if one_daemon.take_record('nps', rec))
lot_store, lot_daemon = fresh()
new = lot_daemon.take_records([('nps', rec) for rec in recs])
ok('the same rows and the same bans as one at a time', picture(lot_store), picture(one_store))
ok('...and says how many were new, as one at a time does', new, one_new)
ok('somebody was banned at all', bool(picture(lot_store)[2]), True)

store, daemon = fresh()
bad = recs[7]
real_take = daemon.take_record


def take_but_one(kind, record, judge=True):
    if record is bad:
        raise RuntimeError('this one is refused')
    return real_take(kind, record, judge=judge)


daemon.take_record = take_but_one
daemon.take_records([('nps', rec) for rec in recs])
want_store, want_daemon = fresh()
for rec in recs:
    if rec is not bad:
        want_daemon.take_record('nps', rec)
ok('a record that raises is dropped and nothing else is lost',
   picture(store), picture(want_store))
ok('...and nothing is left half done', daemon._taking, False)

print('\nA lot whose transaction cannot even begin')
store, daemon = fresh()
few = records(5, NOW)
tries = [0]


class Away(object):
    def __enter__(self):
        tries[0] += 1
        if tries[0] > 50:
            raise SystemExit('asked for ever')
        raise isemon.DbError('connection refused')

    def __exit__(self, *a):
        return False


real_write = store.db_write
store.db_write = lambda *a, **k: Away()
said_was = isemon.log
isemon.log = lambda *a, **k: None
try:
    daemon.take_records([('nps', r) for r in few])
    ok('it comes back rather than asking again for ever', True, True)
except SystemExit:
    ok('it comes back rather than asking again for ever', False, True)
finally:
    isemon.log = said_was
    store.db_write = real_write

print('\nA lot whose commit fails is taken again without counting its bans twice')


def bans(st):
    return sorted((r['ip'], None if r['until'] is None
                   else round((float(r['until']) - time.time()) / 600))
                  for r in st.db.execute('SELECT ip, until FROM blocked'))


again = records(60, NOW)
want_store, want_daemon = fresh()
for rec in again:
    want_daemon.take_record('nps', rec)
store, daemon = fresh()
real_commit = isemon.Db.commit
once = {'done': False}


def commit_fails_once(self):
    if daemon._taking and not once['done']:
        once['done'] = True
        self.rollback()
        raise isemon.DbError('server closed the connection unexpectedly')
    return real_commit(self)


isemon.Db.commit = commit_fails_once
try:
    daemon.take_records([('nps', rec) for rec in again])
finally:
    isemon.Db.commit = real_commit
ok('the commit did fail', once['done'], True)
ok('the same bans, for the same time, as one at a time', bans(store), bans(want_store))

print('\nA ban pressed on a page while a lot is being taken')
store, daemon = fresh()
daemon.any_firewall = lambda: True
isemon.CONFIG['mikrotik_sync'] = 1
started = []
daemon._mikrotik_quietly = lambda: started.append(1)
import threading                                     # noqa: E402
daemon._taking = True
daemon._taking_thread = -1                           # some other thread's lot
daemon.mikrotik_after_change()
daemon._taking = False
daemon._taking_thread = None
time.sleep(0.2)
ok('goes to the router at once', (started, daemon._router_owed), ([1], False))
isemon.CONFIG['mikrotik_sync'] = 0

print('\nWhether an address is kept out, asked of the list once')
store, daemon = fresh()
for ip, until in (('198.51.100.7', None), ('198.51.100.8', time.time() + 600),
                  ('192.0.2.0/24', None), ('2001:db8:5::/48', time.time() + 900),
                  ('2001:db8:1::5', None)):
    with store.db_write() as db:
        db.execute('INSERT INTO blocked (ip, since, until, why, hits) VALUES (?,?,?,?,0)',
                   (ip, time.time(), until, 'test'))
look = store.blocked_lookup()
asked = ['198.51.100.7', '198.51.100.8', '198.51.100.9', '192.0.2.44', '2001:db8:5::1',
         '2001:db8:6::1', '2001:db8:1::5', 'not an address', '192.0.2.0/24']
ok('the same answers as asking one at a time',
   [look(ip) for ip in asked], [store.blocked_until(ip) for ip in asked])

print('\nThe firewall\'s counted hours, added up by the hour first')
DAY = 86400
facts = []
for i in range(300):
    facts.append({'ts': NOW - (i * 997) % (2 * DAY), 'verdict': ('allow', 'deny', 'info')[i % 3],
                  'fw': ('', 'hq', 'branch')[i % 3], 'srcip': '10.1.0.%d' % (i % 40 + 1),
                  'dstip': '198.51.100.%d' % (i % 9 + 1), 'dstport': 443 if i % 2 else 22,
                  'proto': 6, 'sentbyte': i * 10, 'rcvdbyte': i * 7, 'type': 'traffic',
                  'srccountry': 'CZ', 'dstcountry': ('DE', 'US')[i % 2], 'service': 'HTTPS',
                  'app': '', 'cat': '', 'usr': '', 'host': ''})


def by_line(self, events):
    """The sums as they were made before 1.10.160: line by line."""
    sums = {}
    for f in events:
        ts = float(f.get('ts') or 0)
        verdict = f.get('verdict') or 'info'
        sent, rcvd, lines = isemon.fw_carried(f)
        sent = isemon.fw_whole(sent, isemon.FW_COUNTER_MOST)
        rcvd = isemon.fw_whole(rcvd, isemon.FW_COUNTER_MOST)
        dims = self.fw_dims(f)
        fw = str(f.get('fw') or '')[:40]
        if fw:
            dims = dims + [(isemon.fw_dim(d, fw), v) for d, v in dims]
        for span in (3600, 86400):
            at = int(ts // span) * span
            for dim, val in dims:
                key = (span, at, dim, val, verdict)
                one = sums.get(key)
                if one is None:
                    sums[key] = [lines, sent, rcvd]
                else:
                    one[0] += lines
                    one[1] += sent
                    one[2] += rcvd
    return sorted(k + tuple(v) for k, v in sums.items())


store, daemon = fresh()
ok('exactly the same sums', sorted(store.fw_roll_deltas(facts)), by_line(store, facts))

print('\nThe firewall\'s lines: newest, one line by its moment, pages in time order')
store, daemon = fresh(fwlog_keep_days=14, fwlog_allowed_days=14)
filled = daemon.fw_fill([dict(f, fields={'n': str(i)}, raw='line %d' % i,
                              ident='%032x' % (i + 1), type='traffic', sub='forward',
                              brief=0)
                         for i, f in enumerate(facts)])
store.note_fw_events(filled)
kept = [dict(r) for r in store.db.execute('SELECT ident, ts FROM fw_events')]
ok('the lines are there', len(kept) > 100, True)
ok('the newest is MAX(ts)', round(store.newest_in('fw_events'), 3),
   round(max(float(r['ts']) for r in kept), 3))
some = kept[len(kept) // 2]
by_ts = store.fw_get(some['ident'], ts=float(some['ts']))
alone = store.fw_get(some['ident'])
ok('one line found by its moment is the line found without it',
   (by_ts or {}).get('ident'), (alone or {}).get('ident'))
ok('...and a wrong moment still finds it', (store.fw_get(some['ident'], ts=1.0) or {})
   .get('ident'), some['ident'])
since = NOW - 3 * DAY
print('  (split by day: %s)' % store.is_split('fw_events'))
for desc in (True, False):
    for skip in (0, 37, 150):
        rows, _total = store.fw_rows(since=since, limit=50, offset=skip, desc=desc)
        want = [r['ident'] for r in store.db.execute(
            'SELECT ident FROM fw_events WHERE ts >= ? ORDER BY ts %s%s LIMIT 50 OFFSET %d'
            % ('DESC' if desc else 'ASC', store.tie_break('ident', desc), skip), (since,))]
        ok('a page %s from %d is the one statement\'s page'
           % ('newest first' if desc else 'oldest first', skip),
           [r['ident'] for r in rows], want)

print('\nThe new setting')
ok('whole days is a setting with a name and words',
   # On by default since 1.10.176.
   'db_split_whole_days' in isemon.DEFAULTS and isemon.DEFAULTS['db_split_whole_days'] == 1, True)

print('\nSpans as words')
ok('one day', isemon.human_span(86400 + 3 * 3600).startswith('1 day '), True)
ok('two days', isemon.human_span(2 * 86400 + 3600).startswith('2 days'), True)

print('\nThe page: counts, spans and Czech plurals')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')


def js_function(name):
    """A top-level function of the page, to the brace that closes it at the
    start of a line."""
    at = page.index('\nfunction %s(' % name) + 1
    end = page.index('\n}', at)
    return page[at:end + 2]


node = shutil.which('node')
if node:
    script = 'var I18N = {on: false};\n' + '\n'.join(
        js_function(n) for n in ('numLang', 'num', 'i18nPlural')) + r'''
var out = {
  num: num(1234567),
  one: i18nPlural('{0} {0:den|dny|dní}', [0], ['', '1']),
  few: i18nPlural('{0} {0:den|dny|dní}', [0], ['', '3']),
  many: i18nPlural('{0} {0:den|dny|dní}', [0], ['', '1,250']),
  word: i18nPlural('{0} {0:den|dny|dní}', [0], ['', 'more than 5']),
  two: i18nPlural('{1:row|rows}', [0, 1], ['', 'x', '2'])
};
console.log(JSON.stringify(out));
'''
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('a number grouped by thousands', got['num'], '1,234,567')
    ok('one', got['one'], '{0} den')
    ok('two to four', got['few'], '{0} dny')
    ok('five and over, with a comma in it', got['many'], '{0} dní')
    ok('not a number at all', got['word'], '{0} dní')
    ok('two forms', got['two'], 'rows')
else:
    print('  (no node here: the page\'s own functions are not run)')

cs = json.loads((HERE.parent / 'web' / 'lang' / 'cs.json').read_text(encoding='utf-8'))
broken = []
for section in ('patterns', 'rich'):
    for k, v in cs.get(section, {}).items():
        text = v.get('text') or ''
        for slot in __import__('re').findall(r'\{(\d+):([^}]*)\}', text):
            if '{%s}' % slot[0] not in v['source'] or len(slot[1].split('|')) not in (2, 3):
                broken.append(k)
ok('every Czech plural names a slot its pattern has, with two or three forms', broken, [])

for folder in FOLDERS:
    shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
