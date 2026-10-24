#!/usr/bin/env python3
"""What 1.10.159 found wrong, each made to happen and then checked.

Reading the logs, the daemon's own lifecycle, the router and the ban feed,
and the faster answers - the last checked against the slower ones they
replaced, on the same rows.

    ./test/fixes159.py
"""
import gzip
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
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


def fresh(**cfg):
    folder = tempfile.mkdtemp(prefix='isemon-159-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'f.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'watch_devices': '', 'feeds_ban': 0, 'judge_max_age_h': 0,
                          'geo': 0, 'mikrotik1': 0, 'mikrotik2': 0})
    isemon.CONFIG.update(cfg)
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    daemon.feed_wanted = lambda: []
    return folder, store, daemon


class Line(object):
    def __init__(self, text):
        self.ts = 0
        self.line = text


def lines_parser(lines, hold=None):
    return [Line(one) for one in lines if one.startswith('rec')]


def tail_on(path):
    return isemon.LogTail(path, parser=lines_parser)


folder = tempfile.mkdtemp(prefix='isemon-159-logs-')

print('\nA stretch of a file with no end of line')
p = os.path.join(folder, 'skip.log')
with open(p, 'wb') as f:
    f.write(b''.join(b'rec %03d ........................\n' % i for i in range(40)))
t = tail_on(p)
t.read(4096)
with open(p, 'ab') as f:
    f.write(b'B' * 5000 + b'\nrec 999\n')
seen = []
for _ in range(8):
    seen += [r.line for r in t.read(4096)]
ok('is stepped over once, and what follows it is read once', seen, ['rec 999'])

print('\nA rotated file still being written to')
p = os.path.join(folder, 'x.log')
open(p, 'w').write('rec 1\n')
t = tail_on(p)
got = [r.line for r in t.read()]
w = open(p, 'a')
w.write('rec 2\n')
w.flush()
os.rename(p, p + '.1')
open(p, 'w').close()
got += [r.line for r in t.read()]
w.write('rec 3\n')
w.flush()
w.close()
open(p, 'a').write('rec 4\n')
for _ in range(3):
    got += [r.line for r in t.read()]
ok('lines written to it after the rename are read too', got,
   ['rec 1', 'rec 2', 'rec 3', 'rec 4'])
kept = t.state()
ok('...and where it was in it is kept over a restart', 'prev' in kept, True)

print('\nA log path that is a link')
real_dir = os.path.join(folder, 'real')
os.makedirs(real_dir)
real = os.path.join(real_dir, 'y.log')
link = os.path.join(folder, 'y-link.log')
open(real, 'w').write('rec a\n')
os.symlink(real, link)
t = tail_on(link)
got = [r.line for r in t.read()]
open(real, 'a').write('rec b\n')
os.rename(real, real + '.1')
open(real, 'w').write('rec c\n')
got += [r.line for r in t.read()]
ok('the rotated file is found beside the file, not beside the link', got,
   ['rec a', 'rec b', 'rec c'])

print('\nA hole of NUL bytes before a line')
ok('the line after it is a line',
   isemon.log_lines('\x00\x00\x00\x00rec 3\nrec 4\n'), ['rec 3', 'rec 4'])

print('\nHalf an eduroam accounting block over a restart')
hold = {}
isemon.edu_detail_blocks(['Sat Oct  3 10:00:00 2026', '\tUser-Name = "bob@example.org"'],
                         hold)
again = isemon.LogTail.unpack_hold(isemon.LogTail.pack_hold(hold))
out = isemon.edu_detail_blocks(['\tAcct-Status-Type = Start', ''], again)
ok('the block is finished with its first half', [o.get('User-Name') for o in out],
   [['bob@example.org']])

print('\nAn old file read in late December')
when = isemon.otp_when('Jan', '3', '10:00:00',
                       now=datetime(2026, 12, 28, tzinfo=timezone.utc).timestamp(),
                       zone=timezone.utc)
ok('its January lines stay in this year', datetime.fromtimestamp(when, timezone.utc).year, 2026)

print('\nThe first seconds of January, read in the last of December')
when = isemon.otp_when('Jan', '1', '00:00:05',
                       now=datetime(2026, 12, 31, 23, 59, 50, tzinfo=timezone.utc).timestamp(),
                       zone=timezone.utc)
ok('are next year, not last year', datetime.fromtimestamp(when, timezone.utc).year, 2027)

print('\nA FortiGate line with no zone on it')
_, store, daemon = fresh()
isemon._READING_IN.zone = 'UTC'
got = isemon.fg_when({'date': '2026-10-01', 'time': '07:56:02'})
isemon._READING_IN.zone = None
ok('is read in the zone set for that firewall',
   datetime.fromtimestamp(got, timezone.utc).strftime('%H:%M'), '07:56')
_, store, daemon = fresh(log_zone='America/New_York')
plain = datetime(2026, 10, 1, 7, 56, 2).timestamp()
ok('...and not in the ISE logs\' zone', isemon.fg_when({'date': '2026-10-01',
                                                      'time': '07:56:02'}), plain)

print('\nA user name with the rest of a line typed into it')
said = isemon.TACPLUS_QUERY_WHOLE.search(
    "login query for 'admin' tty9 from 198.51.100.66 rejected' tty1 from 10.10.10.9 accepted")
quoted = isemon.TACPLUS_QUERY_QUOTED.search(
    "login query for 'alice' 'tty1' from 10.1.1.1 rejected")
ok('...and a port written in quotes is still the port',
   (quoted.group('user'), quoted.group('port')), ('alice', 'tty1'))
ok('tac_plus keeps the address and the verdict the daemon wrote',
   (said.group('from'), said.group('port'), said.group('verdict')),
   ('10.10.10.9', 'tty1', 'accepted'))
ok('Windows takes the address out of its own section first',
   isemon.win_address({'Source Network Address': '198.51.100.66',
                       'Network Information / Source Network Address': '172.29.40.11'}),
   '172.29.40.11')

print('\nThe settings read again while the database is away')
_, store, daemon = fresh(retain_failed_days=0)
store.settings_write({'retain_failed_days': 0})
daemon.adopt_settings()
daemon.reread_asked.set()
real_serial = store.settings_serial
store.settings_serial = lambda: (_ for _ in ()).throw(isemon.sqlite3.OperationalError('gone'))
daemon.settings_changed_underneath()
store.settings_serial = real_serial
ok('the settings running are kept', isemon.CONFIG.get('retain_failed_days'), 0)
daemon._settings_retry_at = 0                     # a minute later
daemon.settings_changed_underneath()
ok('...and read again when it is back', daemon._settings_serial, store.settings_serial())

print('\nThe same domain event twice in one write')
_, store, daemon = fresh(winsec=1)
ev = {'ident': 'dc1/1/4625', 'ts': time.time() - 60, 'server': 'dc1', 'event': 4625,
      'kind': 'logon-failed', 'account': 'novak', 'said': 'x'}
store.note_win_events([dict(ev), dict(ev)])
ok('is one row', store.db.execute('SELECT COUNT(*) AS n FROM win_events').fetchone()['n'], 1)
if store.roll_on():
    n = store.db.execute("SELECT SUM(n) AS n FROM win_rollup WHERE dim = 'kind'").fetchone()['n']
    ok('...counted once', int(n or 0), 1)

print('\nA dump cut short')
_, store, daemon = fresh()
isemon.DUMP_DIR.mkdir(parents=True, exist_ok=True)
part = isemon.DUMP_DIR / 'isemon-20260101-000000-daily.pgc.part'
part.write_bytes(b'x' * 100)
os.utime(str(part), (time.time() - 7 * 3600, time.time() - 7 * 3600))
store.prune_dumps(keep=3)
ok('its .part is let go once nobody can be writing it', part.exists(), False)

print('\nJobs that never look whether they are wanted')
ok('are not offered a stop they would not honour',
   all(k in isemon.Daemon.WONT_STOP for k in ('db-roll', 'db-split', 'db-dump')), True)

print('\nRouterOS durations of a week or more')
ok('4w1d23:59:00', isemon.mikrotik_seconds('4w1d23:59:00'), 4 * 604800 + 86400 + 86340)
ok('...and the short forms as before',
   (isemon.mikrotik_seconds('1d 02:03:04'), isemon.mikrotik_seconds('9m59s')), (93784, 599))

print('\nA hand ban or a whitelist entry that is everything')
for text in ('0.0.0.0/0', '::/0', '127.0.0.1', '10.0.0.0/7'):
    try:
        isemon.too_wide(text, 'banned')
        ok('%s is refused' % text, 'taken', 'refused')
    except ValueError:
        ok('%s is refused' % text, True)
for text in ('fc00::/7', 'fe80::/10'):
    try:
        isemon.too_wide(text, 'put on the whitelist')
        ok('%s may be spared' % text, True)
    except ValueError as e:
        ok('%s may be spared' % text, str(e), 'spared')
for text in ('10.0.0.0/8', '203.0.113.5', '2001:db8::/32'):
    try:
        isemon.too_wide(text, 'banned')
        ok('%s is taken' % text, True)
    except ValueError as e:
        ok('%s is taken' % text, str(e), 'taken')

print('\nPublic lists and the ranges they are read into')
_, store, daemon = fresh()
ranges = [isemon.range_of(x) for x in ('1.0.0.0/24', '2.0.0.0/32', '2.0.0.0/16', '3.0.0.0/24')]
was = store.STREAM_BATCH
store.STREAM_BATCH = 2
store.put_feed_streamed('x', iter(ranges))
store.STREAM_BATCH = was
ok('a range sharing its start with the last of a page is kept',
   [f for f in store.feeds_with('2.0.5.5')], ['x'])

print('\nUndoing a folding after one of its addresses was let back in')
_, store, daemon = fresh(fold_least=3, fold_widest=24)
for k in (5, 6, 7):
    daemon.ban('198.51.100.%d' % k, why='attacker', by='admin')
daemon.fold_apply(by='test')
vid = store.fold_versions(1)[0]['id']
daemon.unfold('198.51.100.0/24', by='admin')
daemon.unban('198.51.100.6', by='admin') if hasattr(daemon, 'unban') else \
    store.unblock('198.51.100.6', by='admin')
daemon.fold_undo(vid, by='admin')
ok('does not ban it again', store.blocked_one('198.51.100.6'), None)

print('\nThe faster answers give the same answers')
_, store, daemon = fresh()
now = time.time()
rows = []
for i in range(400):
    rows.append({'session': 's%d' % i, 'ts': now - i * 60, 'ip': '203.0.113.%d' % (i % 23),
                 'username': 'user%d' % (i % 17), 'device': 'FTD-VPN', 'server': 'ise1',
                 'kind': ('vpn', 'nps-vpn', None, 'tacacs')[i % 4], 'country': 'CZ',
                 'code': 'abandoned' if i % 9 == 0 else '22056', 'detail': '{}'})
for r in rows:
    store.add_failed(r)
cut = now - 86400
old_attackers = [dict(r) for r in store.db.execute(
    'SELECT ip, COUNT(*) AS tries, MAX(ts) AS last, MIN(ts) AS first FROM failed '
    "WHERE (kind IN ('vpn','nps-vpn') OR kind IS NULL) AND ts>=? AND COALESCE(ip,'')<>'' "
    "AND NOT (kind='nps-vpn' AND COALESCE(code,'')='abandoned') "
    'GROUP BY ip ORDER BY tries DESC, last DESC, ip LIMIT 12', (cut,))]
new_attackers = store.top_attackers(since=cut, limit=12)
ok('the busiest addresses',
   [(r['ip'], int(r['tries'])) for r in new_attackers][:len(old_attackers)],
   [(r['ip'], int(r['tries'])) for r in old_attackers])
old_users = [dict(r) for r in store.db.execute(
    'SELECT username, COUNT(*) AS tries, COUNT(DISTINCT ip) AS addresses, MAX(ts) AS last '
    'FROM failed WHERE ts>=? AND username<>"" AND ' + isemon.judged_sql() + ' '
    'GROUP BY username ORDER BY tries DESC, last DESC, username LIMIT 10', (cut,))]
new_users = store.top_users(since=cut, limit=10, table='failed')
ok('the names tried', [(r['username'], r['tries'], r['addresses']) for r in new_users],
   [(r['username'], r['tries'], r['addresses']) for r in old_users])

print('\nThe front page for a year, over a restart')
out = daemon.dashboard(8760)
written = store.get_meta('dash/8760')
ok('is written down', bool(written), True)
later = isemon.Daemon(store)
ok('...and handed out at once by the next daemon', later.dashboard(8760), out)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
