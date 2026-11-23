#!/usr/bin/env python3
"""1.10.379: bug hunt, round 8 of 10 - the OTP, acme and TACACS+ tabs and
their readers, backups and the tidying.

    ./test/fixes379_hunt.py
"""
import os
import sqlite3
import subprocess
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


folder = Path(tempfile.mkdtemp(prefix='isemon-379-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'otp': 1, 'tacplus': 1})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('The door cards')
now = time.time()
with store.db_write() as db:
    for i, (reason, dt) in enumerate([('the token was wrong', 3000),
                                      ('that token had been used already', 2000),
                                      ('too many tries: held back for a while', 100)]):
        db.execute('INSERT INTO failed (session, ts, ip, username, kind, reason, server) '
                   'VALUES (?,?,?,?,?,?,?)',
                   ('otp/x/%d' % i, now - dt, '', 'anovak', 'otp', reason, 'otp1'))
rows = store.door_subjects('otp', now - 86400, 'username', 12)
ok('"what it last said" is the newest refusal, not the oldest',
   rows[0]['newest'].get('reason'), 'too many tries: held back for a while')

print('tac_plus')
base = int(time.time()) - 3600
lines = []
st = time.strftime('%b %d %H:%M:%S', time.localtime(base - 5))
lines.append("%s tacsrv tac_plus[2461]: login query for 'anovak' tty1 from 10.0.0.9 accepted" % st)
for i, cmd in enumerate(['show version', 'show run', 'configure terminal']):
    at = base + i * 20
    st = time.strftime('%b %d %H:%M:%S', time.localtime(at))
    lines.append("%s tacsrv tac_plus[2461]: authorization query for 'anovak' tty1 from "
                 "10.0.0.9 accepted" % st)
    lines.append('%s\t10.0.0.1\tanovak\ttty1\t10.0.0.9\tstop\ttask_id=%d\ttimezone=UTC\t'
                 'service=shell\tstart_time=%d\tpriv-lvl=15\tcmd=%s <cr>' % (st, i, at, cmd))
daemon.read_records(lines, kind='tacplus')
kinds = [r['kind'] for r in store.db.execute("SELECT kind FROM passed WHERE kind LIKE 'tacplus%'")]
ok('a command let through is no sitting of its own',
   (kinds.count('tacplus'), kinds.count('tacplus-cmd')), (2, 3))

print('RADIUS detail read again, with no id=')
at = int(time.time()) - 1200
st = time.strftime('%b %d %H:%M:%S', time.localtime(at))
ct = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(at))
ct1 = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(at + 1))
det = [
    '%s otp1 radius-detail[5]: nas=192.0.2.1 file=auth-detail-x ts=[%s] Packet-Type = '
    'Access-Request, User-Name = "bdvorak@a.test", Calling-Station-Id = "198.51.100.10", '
    'Packet-Src-IP-Address = 192.0.2.1, Packet-Src-IP-Port = 40001' % (st, ct),
    '%s otp1 radius-detail[5]: nas=192.0.2.1 file=reply-detail-x ts=[%s] Packet-Type = '
    'Access-Reject, Reply-Message = "Denied access by rlm_perl: account does not pass LDAP '
    'group filter(s)", Packet-Dst-IP-Address = 192.0.2.1, Packet-Dst-IP-Port = 40001'
    % (st, ct1)]
daemon.read_records(det, kind='otp-detail')
daemon.read_records(det, kind='otp-detail')
ok('one packet, however often read',
   store.db.execute('SELECT COUNT(*) AS n FROM otp_asked').fetchone()['n'], 1)
daemon.apply_radius_refusals()
ok('...and no refusal of nobody', store.db.execute(
    "SELECT COUNT(*) AS n FROM failed WHERE COALESCE(username,'') = ''").fetchone()['n'], 0)

print('The tidying')
with store.db_write() as db:
    db.execute('DELETE FROM events')
    for i, ts in enumerate([5] * 4 + [7] * 4 + [9]):
        db.execute("INSERT INTO events (ts, kind, level, detail) VALUES (?, 'x', 'info', ?)",
                   (ts, 'e%d' % i))
store.tidy_older('events', 100, stride=3)
ok('a second wall of one moment is taken whole as the first is',
   store.db.execute('SELECT COUNT(*) AS n FROM events').fetchone()['n'], 0)

print('Backups')
for i in range(3):
    p = store.backup(label='x%d' % i)
store.backups()
store.looks_like_ours(p)
store.prune_backups(1)
left = sorted(os.listdir(isemon.BACKUP_DIR))
ok('a copy is a plain file, and nothing of a pruned one is left',
   [n for n in left if n.endswith(('-wal', '-shm'))], [])
store.add_event('test', 'before the copy', 'info')
p = store.backup()
c = sqlite3.connect(str(p))
c.execute('PRAGMA page_size=8192')
c.execute('VACUUM')
c.close()
try:
    store.restore(p)
    said = 'restored'
except Exception as e:
    said = '%s: %s' % (type(e).__name__, e)
ok('a copy of another page size goes back', said, 'restored')
ok('...whole', store.db.execute(
    "SELECT COUNT(*) AS n FROM events WHERE detail = 'before the copy'").fetchone()['n'], 1)
ok('...and sound', store.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
ok('install.sh keeps the three newest old programs and pages',
   'head -n -3' in (ROOT / 'install.sh').read_text())

print('The page')
page = (ROOT / 'web' / 'index.php').read_text()


def js(name):
    i = page.index('function %s(' % name)
    depth, j = 0, page.index('{', i)
    while True:
        depth += {'{': 1, '}': -1}.get(page[j], 0)
        j += 1
        if not depth:
            return page[i:j]


code = js('ceilingOf') + js('amMs') + '''
console.log(JSON.stringify([[0, 1, 2, 5, 14, 100].map(ceilingOf),
  [850, 9500, 59700, 119700, 61000].map(amMs)]));'''
r = subprocess.run(['node', '-e', code], capture_output=True, text=True)
got = r.stdout.strip()
ok('the chart\'s ceiling is four whole steps; a time never says "60 s"', got,
   '[[4,4,4,8,20,100],["850 ms","9.5 s","1 min 0 s","2 min 0 s","1 min 1 s"]]')
ok('the acme certificates sorted by date, not by the words',
   "if (c.not_after) td.dataset.sort = String(c.not_after);" in page)
ok('"850 ms" sorts below "12 s"', 'if (msv) return +msv[1] / 1000;' in page)
ok('a word column opens A to Z', "/^(hits|n)$|bytes/.test(key)" in page)
ok('a removal is said as one', "remove: 'removed'};" in page and "'Removed.'" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
