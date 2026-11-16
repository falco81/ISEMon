#!/usr/bin/env python3
"""1.10.359: questions that read far more than they needed.

What holds an old password asked, for each of twelve rows, the newest event
of that account with a service, `ORDER BY ts DESC LIMIT 1` - on PostgreSQL a
walk backwards through every event of the account, 26 s for a service
account with millions of tickets a day, twice a row. One look now, cut by
the refusals' kinds and the window, and the answers must be the same. The
same for the machine accounts refused for a wrong password: one look for
the five rather than every event of each. And the Domain page's progress
card is kept up by the status, not by its own answer, which can be minutes
apart.

    ./test/fixes359_index.py
"""
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


folder = Path(tempfile.mkdtemp(prefix='isemon-359-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log').items():
    setattr(isemon, k, v)
store = isemon.Storage(isemon.DB_FILE)
now = time.time()
n = [0]


def ev(ago, kind, account, machine='', ip='', process='', service='', said='', event=4625,
       is_machine=0):
    n[0] += 1
    with store.db_write() as db:
        db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, is_machine, '
                   'machine, ip, process, service, said, mark, marks) '
                   "VALUES (?, ?, 'DC1', ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 0)",
                   ('e%d' % n[0], now - ago, event, kind, account, is_machine, machine, ip,
                    process, service, said))


# Somebody's laptop holding an old password: Kerberos and NTLM refusals, two
# services, the newest with a service is krbtgt; what the domain said most is
# "the password was wrong".
for i in range(8):
    ev(3000 - i * 10, 'kerberos-failed', 'jnovak', 'NB-NOVAK', '10.0.0.5', '',
       'cifs/fs1' if i < 5 else 'krbtgt', 'the password was wrong', 4771)
for i in range(3):
    ev(2000 - i, 'logon-failed', 'jnovak', 'NB-NOVAK', '10.0.0.5', '', '', 'locked', 4625)
# ...and a service account with heaps of tickets that worked - which the old
# look walked through - and a handful of refusals with no service at all.
for i in range(300):
    ev(1000 + i, 'kerberos', 'svc-sps', 'SPS01', '10.0.0.9', '', 'http/sps', '', 4769)
for i in range(6):
    ev(500 + i, 'ntlm-failed', 'svc-sps', 'SPS01', '10.0.0.9', '', '', 'the password was wrong',
       4776)
# ...the same account written another way, refused from another machine.
for i in range(5):
    ev(400 + i, 'logon-failed', 'JNovak', 'PC-7', '10.0.0.7', 'outlook.exe', '',
       'the password was wrong', 4625)

holders = store.win_holders(now - 86400, 12, None)
by = {(h['said'], h['newest']['machine']): h['newest'] for h in holders}
ok('the laptop: the newest service it asked for', by[('jnovak', 'NB-NOVAK')]['service'], 'krbtgt')
ok('...and that refusal\'s kind', by[('jnovak', 'NB-NOVAK')]['kind'], 'kerberos-failed')
ok('...and what the domain said most', by[('jnovak', 'NB-NOVAK')]['said'], 'the password was wrong')
ok('the service account: no service on its refusals, none said',
   by[('svc-sps', 'SPS01')]['service'], '')
ok('...what it was told', by[('svc-sps', 'SPS01')]['said'], 'the password was wrong')
ok('...its tickets that worked not taken for a refusal', by[('svc-sps', 'SPS01')]['kind'],
   'logon-failed')
ok('the other spelling: its own machine and program', by[('JNovak', 'PC-7')]['said'],
   'the password was wrong')

# The old way, a row at a time, for the same rows: the answers agree.
for h in holders:
    got = h['newest']
    row = store.db.execute(
        "SELECT service, kind FROM win_events WHERE ts >= ? AND LOWER(account) = ? "
        "AND kind IN ('logon-failed','kerberos-failed','ntlm-failed') "
        "AND COALESCE(machine,'') = ? AND COALESCE(ip,'') = ? AND COALESCE(process,'') = ? "
        "AND COALESCE(service,'') <> '' ORDER BY ts DESC LIMIT 1",
        (now - 86400, h['said'].lower(), got['machine'], got['ip'], got['process'])).fetchone()
    ok('as a row at a time: %s from %s' % (h['said'], got['machine']),
       got['service'], str(row['service']) if row else '')

src = Path(isemon.__file__).read_text(encoding='utf-8')
start = src.index('    def win_holders(')
body = src[start:src.index('\n    def ', start + 10)]
ok('no look a row by the account any more', "'ORDER BY ts DESC LIMIT 1' %" in body, False)

# Machine accounts with a wrong password, and where from.
for i in range(7):
    ev(300 + i, 'kerberos-failed', 'PC9$', 'PC9', '10.0.1.9' if i < 5 else '10.0.1.10', '', '',
       'the password was wrong', 4771, 1)
for i in range(50):
    ev(200 + i, 'kerberos', 'PC9$', 'PC9', '10.0.1.9', '', 'host/pc9', '', 4769, 1)
got = store.win_machine_refused(now - 86400)
pc9 = [g for g in got if g['account'] == 'PC9$']
ok('a machine refused for a wrong password is named', len(pc9), 1)
ok('...with where from, busiest first', pc9[0]['ips'] if pc9 else None,
   [('10.0.1.9', 5), ('10.0.1.10', 2)])
start = src.index('    def win_machine_refused(')
body = src[start:src.index('\n    def ', start + 10)]
ok('...asked once for all of them', body.count('self.db.execute('), 2)

page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
ok('the progress card is kept up by the status every 5 s',
   'winCountingFromStatus(data.going)' in page)
ok('...the Domain page asked again when the counting is gone',
   'if (had && !now)' in page and 'loadWindows(true)' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
