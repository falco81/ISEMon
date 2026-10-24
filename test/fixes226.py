#!/usr/bin/env python3
"""1.10.226: otp - the token server that replaced totpcgi, with codes sent by
SMS and by mail (otp 1.0.76 and later) - read as fully as totpcgi always was,
and totpcgi read exactly as before.

The lines are a real otp 1.0.92 pair of servers' own, names and addresses
changed (test/otp-1.0.92/). Every one of otp's sentences is out of its
source.

    ./test/fixes226.py
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime
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


def title(words):
    print('\n' + words)


# --------------------------------------------------------------------------
title('Every sentence otp writes, in the page\'s words')
W = isemon.otp_words
ok('totpcgi\'s own, unchanged: the token was right', W('Valid token used'), 'the token was right')
ok('...a step out of time', W('Valid token within window size used'),
   'the token was right, a step out of time')
ok('...a recovery code', W('Scratch-token used'), 'a one-off recovery code was used')
ok('...wrong', W('Not a valid token'), 'the token was wrong')
ok('...used already', W('Token has already been used once'), 'that token had been used already')
ok('...nothing enrolled', W('pincodes file not found!'), 'this account has nothing enrolled here')
ok('otp: a code by SMS', W('Code sent by SMS accepted'), 'a code by SMS was right')
ok('otp: a code by mail', W('Code sent by mail accepted'), 'a code by mail was right')
ok('otp: nothing enrolled, in its words, the same as totpcgi\'s',
   W('No token is enrolled for this account'), W('pincodes file not found!'))
ok('otp: rate limit', W('Rate-limit reached, please try again later'),
   'too many tries: held back for a while')
ok('otp: locked out', W('Locked out after too many wrong codes, please try again later'),
   'locked out after too many wrong codes')
ok('otp: switched off', W('This token is switched off'), 'the token is switched off')
ok('otp: never confirmed', W('This token has not been confirmed yet'),
   'the token was never confirmed')
ok('otp: a key it cannot open', W('The key of this token cannot be opened on this machine'),
   'this server cannot open the token’s key')
ok('otp: confirming a new token', W('Not a valid token (confirming a new token)'),
   'the code was wrong confirming a new token')
ok('...rate limit and lockout while confirming', (
    W('Rate-limit reached, please try again later (confirming a new token)'),
    W('Locked out after too many wrong codes, please try again later (confirming a new token)')),
   ('too many tries confirming a new token', 'locked out confirming a new token'))
ok('otp: ...too many, the key thrown away',
   W('Not a valid token (confirming a new token - too many, the new key is thrown away)'),
   'too many wrong codes confirming a new token: its key was thrown away')
ok('otp: not in the groups of the realm', W('Not in the groups of the realm corp: may not enrol'),
   'not in the realm’s groups: may not enrol a token')
ok('a sentence nobody knows is kept as it is', W('Something new'), 'Something new')

title('How the code came')
H = isemon.otp_asked_how
ok('SMS, in Czech', H('Zadejte kód z SMS poslané na +420******123'),
   ('sms', '+420******123'))
ok('SMS, in English', H('Type the code sent by SMS to +420******123'), ('sms', '+420******123'))
ok('mail, in English', H('Type the code mailed to j*****@example.cz'), ('mail', 'j*****@example.cz'))
ok('mail, in Czech', H('Zadejte kód, který přišel e-mailem na j*****@example.cz'),
   ('mail', 'j*****@example.cz'))
ok('the app, both languages', (H('Type the code from the app on your phone')[0],
                               H('Zadejte kód z aplikace v telefonu')[0]), ('app', 'app'))
ok('"type it again" is not a new question', H('Kód nebyl správný - zadejte ho znovu'),
   ('', ''))
ok('...nor anything else', H('Denied access by rlm_perl'), ('', ''))
ok('the token line says it as well', [isemon.otp_line_how(x) for x in (
    'Code sent by SMS accepted', 'Code sent by mail accepted', 'Scratch-token used',
    'Valid token used', 'Not a valid token')], ['sms', 'mail', 'recovery', 'app', ''])

title('What the code was typed for')
P = isemon.otp_purpose
ok('signing in, as totpcgi always wrote it', P('PAM_SM_AUTH'), '')
ok('otp\'s enrolment page', P('PROVISION'), 'on the enrolment page')
ok('an administrator confirming one', P('ADMIN'), 'confirmed by an administrator')
ok('a test', (P('TEST-DRY'), P('CLI-DRY')), ('a test by an administrator',) * 2)
ok('a line with no mode at all', P(''), '')

# --------------------------------------------------------------------------
title('Two otp servers\' logs, read for real')
work = Path(tempfile.mkdtemp(prefix='isemon-226-'))
isemon.STATE_DIR = work
isemon.DB_FILE = work / 'd.db'
isemon.BACKUP_DIR = work / 'backups'
isemon._LOG_PATH = work / 'd.log'
isemon.CONFIG_FILE = work / 'config.json'
(work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite', 'otp': 1, 'otp_detail': 1}))
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'otp': 1, 'otp_detail': 1, 'geo': 0, 'api_port': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = datetime(2026, 10, 24, 14, 0, 0).timestamp()
DATA = HERE / 'otp-1.0.92'
lines = {}
for name in sorted(os.listdir(DATA)):
    lines[name] = (DATA / name).read_text(encoding='utf-8').splitlines()
# The packets first and the token lines after, as a shipper on a timer
# delivers them - and the other way round for the second server.
for rec in isemon.otp_detail_lines(lines['otp1-radius-detail.log'], now=NOW):
    daemon.take_record('otp-detail', rec)
for rec in isemon.otp_parse_lines(lines['otp1-totp.cgi.log'], now=NOW):
    daemon.take_record('otp', rec)
for rec in isemon.otp_parse_lines(lines['otp2-totp.cgi.log'], now=NOW):
    daemon.take_record('otp', rec)
for rec in isemon.otp_detail_lines(lines['otp2-radius-detail.log'], now=NOW):
    daemon.take_record('otp-detail', rec)
db = sqlite3.connect(str(isemon.DB_FILE))
db.row_factory = sqlite3.Row
ok('every token line is read: 13 let in, 7 not',
   (db.execute("SELECT COUNT(*) FROM passed WHERE kind = 'otp'").fetchone()[0],
    db.execute("SELECT COUNT(*) FROM failed WHERE kind = 'otp'").fetchone()[0]), (13, 7))
orphans = db.execute("SELECT COUNT(*) FROM otp_asked WHERE kind = 'ask' AND verdict <> '' "
                     "AND username = ''").fetchone()[0]
ok('a reply written a second after its request is one row with it, not a row of its own',
   orphans, 0)
row = db.execute("SELECT verdict, username FROM otp_asked WHERE rid = '127.0.0.1:59910'").fetchall()
ok('...the request at :37 and its accept at :38', [tuple(r) for r in row],
   [('accept', 'jnovak@example.int')])
ok('the requests otp never answered stay requests nobody answered',
   db.execute("SELECT COUNT(*) FROM otp_asked WHERE kind = 'ask' AND verdict = ''").fetchone()[0], 5)
sms = db.execute("SELECT reason FROM failed WHERE kind = 'otp' ORDER BY ts").fetchall()
ok('the refusals in the page\'s words', [r[0] for r in sms], [
    'the token was wrong', 'that token had been used already',
    'that token had been used already', 'the token was wrong',
    'the token was wrong', 'the token was wrong',
    'this account has nothing enrolled here'])
ok('...and the one typed on otp\'s enrolment page says so beside it',
   [r[0] for r in db.execute("SELECT service FROM failed WHERE kind = 'otp' ORDER BY ts")],
   ['', '', '', '', 'on the enrolment page', '', ''])
got = db.execute("SELECT subtype, service FROM passed WHERE kind = 'otp' AND subtype LIKE "
                 "'Code sent%' ORDER BY ts").fetchall()
ok('a code by SMS let in five times, kept in otp\'s own words', [tuple(r) for r in got],
   [('Code sent by SMS accepted', '')] * 5)

title('...and the page\'s joining of them')
rows = [dict(r) for r in db.execute("SELECT * FROM failed WHERE kind = 'otp' ORDER BY ts")]
near = store.otp_asked_near([(r['session'], r['server'], r['username'], r['ts'], False, '',
                              r['asked_as']) for r in rows])
wrong_sms = [r for r in rows if r['asked_as'] == '127.0.0.1:41029'][0]
facts = near.get(wrong_sms['session']) or {}
ok('a wrong code typed into the second window knows it was a code by SMS, and where to',
   (facts.get('code_by'), facts.get('code_to')), ('sms', '+420******123'))
rows = [dict(r) for r in db.execute("SELECT * FROM passed WHERE kind = 'otp' ORDER BY ts")]
near = store.otp_asked_near([(r['session'], r['server'], r['username'], r['ts'], True,
                              r['tkey'], r['asked_as']) for r in rows])
two = [r for r in rows if r['server'] == 'otp2' and r['subtype'].startswith('Code')][0]
ok('...and the question on one node and the answer on the other still meet',
   (near.get(two['session']) or {}).get('code_by'), 'sms')
plain = [r for r in rows if r['asked_as'] == '192.0.2.32:46465'][0]
ok('a code from the app with no second window has nothing of the kind',
   'code_by' in (near.get(plain['session']) or {}), False)

title('What has no token line at all')
moved = daemon.apply_radius_refusals(since=0)
moved += daemon.apply_unanswered_codes(NOW + 3600, {})
alone = db.execute("SELECT reason, code, asked_as FROM failed WHERE kind = 'otp' AND session "
                   "LIKE 'otp/radius/%' ORDER BY ts").fetchall()
ok('the refusals before any code and the code mailed and never typed are written down',
   [tuple(r) for r in alone], [
       ('refused before a code was looked at', 'before-code', '192.0.2.32:54534'),
       ('refused before a code was looked at', 'before-code', '192.0.2.32:51982'),
       ('refused before a code was looked at', 'before-code', '192.0.2.32:38973'),
       ('a code by mail was sent and never typed', 'code-unused', '192.0.2.32:53687')])
ok('...a refusal that has a token line is not written twice',
   db.execute("SELECT COUNT(*) FROM failed WHERE kind = 'otp' AND asked_as = '127.0.0.1:45026'")
   .fetchone()[0], 1)
ok('...nor is the code by SMS that was typed, right or wrong',
   db.execute("SELECT COUNT(*) FROM failed WHERE code = 'code-unused'").fetchone()[0], 1)
again = daemon.apply_radius_refusals(since=0) + daemon.apply_unanswered_codes(NOW + 3600, {})
ok('...and read again, nothing more', again, 0)
ok('none of it is ever judged: no address on any of them',
   db.execute("SELECT COUNT(*) FROM failed WHERE kind = 'otp' AND ip <> ''").fetchone()[0], 0)

title('A database written by 1.10.225, mended once')
db.execute("DELETE FROM meta WHERE key IN ('mended_otp_words', 'mended_otp_pairs')")
db.execute("UPDATE failed SET reason = 'No token is enrolled for this account' "
           "WHERE reason = 'this account has nothing enrolled here'")
# A request and its reply as 1.10.225 left them: two rows.
db.execute("INSERT INTO otp_asked (ident, ts, at, server, kind, username, ip, nas, tunnel, "
           "verdict, said, session, device, rid, detail) VALUES "
           "('otp/otpx/1792800000/4000', 1792800000, 0, 'otpx', 'ask', 'pk@example.int', '', "
           "'10.0.0.1', '', '', '', '', '', '10.0.0.1:4000', '{\"made_of\": [\"a\"]}'),"
           "('otp/otpx/1792800001/4000', 1792800001, 0, 'otpx', 'ask', '', '', '', '', "
           "'reject', '', '', '', '10.0.0.1:4000', '{\"made_of\": [\"b\"]}')")
db.commit()
ok('the words', store.mend_otp_words(), 1)
ok('...then nothing in otp\'s own words is left',
   db.execute("SELECT COUNT(*) FROM failed WHERE reason = 'No token is enrolled for this "
              "account'").fetchone()[0], 0)
ok('the halves', store.mend_otp_pairs(), 1)
ok('...one row, with both', [tuple(r) for r in db.execute(
    "SELECT ident, username, verdict FROM otp_asked WHERE server = 'otpx'")],
   [('otp/otpx/1792800000/4000', 'pk@example.int', 'reject')])
ok('...and once only', (store.mend_otp_words(), store.mend_otp_pairs()), (0, 0))

title('totpcgi, exactly as before')
OLD = [
    'Sep 24 09:35:34 otp totp.cgi[13177]: Success: user=jnovak@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Valid token used',
    'Sep 24 09:36:01 otp totp.cgi[13178]: Failure: user=pkolar@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Not a valid token',
    'Sep 24 09:37:00 otpsec totp.cgi[901]: Failure: user=edvorak@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=pincodes file not found!',
]
for rec in isemon.otp_parse_lines(OLD, now=NOW):
    daemon.take_record('otp', rec)
got = [tuple(r) for r in db.execute(
    "SELECT username, reason FROM failed WHERE kind = 'otp' AND server IN ('otp', 'otpsec') "
    'ORDER BY ts')]
ok('the same words for the same lines', got,
   [('pkolar', 'the token was wrong'), ('edvorak', 'this account has nothing enrolled here')])
ok('...and a sign-in nothing more than it was',
   [tuple(r) for r in db.execute("SELECT subtype, service FROM passed WHERE server = 'otp'")],
   [('Valid token used', '')])
FR = [
    # FreeRADIUS in front of totpcgi, the request and its reply in one second.
    'Sep 24 09:36:01 otp radius-detail[1682]: nas=172.22.0.137 '
    'file=auth-detail-20260924 ts=[Thu Sep 24 09:35:34 2026] '
    'Packet-Type = Access-Request, Packet-Src-IP-Address = 172.22.0.137, '
    'Packet-Src-Port = 48603, User-Name := "jnovak@example.int", '
    'Calling-Station-Id = "203.0.113.9"',
    'Sep 24 09:36:01 otp radius-detail[1682]: nas=172.22.0.137 '
    'file=reply-detail-20260924 ts=[Thu Sep 24 09:35:34 2026] '
    'Packet-Type = Access-Accept, Packet-Dst-IP-Address = 172.22.0.137, Packet-Dst-Port = 48603',
]
for rec in isemon.otp_detail_lines(FR, now=NOW):
    daemon.take_record('otp-detail', rec)
ok('FreeRADIUS\'s request and reply in one second, one row as always', [tuple(r) for r in db.execute(
    "SELECT ident, username, verdict, ip FROM otp_asked WHERE server = 'otp'")],
   [('otp/otp/%d/48603' % int(isemon.otp_detail_lines(FR[:1], now=NOW)[0].ts),
     'jnovak@example.int', 'accept', '203.0.113.9')])

title('The chosen hour across the night summer time ends')
os.environ['TZ'] = 'Europe/Prague'
time.tzset()
isemon.CONFIG.update({'update_when': 'at_time', 'update_at': '03:30'})
real_time = time.time
try:
    # 24 October 2026, 13:45 in Prague: tomorrow is 25 hours long.
    time.time = lambda: datetime(2026, 10, 24, 13, 45).timestamp()
    when = time.localtime(daemon.update_next(time.time() - 40 * 86400, 30 * 86400))
    ok('something monthly and due waits for 03:30 tomorrow, not 02:30',
       (when.tm_mday, when.tm_hour, when.tm_min), (25, 3, 30))
    time.time = lambda: datetime(2026, 3, 28, 13, 45).timestamp()
    when = time.localtime(daemon.update_next(time.time() - 40 * 86400, 30 * 86400))
    ok('...nor 04:30 the night it starts', (when.tm_mday, when.tm_hour, when.tm_min), (29, 3, 30))
finally:
    time.time = real_time

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
