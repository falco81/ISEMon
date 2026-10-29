#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eduroam.py - the visitors' network, which is a different RADIUS server
writing a different log, and the proof that it is read as what it is.

Four things are at stake here and each of them is somebody's afternoon:

  * a refusal is one refusal. FreeRADIUS writes two lines about it and a
    reader that takes both doubles every number on the page.
  * a login is one login. The line written when the identity inside the EAP
    tunnel checks out is not a second person signing in.
  * a password is never kept. FreeRADIUS writes what was offered on a
    refusal - `[somebody/hunter2]` - and none of it may reach a row, a
    record or a log this program writes.
  * nothing here is ever judged. The only address on one of these lines is
    the wireless controller the request came through, and banning it would
    take the whole of eduroam off the air.

The lines below are the real shapes, as the installation this was written
against actually writes them.

    ./test/eduroam.py
"""
import shutil
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


def title(words):
    print('\n%s' % words)


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-edu-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'edu.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'edu.log'
    isemon.CONFIG.update({
        'blacklist': 1, 'block_mode': 'temporary', 'block_tries': 3,
        'block_window_min': 60, 'block_lots': 0, 'block_bogus_tries': 0,
        'block_ladder': '15, 60, forever', 'feeds_ban': 0, 'geo': 0,
        'mikrotik_host': '', 'watch_devices': '', 'passed_devices': '',
        'never_block': '', 'never_block_countries': '', 'read_passed': 1,
        'judge_max_age_h': 0, 'debug': False,
        'eduroam': 1, 'eduroam_ignore': '', 'ise_paths': [str(Path(folder) / 'nothing')],
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    return folder, store, daemon


# One day of a real server, cut down to one of everything it writes.
LOG = """\
Sep 24 23:52:42 edurad1 radius: Thu Sep 24 23:52:42 2026 : Auth: (10550972) Invalid user: \
[testaccount/cisco] (from client wlc9800 port 0)
Sep 24 23:52:42 edurad1 radius: Thu Sep 24 23:52:42 2026 : Auth: (10550972) Login incorrect: \
[testaccount/cisco] (from client wlc9800 port 0)
Sep 24 23:53:11 edurad1 radius: Thu Sep 24 23:53:11 2026 : Auth: (10550986)   Login OK: \
[69824@example.cz/<via Auth-Type = eap>] (from client wlc9800 port 0 via TLS tunnel)
Sep 24 23:53:11 edurad1 radius: Thu Sep 24 23:53:11 2026 : Auth: (10550987) Login OK: \
[69824@example.cz/<via Auth-Type = eap>] (from client wlc9800 port 2915 cli 36-C3-21-CD-1A-94)
Sep 24 23:53:58 edurad1 radius: Thu Sep 24 23:53:58 2026 : Auth: (10551029) Login incorrect \
(Home Server says so): [status@flr.eduroam.cz/<no User-Password attribute>] (from client \
monitoring port 0 cli 70-6F-6C-6F-FF-FC)
Sep 24 23:53:58 edurad1 radius: Thu Sep 24 23:53:58 2026 : Auth: (10551029) Login incorrect: \
[status@flr.eduroam.cz/<no User-Password attribute>] (from client monitoring port 0 cli \
70-6F-6C-6F-FF-FC)
Sep 24 23:54:08 edurad1 radius: Thu Sep 24 23:54:08 2026 : Info:  ... shutting down socket \
auth+acct from client (78.128.248.10, 39825) -> (*, 2083, virtual-server=default)
Sep 24 23:54:20 edurad1 radius: Thu Sep 24 23:54:20 2026 : Auth: (10551069) Login OK: \
[jk@hf.jamu.cz/<via Auth-Type = Accept>] (from client wlc5500 port 2915 cli AA-8D-16-FE-5D-E0)
Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (10551100) Login incorrect: \
[somebody@example.cz/hunter2] (from client wlc9800 port 2915 cli DE-18-C7-2E-5D-C6)
"""

# One accounting record, as the controller sends it: this is where
# everything worth knowing about the session actually is.
DETAIL = """\
Thu Sep 24 23:53:12 2026
\tCisco-AVPair = "dc-device-name=iPhone"
\tCisco-AVPair = "dc-profile-name=Un-Classified Device"
\tFramed-IP-Address = 172.25.113.54
\tUser-Name = "69824@example.cz"
\tCisco-AVPair = "vlan-id=1111"
\tCisco-AVPair = "method=dot1x"
\tCalled-Station-Id = "AP_24-W60:eduroam"
\tCalling-Station-Id = "36-C3-21-CD-1A-94"
\tNAS-IP-Address = 172.21.8.10
\tNAS-Port-Type = Wireless-802.11
\tNAS-Identifier = "wlc9800"
\tAcct-Status-Type = Start
\tStripped-User-Name = "69824"
\tRealm = "example.cz"
\tTimestamp = 1790286792

Thu Sep 24 23:52:41 2026
\tUser-Name = "testaccount"
\tAcct-Status-Type = Interim-Update
\tNAS-IP-Address = 172.21.8.10
\tRealm = "NULL"
\tTimestamp = 1790286761

"""


def lay_out(folder, log=LOG, detail=DETAIL):
    """A server's folder, as FreeRADIUS leaves it."""
    where = Path(folder) / 'edurad1'
    where.mkdir(parents=True, exist_ok=True)
    (where / 'radius.log').write_text(log, encoding='utf-8')
    (where / 'detail-20260924').write_text(detail, encoding='utf-8')
    isemon.CONFIG['eduroam_paths'] = [str(where)]
    return where


folder, store, daemon = fresh()
where = lay_out(folder)

title('Which files are read, and what is in each')
files = [(kind, Path(path).name) for kind, path, _s in daemon.log_files() if 'edu' in str(_s)]
ok('both of them, the sign-ins and the sessions',
   files, [('eduroam', 'radius.log'), ('eduroam-detail', 'detail-20260924')])
isemon.CONFIG['eduroam'] = 0
ok('...and switched off, neither',
   [f for f in daemon.log_files() if 'edu' in str(f[2])], [])
isemon.CONFIG['eduroam'] = 1
ok('the accounting file is found by what it is named after, not by its whole name',
   Path(isemon.Daemon.newest_detail(str(where), 'detail-')).name, 'detail-20260924')
(where / 'detail-20260925').write_text('', encoding='utf-8')
ok('...and when the day rolls over, the new one is the one followed',
   Path(isemon.Daemon.newest_detail(str(where), 'detail-')).name, 'detail-20260925')
(where / 'detail-20260925').unlink()

title('One authentication is one record')
daemon.read_logs()
counts = {k: v for k, v in store.failed_counts().items() if v}
ok('every refusal is written down once, not once a line',
   counts, {'eduroam': 3})
ok('...and every login once, not once for the tunnel and once for itself',
   {k: v for k, v in store.passed_counts().items() if v}, {'eduroam': 2})
ok('reading the whole of it again adds nothing', daemon.read_logs(), 0)

title('What a refusal says')
rows = store.failed_rows(kind='eduroam')[0]
said = {r['username']: r for r in rows}
ok('a name nobody here has ever heard of says so',
   said['testaccount']['reason'], 'no such account here')
ok('...and a name from somewhere else that was refused there says that instead',
   said['status@flr.eduroam.cz']['reason'], 'the home institution refused it')
ok('...and a password that was simply wrong says that',
   said['somebody@example.cz']['reason'], 'the password was wrong')
ok('the institution is kept beside the name, because on eduroam that is the point',
   [said['status@flr.eduroam.cz']['realm'], said['somebody@example.cz']['realm']],
   ['flr.eduroam.cz', 'example.cz'])
ok('the machine is kept where the line named it',
   said['somebody@example.cz']['mac'], 'DE-18-C7-2E-5D-C6')
ok('...and the controller it came through is the device',
   said['somebody@example.cz']['device'], 'wlc9800')

title('The password it was refused for is never kept')
whole = ' '.join(str(dict(r)) for r in rows)
ok('not in the row', 'hunter2' in whole, False)
ok('...nor in the record kept beside it',
   'hunter2' in str(store.unpack_detail(
       store.db.execute("SELECT detail FROM failed WHERE username = ?",
                        ('somebody@example.cz',)).fetchone()['detail'])), False)
ok('...and what was offered is still said, without saying what it was',
   isemon.ise_first({'Asked with': ['via Auth-Type = eap']}, 'Asked with'),
   'via Auth-Type = eap')

title('Nothing here is ever judged')
ok('no address is taken off one of these lines at all',
   [r['ip'] or '' for r in rows], ['', '', ''])
ok('...so nothing was banned', store.blocked_all(), [])
ok('...and the door is not the one the banning weighs',
   [r['kind'] for r in rows], ['eduroam', 'eduroam', 'eduroam'])

title('Where the machine actually was comes from the accounting')
seen = store.eduroam_seen(['36-C3-21-CD-1A-94'])
one = seen.get('36-C3-21-CD-1A-94') or {}
ok('the access point that heard it', one.get('ap'), 'AP_24-W60')
ok('...the network it joined', one.get('ssid'), 'eduroam')
ok('...the VLAN it was put in', one.get('vlan'), '1111')
ok('...the address it was given', one.get('client'), '172.25.113.54')
ok('...the controller that answered for it', one.get('device'), 'wlc9800')
ok('...and what the machine calls itself', one.get('calls_itself'), 'iPhone')
ok('a machine nobody has an accounting record for is simply not known',
   store.eduroam_seen(['DE-18-C7-2E-5D-C6']), {})
ok('"Unknown" is not the name of anything and is not kept as one',
   isemon.edu_session_facts({'cisco-av-pair': ['dc-device-name=Unknown'],
                             'Calling-Station-ID': ['AA-BB-CC-DD-EE-FF']})['calls_itself'], '')
ok('...and NULL is not the name of an institution',
   isemon.edu_session_facts({'Realm': ['NULL'], 'User-Name': ['x'],
                             'Calling-Station-ID': ['AA-BB-CC-DD-EE-FF']})['realm'], '')
ok('an accounting record is never a row of its own',
   store.passed_rows(kind='eduroam')[1], 2)
ok('...and an older one arriving after a newer one does not undo it',
   store.note_eduroam_session({'mac': '36-C3-21-CD-1A-94', 'ap': 'somewhere else',
                               'ts': 1}), False)
ok('...the newest is still what is known',
   (store.eduroam_seen(['36-C3-21-CD-1A-94']).get('36-C3-21-CD-1A-94') or {}).get('ap'),
   'AP_24-W60')

title('A login is joined to its session by the machine, when the page is drawn')
rows = store.passed_rows(kind='eduroam')[0]
joined = store.eduroam_seen([r['mac'] for r in rows])
ok('the one with an accounting record knows where it was',
   bool(joined.get('36-C3-21-CD-1A-94')), True)
ok('...and the one without says nothing rather than something wrong',
   bool(joined.get('AA-8D-16-FE-5D-E0')), False)

title('The accounts nobody wants to see')
ok('a name on the list is left out', isemon.edu_ignored('testaccount', 'testaccount'), True)
ok('...with its realm on it as well', isemon.edu_ignored('testaccount@x.cz', 'testaccount'),
   True)
ok('...and however it was typed', isemon.edu_ignored('TestAccount', ' testaccount '), True)
ok('...and a list of several', isemon.edu_ignored('probe', 'testaccount, probe, monitor'),
   True)
ok('a name that is not on it is not', isemon.edu_ignored('jnovak@example.cz', 'testaccount'),
   False)
ok('...and a name that merely starts the same is not either',
   isemon.edu_ignored('testaccountant', 'testaccount'), False)
ok('nothing on the list leaves everybody in', isemon.edu_ignored('anybody', ''), False)

title('A sorting that changed does not turn these into something else')
store.set_meta('passed_sorted', '0')
store.set_meta('failed_sorted', '0')
store.fill_in_kinds()
store.fill_in_failed_kinds()
ok('the logins are still eduroam logins',
   {k: v for k, v in store.passed_counts().items() if v}, {'eduroam': 2})
ok('...and the refusals still eduroam refusals',
   {k: v for k, v in store.failed_counts().items() if v}, {'eduroam': 3})
ok('...with what the server said about each of them kept',
   sorted({r['reason'] for r in store.failed_rows(kind='eduroam')[0]}),
   ['no such account here', 'the home institution refused it', 'the password was wrong'])
ok('...and the institution kept as well',
   sorted({r['realm'] or '' for r in store.failed_rows(kind='eduroam')[0]}),
   ['', 'example.cz', 'flr.eduroam.cz'])

# A second installation, with the same logs and one setting different.
# On the file engine that is a second file; on a database server there is
# one database, and the two would be the same installation wearing two
# names - which is the one thing this whole program refuses elsewhere. So
# the first one is put away before the second is made.
try:
    daemon.stop()
except Exception:
    pass
store.close()
folder2, store2, daemon2 = fresh()
lay_out(folder2)
isemon.CONFIG['eduroam_ignore'] = 'testaccount'
daemon2.read_logs()
ok('switched on, that account is in no table anywhere',
   store2.db.execute("SELECT COUNT(*) AS n FROM failed WHERE username LIKE '%testaccount%'"
                     ).fetchone()['n'], 0)
ok('...not in the counts either',
   {k: v for k, v in store2.failed_counts().items() if v}, {'eduroam': 2})
ok('...and not among the machines that are remembered',
   store2.db.execute("SELECT COUNT(*) AS n FROM eduroam_seen WHERE account LIKE "
                     "'%testaccount%'").fetchone()['n'], 0)
isemon.CONFIG['eduroam_ignore'] = ''

title('The lines that are not authentications')
ok('a socket being opened and closed is not somebody signing in',
   isemon.edu_parse_lines([
       'Sep 24 23:54:08 edurad1 radius: Thu Sep 24 23:54:08 2026 : Info:  ... shutting down '
       'socket auth+acct from client (78.128.248.10, 39825) -> (*, 2083)']), [])
ok('...nor is a line from something else entirely',
   isemon.edu_parse_lines(['Sep 24 23:54:08 edurad1 sshd[1]: Accepted publickey for root']),
   [])
ok('an empty file is an empty list', isemon.edu_parse_lines([]), [])
ok('...and so is a file of nothing but blank lines',
   isemon.edu_parse_lines(['', '   ', '']), [])

title('A record cut in half by the reading is still one record')
lines = LOG.splitlines()
hold = {}
first = isemon.edu_parse_lines(lines[:5], hold)
second = isemon.edu_parse_lines(lines[5:], hold)
ok('the pair split across two reads is written down under one name',
   len({r.session for r in first + second}), len(first) + len(second) - 1)
blocks = []
hold2 = {}
half = DETAIL.splitlines()
blocks += isemon.edu_detail_blocks(half[:6], hold2)
blocks += isemon.edu_detail_blocks(half[6:], hold2)
ok('...and an accounting record split down the middle keeps all of itself',
   isemon.ise_first(blocks[0], 'Calling-Station-ID'), '36-C3-21-CD-1A-94')

title('A file this daemon may not read says so in words')
said = isemon.trouble_words('[Errno 13] Permission denied', str(where / 'detail-20260924'))
ok('the error is turned into the thing that is actually wrong',
   'may not read that file' in said, True)
fix = isemon.trouble_fix('[Errno 13] Permission denied', str(where / 'detail-20260924'))
ok('...and the command that ends it reaches a file not called .log',
   fix.startswith('chgrp -R') and 'find' in fix, True)

title('Searching a list of machines by what is on it')
ok('a name with an institution on the end of it',
   store.passed_rows(kind='eduroam', text='hf.jamu.cz')[1], 1)
ok('...the institution on its own',
   store.failed_rows(kind='eduroam', text='example.cz')[1], 1)
ok('...and a MAC', store.passed_rows(kind='eduroam', text='36-C3-21-CD-1A-94')[1], 1)
ok('...and that search is not made of the lists it means nothing on',
   store.passed_rows(kind='vpn', text='hf.jamu.cz')[1], 0)

title('What the review found, held so it cannot come back')
ok('a MAC written with colons is the same machine as one written with dashes',
   [isemon.mac_written('36:C3:21:CD:1A:94'), isemon.mac_written('36c3.21cd.1a94'),
    isemon.mac_written('36-c3-21-cd-1a-94'), isemon.mac_written('36C321CD1A94')],
   ['36-C3-21-CD-1A-94'] * 4)
ok('...and nothing else is a MAC at all',
   [isemon.mac_written('172.29.2.34'), isemon.mac_written(''),
    isemon.mac_written('AP_24-W60:eduroam'), isemon.mac_written('36-C3-21-CD-1A')],
   ['', '', '', ''])
ok('an accounting record whose controller writes colons still joins to its sign-in',
   isemon.edu_session_facts({'Calling-Station-ID': ['36:C3:21:CD:1A:94'],
                             'User-Name': ['x@y.cz']})['mac'], '36-C3-21-CD-1A-94')

title('A password with a slash in it is still a password')
slashed = isemon.edu_parse_lines([
    'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (11) Login incorrect: '
    '[jan@example.cz/hun/ter2] (from client wlc9800 port 0)'])
ok('the name is cut at the first slash, not the last',
   slashed[0].user, 'jan@example.cz')
ok('...so no part of it reaches the institution either',
   isemon.ise_first(slashed[0].fields, 'Realm'), 'example.cz')
ok('...nor anything else in the record',
   [bit in str(dict(slashed[0].fields)) for bit in ('hun', 'ter2')], [False, False])
angled = isemon.edu_parse_lines([
    'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (12) Login incorrect: '
    '[jan@example.cz/<mysecret>] (from client wlc9800 port 0)'])
ok('a password typed in angle brackets is not mistaken for what FreeRADIUS writes there',
   isemon.ise_first(angled[0].fields, 'Asked with'), '')
ok('...while what FreeRADIUS does write there is still kept',
   [isemon.ise_first(r.fields, 'Asked with') for r in isemon.edu_parse_lines([
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (13) Login OK: '
       '[a@b.cz/<via Auth-Type = eap>] (from client wlc9800 port 0 cli 00-11-22-33-44-55)',
       'Sep 24 23:55:32 edurad1 radius: Thu Sep 24 23:55:32 2026 : Auth: (14) Login incorrect: '
       '[c@d.cz/<no User-Password attribute>] (from client monitoring port 0)'])],
   ['eap', 'no User-Password attribute'])

title('A request number that comes round again is not the same request')
mixed = isemon.edu_parse_lines([
    'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (5) Login OK: '
    '[alice@a.cz/<via Auth-Type = eap>] (from client wlc9800 port 0 cli 00-11-22-33-44-55)',
    'Sep 24 23:55:32 edurad1 radius: Thu Sep 24 23:55:32 2026 : Auth: (6) Login OK: '
    '[bob@b.cz/<via Auth-Type = eap>] (from client wlc9800 port 0 cli 00-11-22-33-44-66)',
    'Sep 24 23:55:33 edurad1 radius: Thu Sep 24 23:55:33 2026 : Auth: (5) Login incorrect: '
    '[carol@c.cz/x] (from client wlc9800 port 0)'])
ok('a server that restarted and began numbering again keeps everybody',
   sorted(r.user for r in mixed), ['alice@a.cz', 'bob@b.cz', 'carol@c.cz'])
ok('...and nobody is given somebody else\u2019s words',
   isemon.ise_first([r for r in mixed if r.user == 'carol@c.cz'][0].fields, 'Also said'), '')
ok('two servers that number their requests the same are not one server',
   len(isemon.edu_parse_lines([
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (9) Login incorrect: '
       '[a@x.cz/p] (from client wlc9800 port 0)',
       'Sep 24 23:55:31 edurad2 radius: Thu Sep 24 23:55:31 2026 : Auth: (9) Login incorrect: '
       '[a@x.cz/p] (from client wlc9800 port 0)'])), 2)
ok('a refusal written without a request number at all is still one refusal',
   len(isemon.edu_parse_lines([
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: Invalid user: '
       '[nobody/p] (from client wlc9800 port 0)',
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: Login incorrect: '
       '[nobody/p] (from client wlc9800 port 0)'])), 1)

title('The accounting file that is followed is the live one')
import os as _os
for name in ('detail-20260923.gz', 'detail-20260924.gz', 'detail-20260924.work',
             'detail-20260924.1'):
    (where / name).write_text('', encoding='utf-8')
ok('a rotated copy is not read instead of the file being written',
   Path(isemon.Daemon.newest_detail(str(where), 'detail-')).name, 'detail-20260924')
for name in ('detail-20260923.gz', 'detail-20260924.gz', 'detail-20260924.work',
             'detail-20260924.1'):
    (where / name).unlink()

title('The last record in a file does not wait for the next one')
blocks = isemon.edu_detail_blocks(DETAIL.splitlines())
ok('a record ended by a blank line is handed over at once', len(blocks), 2)
ok('...and one still being written is held until it is finished',
   len(isemon.edu_detail_blocks(DETAIL.splitlines()[:8])), 0)

title('A name on the ignore list is that name and not another institution\u2019s')
ok('an entry with an institution on it means that account only',
   [isemon.edu_ignored('probe@ours.cz', 'probe@ours.cz'),
    isemon.edu_ignored('probe@somewhere.else', 'probe@ours.cz')], [True, False])
ok('...while an entry without one means the name wherever it signs in from',
   [isemon.edu_ignored('probe', 'probe'), isemon.edu_ignored('probe@anywhere.cz', 'probe')],
   [True, True])

title('A database restored from before this table existed mends itself')
store.db.execute('DROP TABLE eduroam_seen')
store.db.commit()
ok('writing to it says so rather than raising',
   store.note_eduroam_session({'mac': '00-11-22-33-44-55', 'ts': 2}), False)
ok('...and reading it answers nothing rather than raising',
   store.eduroam_seen(['00-11-22-33-44-55']), {})
store.mend()
ok('...and mending brings the table back',
   store.note_eduroam_session({'mac': '00-11-22-33-44-55', 'ap': 'AP_1', 'ts': 2}), True)


title('...and what the second reading found')
def one_line(ident, verdict, who, when='23:55:31', host='edurad1'):
    return ('Sep 24 %s %s radius: Thu Sep 24 %s 2026 : Auth: %s%s: [%s] '
            '(from client wlc9800 port 0)'
            % (when, host, when, ('(%s) ' % ident) if ident else '', verdict, who))

ok('a log with no request numbers keeps every try, not one of them',
   len(isemon.edu_parse_lines([one_line('', 'Login incorrect', 'admin@x.cz/p',
                                        '23:5%d:11' % n) for n in range(5)])), 5)
ok('...while the pair written about one of them is still one refusal',
   len(isemon.edu_parse_lines([one_line('', 'Invalid user', 'admin@x.cz/p'),
                               one_line('', 'Login incorrect', 'admin@x.cz/p')])), 1)
ok('...and two tries in the same second are two tries',
   len(isemon.edu_parse_lines([one_line('', 'Login incorrect', 'admin@x.cz/p'),
                               one_line('', 'Login incorrect', 'admin@x.cz/p')])), 2)

title('A machine is not an account called host')
mach = isemon.edu_parse_lines([
    'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (21) Login OK: '
    '[host/PC1234.example.int@example.int/<via Auth-Type = eap>] (from client wlc9800 '
    'port 2915 cli 00-11-22-33-44-55)'])
ok('a Windows machine keeps the whole of what it called itself',
   mach[0].user, 'host/PC1234.example.int@example.int')
ok('...and the institution with it', isemon.ise_first(mach[0].fields, 'Realm'), 'example.int')
ok('a person whose password had a slash in it still keeps their institution',
   isemon.ise_first(isemon.edu_parse_lines([
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (22) Login '
       'incorrect: [jan@example.cz/hun/ter] (from client wlc9800 port 0)'])[0].fields,
       'Realm'), 'example.cz')
ok('what FreeRADIUS writes where a password would be is kept, whichever of them it is',
   [isemon.ise_first(r.fields, 'Asked with') for r in isemon.edu_parse_lines([
       'Sep 24 23:55:31 edurad1 radius: Thu Sep 24 23:55:31 2026 : Auth: (23) Login '
       'incorrect: [a@b.cz/<CHAP-Password>] (from client wlc9800 port 0)',
       'Sep 24 23:55:32 edurad1 radius: Thu Sep 24 23:55:32 2026 : Auth: (24) Login '
       'incorrect: [c@d.cz/<hunter2>] (from client wlc9800 port 0)'])],
   ['CHAP-Password', ''])

title('The machines are looked up however the controller spells them')
store.note_eduroam_session({'mac': '36:C3:21:CD:1A:94', 'ap': 'AP_spelled', 'ts': 9e9})
ok('a MAC written with colons is stored as the one shape',
   (store.eduroam_seen(['36-C3-21-CD-1A-94']).get('36-C3-21-CD-1A-94') or {}).get('ap'),
   'AP_spelled')
ok('...and asked for in any of them', sorted(store.eduroam_seen(
   ['36:C3:21:CD:1A:94', '36c3.21cd.1a94']).keys()), ['36-C3-21-CD-1A-94'])

title('A database restored from an older version is put through this version\u2019s rules')
import sqlite3 as _sq
older = store.backup(label='for-the-test')
old = _sq.connect(str(older))
old.execute("UPDATE failed SET kind = NULL")
old.execute("UPDATE meta SET value = '1' WHERE key IN ('failed_sorted','passed_sorted')")
old.commit(); old.close()
isemon.Storage.LATER = True
store.restore(str(older))
ok('every row it brought in has had its door worked out',
   store.db.execute('SELECT COUNT(*) AS n FROM failed WHERE kind IS NULL').fetchone()['n'], 0)
ok('...and the database says which rule it was put through',
   store.get_meta('failed_sorted'), str(isemon.Storage.SORT_VERSION))
isemon.Storage.LATER = False

title('Rows with no door at all are never left for later')
isemon.Storage.LATER = True
store.db.execute("UPDATE failed SET kind = NULL WHERE kind = 'eduroam'")
store.db.commit()
store.set_meta('failed_sorted', '1')
store.mend()
ok('opening the database fills those in before anything counts them',
   store.db.execute('SELECT COUNT(*) AS n FROM failed WHERE kind IS NULL').fetchone()['n'], 0)
ok('...without claiming the whole table has been put through this version',
   store.get_meta('failed_sorted'), '1')
store.catch_up()
ok('...which is what the catching up behind the page is for',
   store.get_meta('failed_sorted'), str(isemon.Storage.SORT_VERSION))
isemon.Storage.LATER = False

title('eduroam is its own band on the front page, never the VPN\u2019s')
when = time.time() - 600
SYSLOG = time.strftime('%b %d %H:%M:%S', time.localtime(when))
FREERAD = time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(when))
for n in range(9):
    daemon.read_records(
        ['%s edurad1 radius: %s : Auth: (%d) Login OK: '
         '[visitor%d@far.away.cz/<via Auth-Type = eap>] (from client wlc9800 port 2915 '
         'cli 00-11-22-33-44-%02d)' % (SYSLOG, FREERAD, 9000 + n, n, n)], kind='eduroam')
bars = [b for b in store.auth_counts(hours=2, step=3600) if b['passed'] or b['failed']]
drawn = sum(b['passed'] - b['passed_tacacs'] - b['passed_network'] - b['passed_otp']
            - b['passed_eduroam'] for b in bars)
ok('the logins are counted under eduroam', sum(b['passed_eduroam'] for b in bars), 9)
ok('...and not one of them is drawn as a VPN login', drawn, 0)
ok('...while the bar is still as tall as the hour really was',
   sum(b['passed'] for b in bars), 9)
ok('a refusal is an attempt in its own band, not "not an attempt"',
   [sum(b['failed_eduroam'] for b in bars), sum(b['failed_other'] for b in bars)], [0, 0])

title('Nothing eduroam does can ever earn anybody a ban')
before = len(store.blocked_all())
flood = []
for n in range(40):
    flood.append('Sep 24 23:5%d:%02d edurad1 radius: Thu Sep 24 23:5%d:%02d 2026 : Auth: '
                 '(%d) Login incorrect: [victim@somewhere.cz/p] (from client wlc9800 port 0 '
                 'cli 00-11-22-33-44-55)' % (n // 10, n % 60, n // 10, n % 60, 8000 + n))
daemon.read_records(flood, kind='eduroam')
ok('forty refusals in a row ban nobody', len(store.blocked_all()), before)
ok('...nor does the pass that goes back over every log see one of them',
   len([r for r in store.failed_for_judging() if not r.get('ip')]), 0)
ok('...because such a record carries no address at all',
   {r['ip'] or '' for r in store.failed_rows(kind='eduroam')[0]}, {''})
ok('...and the busiest addresses are still only the VPN\u2019s',
   [r for r in store.top_attackers(since=0, limit=50) if not r['ip']], [])
ok('...as are the names being tried',
   [r for r in store.top_users(since=0, limit=50) if '@somewhere.cz' in (r['username'] or '')],
   [])

shutil.rmtree(folder, ignore_errors=True)
shutil.rmtree(folder2, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
