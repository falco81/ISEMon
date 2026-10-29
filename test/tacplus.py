#!/usr/bin/env python3
"""A TACACS+ daemon of the site's own, read the way this program reads it.

Not every site puts its switches behind ISE. `tac_plus` - Shrubbery's, and
the `tac_plus-ng` that came after it - is a daemon a site runs itself, and
where one is in front of the network gear it holds what the TACACS tab holds
about ISE: who signed in to which switch, from where, and every command they
ran once they were in.

The lines below are real ones, out of a log a site sent: 251,533 of them,
five years of three accounts on eighteen switches, and every single one a
command. That is the shape of the difficulty. tac_plus writes nothing at all
about sessions on most installations, so the sitting a command belongs to
has to be read out of the commands themselves - which is what a person
reading down the log does, and which has to come out the same way twice or
the same session is drawn as two.

Nothing here is ever judged and nothing here can earn anybody a ban.

    ./test/tacplus.py
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

# The lines below were written in Prague and some of them carry no zone, so
# the suite is run where they were written - not wherever the machine
# running it happens to be (a test box in UTC read them two hours out).
os.environ['TZ'] = 'Europe/Prague'
time.tzset()

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

DAEMON_SRC = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

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
    folder = tempfile.mkdtemp(prefix='isemon-tacplus-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'tac.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'tac.log'
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
        'ise': 0, 'ise_paths': [str(Path(folder) / 'nothing')],
        'winsec': 0, 'otp': 0, 'eduroam': 0,
        'tacplus': 1, 'tacplus_paths': [str(Path(folder) / 'tacsrv')],
        'tacplus_name': 'tac_acct.log', 'tacplus_said_name': 'tac_plus.log',
        'tacplus_gap_min': 30,
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    return folder, store, daemon


# Real lines, tabs and all. The first is the oldest in the log this was
# written against; the rest are the shapes that differ from it - no
# `start_time`, the web interface with its two extra fields, a device that
# sends an `addr` of its own, and a session opened by the switch itself
# rather than by a person.
T = '\t'
ACCT = [
    'Sep 16 11:56:52' + T + '192.9.212.254' + T + 'admin' + T + 'tty1' + T
    + '10.10.10.9' + T + 'stop' + T + 'task_id=9947' + T + 'timezone=UTC' + T
    + 'service=shell' + T + 'start_time=1631786213' + T + 'priv-lvl=15' + T
    + 'cmd=configure terminal <cr>',
    'Sep 16 11:56:55' + T + '192.9.212.254' + T + 'admin' + T + 'tty1' + T
    + '10.10.10.9' + T + 'stop' + T + 'task_id=9948' + T + 'timezone=UTC' + T
    + 'service=shell' + T + 'start_time=1631786215' + T + 'priv-lvl=0' + T
    + 'cmd=end <cr>',
    'Sep 17 11:17:52' + T + '192.9.211.238' + T + 'admin' + T + 'tty1' + T
    + '10.10.10.9' + T + 'stop' + T + 'task_id=414' + T + 'timezone=UTC' + T
    + 'service=shell' + T + 'priv-lvl=15' + T + 'cmd=archive <cr>',
    'Jan 29 08:59:35' + T + '192.9.211.198' + T + 'admin' + T + 'webui_port' + T
    + '192.9.220.153' + T + 'stop' + T + 'task_id=22773' + T + 'timezone=CET' + T
    + 'service=shell' + T + 'priv-lvl=15' + T + 'authen-method=6' + T
    + 'aaa-authen-service=1' + T + 'cmd=wlan VLAN236_Internet 3 DPMO_Host',
    'Dec 21 10:14:06' + T + '192.9.211.200' + T + 'admin' + T + 'unknown' + T
    + '192.9.220.153' + T + 'stop' + T + 'task_id=4963' + T + 'service=shell' + T
    + 'priv-lvl=249' + T + 'cmd=ap name AP_Diagnostika_Plocha 24-W51' + T
    + 'addr=192.9.220.153',
    'Sep 29 14:24:23' + T + '192.9.211.221' + T + 'callhome' + T + 'tty2' + T
    + 'EEM:callhome' + T + 'stop' + T + 'task_id=12182' + T + 'timezone=Prague' + T
    + 'service=shell' + T + 'start_time=1790684657' + T + 'priv-lvl=15' + T
    + 'cmd=dir crashinfo: <cr>',
]
# ...and the daemon's own log, which is the only place a refusal is written.
SAID = [
    "Sep 29 09:14:02 tacsrv tac_plus[2461]: login query for 'jnovak' tty2 from "
    '10.10.10.9 rejected',
    "Sep 29 09:14:31 tacsrv tac_plus[2461]: login query for 'jnovak' tty2 from "
    '10.10.10.9 accepted',
    'Sep 29 10:02:11 tacsrv tac_plus[2461]: login failure: admin 192.9.211.198 '
    '(192.9.220.153) tty1',
    "Sep 29 10:47:55 tacsrv tac_plus[2461]: authorization query for 'dpmo' tty1 "
    'from 192.9.220.153 rejected',
    'Sep 29 11:03:19 tacsrv tac_plus[2461]: connect from 192.9.211.198 '
    '[192.9.211.198]',
    'Sep 29 11:03:20 tacsrv tac_plus[2461]: Reading config file /etc/tac_plus.conf',
    "Sep 29 12:20:44 tacsrv tac_plus[2461]: Authentication failed for 'svc-backup' "
    'from 10.20.0.7',
]

# ---------------------------------------------------------------------------
title('One line of the accounting log, taken apart')
got = isemon.tacplus_record_from(ACCT[0])
ok('it is a record at all', got is not None)
ok('...whose account is the person', got.user, 'admin')
ok('...whose address is where they came from, not the switch', got.ip, '10.10.10.9')
ok('...and the switch is the device', isemon.ise_first(got.fields, 'Device'),
   '192.9.212.254')
ok('the command is what they typed', got.command, 'configure terminal')
ok('...without the terminator the device sends',
   '<cr>' in got.command, False)
ok('the line of the device is kept', isemon.ise_first(got.fields, 'Port'), 'tty1')
ok('...and so is what they were allowed to be',
   isemon.ise_first(got.fields, 'Privilege'), '15')
# `start_time` is seconds since the epoch, and it is the only part of the
# line that cannot be a year or a zone out.
ok('the moment is the one the device sent', int(got.ts), 1631786213)
ok('...which is 2021, not this year',
   time.strftime('%Y', time.localtime(got.ts)), '2021')

# ---------------------------------------------------------------------------
title('The shapes that are not that one')
got = isemon.tacplus_record_from(ACCT[3])
ok('the web interface is a line of the device like any other',
   isemon.ise_first(got.fields, 'Port'), 'webui_port')
ok('...and how they signed in is said in words rather than as a number',
   isemon.ise_first(got.fields, 'How they signed in'), 'TACACS+')
ok('a command with spaces in it is one command',
   got.command, 'wlan VLAN236_Internet 3 DPMO_Host')
got = isemon.tacplus_record_from(ACCT[4])
ok('a device that sends an address of its own is still read',
   got.command, 'ap name AP_Diagnostika_Plocha 24-W51')
ok('...and an `unknown` line of the device is not drawn as a line called unknown',
   isemon.ise_first(got.fields, 'Port'), '')
got = isemon.tacplus_record_from(ACCT[5])
ok('a session the switch opened itself has no address',
   got.ip, '')
ok('...and says so where it came from', isemon.ise_first(got.fields, 'Asked from'),
   'EEM:callhome')
ok('a line that is not one of these at all is nothing',
   isemon.tacplus_record_from('this is not a tac_plus line'), None)
ok('...nor is an empty one', isemon.tacplus_record_from(''), None)

# ---------------------------------------------------------------------------
title('A stamp with no year in it, read against the file’s own clock')
# Everywhere else in this program a stamp with no year is read as this year,
# which is right because the line was written a moment ago. An accounting
# log left to run is a switch's whole life in one file - the one this was
# written against holds five years - and read as this year its first line
# lands next week.
LINES = isemon.tacplus_parse_lines(ACCT)
ok('every line of the log is a record', len(LINES), len(ACCT))
years = [time.strftime('%Y', time.localtime(r.ts)) for r in LINES]
ok('the ones with a moment in them are filed under their own year',
   (years[0], years[-1]), ('2021', '2026'))
ok('...and the one without follows the line before it rather than today',
   years[2], '2021')
ok('nothing is filed in the future',
   [y for y in years if int(y) > int(time.strftime('%Y'))], [])
# ...and the same lines read twice are the same records, which is what makes
# reading a file again safe.
AGAIN = isemon.tacplus_parse_lines(ACCT)
ok('reading the same lines again makes the same records',
   [r.session for r in AGAIN], [r.session for r in LINES])
ok('...and every one of them is its own record',
   len({r.session for r in LINES}), len(LINES))

# ---------------------------------------------------------------------------
title('The daemon’s own log, which is where a refusal is')
GOT = isemon.tacplus_parse_lines(SAID)
ok('the lines about somebody are records', len(GOT), 5)
ok('...and the daemon talking to itself is not',
   [r for r in GOT if 'config file' in str(r.fields)], [])
refused = [r for r in GOT if r.failed]
ok('four of them were turned away', len(refused), 4)
ok('...each with the name that was refused',
   sorted({r.user for r in refused}), ['admin', 'dpmo', 'jnovak', 'svc-backup'])
ok('...and the address it came from',
   isemon.ise_first(refused[0].fields, 'Asked from'), '10.10.10.9')
ok('the daemon’s own words are what the row says',
   isemon.ise_first(refused[0].fields, 'What happened'), 'login query rejected')
ok('...and a failure written the other way is read too',
   isemon.ise_first(refused[1].fields, 'What happened'), 'login failure')
ok('one of them got in', len([r for r in GOT if not r.failed]), 1)

# ---------------------------------------------------------------------------
title('A shipper that puts a real stamp in front')
# tac_plus itself cannot write a year: `Sep 16 11:56:52` is all its
# accounting file ever says. A site that ships these lines with rsyslog can
# put a full stamp in front of them - year, and the zone as well - and that
# is the one way a line of this file is dated exactly. See
# `docs/tacplus-logs.md`; what matters here is that every shape is read and
# that the stamp in front is believed over the one behind it.
BASE = ('192.9.212.254' + T + 'admin' + T + 'tty1' + T + '10.10.10.9' + T
        + 'stop' + T + 'task_id=9947' + T + 'timezone=UTC' + T + 'service=shell'
        + T + 'priv-lvl=15' + T + 'cmd=show version <cr>')
SHAPES = {
    'as tac_plus writes it': 'Sep 16 11:56:52' + T + BASE,
    'shipped with rfc3339 in front':
        '2024-09-16T11:56:52+02:00 Sep 16 11:56:52' + T + BASE,
    'shipped with the stamp replaced': '2024-09-16T11:56:52+02:00' + T + BASE,
    'a plain ISO stamp': '2024-09-16 11:56:52' + T + BASE,
    'one with milliseconds': '2024-09-16T11:56:52.481+02:00 Sep 16 11:56:52' + T + BASE,
    'one with a priority in front':
        '<86>2024-09-16T11:56:52+02:00 Sep 16 11:56:52' + T + BASE,
    'one written in UTC': '2024-09-16T09:56:52Z Sep 16 11:56:52' + T + BASE,
    'an offset with no colon in it':
        '2024-09-16T11:56:52+0200 Sep 16 11:56:52' + T + BASE,
    'seconds since the epoch': '1726480612' + T + BASE,
}
for what, line in SHAPES.items():
    got = isemon.tacplus_record_from(line)
    ok('read: %s' % what, got is not None and got.command == 'show version')
DATED = {what: isemon.tacplus_record_from(line).ts for what, line in SHAPES.items()}
ok('a stamp with a year in it is dated by that year',
   {time.strftime('%Y', time.localtime(v))
    for k, v in DATED.items() if k != 'as tac_plus writes it'}, {'2024'})
ok('...and every one of those means the same second',
   len({int(v) for k, v in DATED.items() if k != 'as tac_plus writes it'}), 1)
ok('...including the one written in UTC and the one written in Prague',
   int(DATED['one written in UTC']), int(DATED['shipped with rfc3339 in front']))
# ...and the daemon's own log, shipped the same way.
SAID_SHAPES = [
    "Sep 29 09:14:02 tacsrv tac_plus[2461]: login query for 'jnovak' tty2 from "
    '10.10.10.9 rejected',
    "Sep 29 09:14:02 tac_plus[2461]: login query for 'jnovak' tty2 from "
    '10.10.10.9 rejected',
    "<86>2024-09-29T09:14:02+02:00 tacacs.example.loc tac_plus[2461]: login query "
    "for 'jnovak' tty2 from 10.10.10.9 rejected",
]
GOT_SAID = [isemon.tacplus_record_from(one) for one in SAID_SHAPES]
ok('a refusal is read however the line reached here',
   [g is not None and g.user == 'jnovak' for g in GOT_SAID], [True, True, True])
ok('...with the machine it was written on, where the line says',
   [g.server for g in GOT_SAID], ['tacsrv', 'tac_plus', 'tacacs.example.loc'])
ok('...and the stamp in front is the one believed',
   time.strftime('%Y', time.localtime(GOT_SAID[2].ts)), '2024')

# ---------------------------------------------------------------------------
title('What rsyslog does to a line on the way, left to its defaults')
# Two things, each of which on its own would have ruined the first import on
# the site this was written for - measured on its own log: every one of
# 251,533 lines unread, or 15,356 of them filed as the afternoon they were
# sent.
#
# rsyslog turns a TAB into `#011` on the way in unless it is told not to,
# and the tabs are the only thing between one field and the next.
ESCAPED = ACCT[0].replace('\t', '#011')
got = isemon.tacplus_record_from(ESCAPED)
ok('a line whose tabs arrived as #011 is still a line', got is not None)
ok('...read exactly as the same line with its tabs', (got.command, got.user, got.ip,
   int(got.ts)), ('configure terminal', 'admin', '10.10.10.9', 1631786213))
ok('...and a real tab is never second-guessed',
   isemon.tacplus_record_from(ACCT[0].replace('cmd=configure terminal',
                                               'cmd=echo #011')).command, 'echo #011')
# The first time imfile is pointed at a file it sends ALL of it, and the
# receiver stamps each line with the moment it arrived. That is when the line
# was SENT, and for a five-year-old line that is five years out.
SENT_AT = '2026-09-29T16:20:00+02:00  '
BACKLOG = [SENT_AT + one for one in ACCT]
HELD = {}
GOT_BACKLOG = isemon.tacplus_parse_lines(BACKLOG, HELD)
ok('a whole file sent at once is read line for line', len(GOT_BACKLOG), len(ACCT))
ok('...and a line with no start_time is dated by what tac_plus wrote on it, '
   'not by when it was sent',
   time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(GOT_BACKLOG[2].ts)),
   '17-09-2021 11:17:52')
ok('...so nothing in it is filed as the afternoon it arrived',
   [r for r in GOT_BACKLOG if 'Started' not in r.fields
    and abs(r.ts - isemon.iso_seconds('2026-09-29T16:20:00+02:00')) < 86400], [])
# ...while a line whose shipper REPLACED tac_plus's stamp has only that one.
ONLY = isemon.tacplus_record_from('2024-09-16T11:56:52+02:00' + T + BASE)
ok('a line with nothing but the shipper\u2019s stamp is dated by it',
   time.strftime('%Y', time.localtime(ONLY.ts)), '2024')
# ...and the very first line of a file, with nothing before it to go by: the
# latest year that does not put it after it was sent.
FIRST = isemon.tacplus_record_from('2027-01-02T09:00:00+01:00 Dec 31 23:59:58'
                                   + T + BASE)
ok('a first line written just before New Year and sent just after it is last '
   'year\u2019s', time.strftime('%d-%m-%Y', time.localtime(FIRST.ts)), '31-12-2026')
# The daemon's own log, sent the same way.
LATE = isemon.tacplus_record_from(
    '2026-09-29T16:20:00+02:00 Mar 03 08:01:44 tacacs tac_plus[2461]: login '
    'failure: admin 192.9.211.198 (192.9.220.153) tty1')
ok('a refusal written in March and sent in September is a refusal in March',
   time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(LATE.ts)), '03-03-2026 08:01:44')
ok('...and the daemon\u2019s own chatter is still not a refusal',
   isemon.tacplus_record_from('Sep 29 14:24:22 tacacs tac_plus[25089]: connect from '
                              '192.9.211.221 [192.9.211.221]'), None)

# ...and the exact shape the receiving rsyslog writes with the template
# `docs/tacplus-logs.md` gives it, RSYSLOG_FileFormat: a stamp to the
# microsecond, the host, the tag, and then the line as tac_plus wrote it.
FILEFORMAT = ('2026-09-29T16:20:00.123456+02:00 tacacs tac_acct: '
              + ACCT[0].replace('\t', '#011'))
got = isemon.tacplus_record_from(FILEFORMAT)
ok('an accounting line as the receiving rsyslog writes it is read',
   (got.command, got.user, int(got.ts)) if got else None,
   ('configure terminal', 'admin', 1631786213))
got = isemon.tacplus_record_from('2026-09-29T16:20:00.123456+02:00 tacacs tac_acct: '
                                 + ACCT[0])
ok('...with its tabs kept as well', got is not None and got.command, 'configure terminal')
got = isemon.tacplus_record_from(
    "2026-09-29T09:14:02.004211+02:00 tacacs tac_plus[2461]: login query for "
    "'jnovak' tty2 from 10.10.10.9 rejected")
ok('...and a refusal as it writes that',
   (got.user, got.server, time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(got.ts)))
   if got else None, ('jnovak', 'tacacs', '29-09-2026 09:14:02'))

# ---------------------------------------------------------------------------
title('Where the file has got to, across the pieces it is read in')
# A file is read eight megabytes at a time, and after a restart from where
# it stopped. Where the file has got to has to survive both, or the top of
# every piece is read as though nothing came before it.
PIECE_ONE = [ACCT[0], ACCT[1]]            # 2021, with start_time
PIECE_TWO = [ACCT[2]]                     # no start_time: 17 Sep, which year?
HOLD = {}
isemon.tacplus_parse_lines(PIECE_ONE, HOLD)
SECOND = isemon.tacplus_parse_lines(PIECE_TWO, HOLD)
ok('a line at the top of the next piece follows the one before it, not today',
   time.strftime('%Y', time.localtime(SECOND[0].ts)), '2021')
PACKED = isemon.LogTail.unpack_hold(isemon.LogTail.pack_hold(HOLD))
AGAIN = isemon.tacplus_parse_lines(PIECE_TWO, PACKED)
ok('...and after a restart, which is the same thing written down and read back',
   time.strftime('%Y', time.localtime(AGAIN[0].ts)), '2021')
# An exact moment sets the clock, even backwards: whatever was inferred
# before it may have been wrong, and it must not pin every line after it.
WRONG = {isemon.TACPLUS_CLOCK_KEY: {'at': isemon.iso_seconds('2026-01-01T00:00:00+01:00'),
                                    'parts': {}}}
isemon.tacplus_parse_lines([ACCT[0]], WRONG)
ok('an exact moment puts a clock that had run ahead back where it belongs',
   time.strftime('%Y', time.localtime(WRONG[isemon.TACPLUS_CLOCK_KEY]['at'])), '2021')

# ---------------------------------------------------------------------------
title('The site\u2019s own server, set up as docs/tacplus-setup.md says')
# Both files, as they were on the tac_plus server the afternoon it was set
# up: a wrong password typed on purpose at two switches, then a few commands
# on each. This is the build the refusals were never seen from before -
# and the one line of it that mattered most was being read wrongly.
REAL_ACCT = [
    'Sep 29 16:12:52\t192.9.212.254\tadmin\ttty1\t10.10.10.9\tstop\ttask_id=24753\t'
    'timezone=UTC\tservice=shell\tstart_time=1790691166\tpriv-lvl=15\t'
    'cmd=show running-config <cr>',
    'Sep 29 16:12:56\t192.9.212.254\tadmin\ttty1\t10.10.10.9\tstop\ttask_id=24754\t'
    'timezone=UTC\tservice=shell\tstart_time=1790691170\tpriv-lvl=15\t'
    'cmd=configure terminal <cr>',
    'Sep 29 16:12:57\t192.9.212.254\tadmin\ttty1\t10.10.10.9\tstop\ttask_id=24755\t'
    'timezone=UTC\tservice=shell\tstart_time=1790691171\tpriv-lvl=0\tcmd=exit <cr>',
    'Sep 29 17:20:08\t192.9.211.248\tadmin\ttty1\t10.10.10.9\tstop\ttask_id=345\t'
    'timezone=UTC\tservice=shell\tstart_time=1790695203\tpriv-lvl=15\t'
    'cmd=show running-config <cr>',
    'Sep 29 17:20:17\t192.9.211.248\tadmin\ttty1\t10.10.10.9\tstop\ttask_id=348\t'
    'timezone=UTC\tservice=shell\tstart_time=1790695212\tpriv-lvl=1\t'
    'cmd=show interfaces status <cr>',
]
REAL_SAID = [
    'Sep 29 16:12:44 tacacs tac_plus[25415]: connect from 192.9.212.254 [192.9.212.254]',
    'Sep 29 16:12:46 tacacs tac_plus[25415]: login failure: admin 192.9.212.254 '
    '(192.9.212.254) tty1',
    'Sep 29 16:12:48 tacacs tac_plus[25416]: connect from 192.9.212.254 [192.9.212.254]',
    'Sep 29 17:20:01 tacacs tac_plus[25583]: connect from 192.9.211.248 [192.9.211.248]',
    'Sep 29 17:20:01 tacacs tac_plus[25583]: login failure: admin 192.9.211.248 '
    '(192.9.211.248) tty1',
]
GOT_REAL = isemon.tacplus_parse_lines(REAL_SAID, {})
ok('this build writes refusals, and both are read', [r.user for r in GOT_REAL],
   ['admin', 'admin'])
ok('...and the connections around them are not', len(GOT_REAL), 2)
# The two things after the name are both the SWITCH: its name and its
# address. Where the person sat is not on this line at all, and read as
# though it were, every refusal was filed against the switch's own address.
ok('the switch is the device a refusal happened at',
   [isemon.ise_first(r.fields, 'Device') for r in GOT_REAL],
   ['192.9.212.254', '192.9.211.248'])
ok('...and never the address somebody came from',
   [r.ip for r in GOT_REAL], ['', ''])
ok('...with the line of it they were on', [isemon.ise_first(r.fields, 'Port')
                                           for r in GOT_REAL], ['tty1', 'tty1'])
ok('...and the server that said so', [r.server for r in GOT_REAL], ['tacacs', 'tacacs'])
folderR, storeR, daemonR = fresh()
daemonR.read_records(REAL_ACCT + REAL_SAID, kind='tacplus')
ok('two switches, two sittings',
   storeR.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind='tacplus'")
   .fetchone()['n'], 2)
ok('...every command in one of them',
   sorted(daemonR.commands_for_login(dict(r))['ran'] for r in storeR.db.execute(
       "SELECT * FROM passed WHERE kind='tacplus'").fetchall()), [2, 3])
ok('...and the person\u2019s own address on the sitting, out of the accounting',
   {r['ip'] for r in storeR.db.execute(
       "SELECT ip FROM passed WHERE kind='tacplus'").fetchall()}, {'10.10.10.9'})
ok('...while the refusals carry none, because their line has none',
   {r['ip'] or '' for r in storeR.db.execute(
       "SELECT ip FROM failed WHERE kind='tacplus'").fetchall()}, {''})
# ...and the front page's chart, which a single sitting inside its window
# used to take down entirely: the band was named and never given a place.
BARS = storeR.auth_counts(24 * 400)
ok('the chart draws with sittings in it',
   sum(b.get('passed_tacplus', 0) for b in BARS), 2)
ok('...as a band of their own, not as the VPN',
   sum(b['passed'] - b.get('passed_tacplus', 0) for b in BARS), 0)
ok('...and the refusals likewise', sum(b.get('failed_tacplus', 0) for b in BARS), 2)
# ...and what 1.10.83 to 1.10.86 already wrote down the wrong way is put right
# at the next start, without reading anything again.
with storeR.db_write() as dbR:
    dbR.execute("UPDATE failed SET ip = device WHERE kind = 'tacplus'")
ok('a refusal written the old way names its own switch as the source',
   storeR.db.execute("SELECT COUNT(*) AS n FROM failed WHERE kind='tacplus' AND ip = device")
   .fetchone()['n'], 2)
ok('...and the next start takes that away', storeR.mend_tacplus_refusals(force=True), 2)
ok('...leaving the switch where it belongs, as the device',
   sorted(r['device'] for r in storeR.db.execute(
       "SELECT device FROM failed WHERE kind='tacplus' AND COALESCE(ip,'') = ''")),
   ['192.9.211.248', '192.9.212.254'])
ok('...and a second start finds nothing more to do', storeR.mend_tacplus_refusals(), 0)
ok('...and does not even read the table', storeR.mended_once('tacplus_refusals', '1'), True)
shutil.rmtree(folderR, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Sittings and commands, stored')
folder, store, daemon = fresh()
ok('reading it wrote something down',
   daemon.read_records(ACCT + SAID, kind='tacplus') > 0)


def rows(table, kind):
    return store.db.execute('SELECT COUNT(*) AS n FROM %s WHERE kind=?' % table,
                            (kind,)).fetchone()['n']


ok('every command is a row of its own', rows('passed', 'tacplus-cmd'), 6)
ok('...and each sitting they were typed in is one row', rows('passed', 'tacplus'), 6)
ok('what the daemon turned away is on the other list', rows('failed', 'tacplus'), 4)
ok('nothing landed in anybody else’s door',
   store.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind NOT LIKE 'tacplus%'")
   .fetchone()['n'], 0)
# The commands of one sitting, found the way the page finds them.
sitting = dict(store.db.execute(
    "SELECT * FROM passed WHERE kind='tacplus' AND username='admin' "
    'ORDER BY ts ASC LIMIT 1').fetchone())
said = daemon.commands_for_login(sitting)
ok('a sitting carries the commands typed in it', (said or {}).get('ran'), 2)
ok('...in the order they were typed',
   [c['cmd'] for c in said['commands']], ['configure terminal', 'end'])
ok('the box at the top finds a command typed through tac_plus',
   [(c['said'], c['kinds'], c['name']) for c in daemon.find('configure t')['commands']],
   [('configure terminal', ['tacplus-cmd'], 'admin')])
ok('a sitting on a switch is never judged and never banned',
   store.db.execute('SELECT COUNT(*) AS n FROM blocked').fetchone()['n'], 0)

# ---------------------------------------------------------------------------
title('A prompt that sat quiet is somebody sitting down again')
# tac_plus writes nothing about sessions on most installations, so the
# sitting is read out of the commands: a gap, and then somebody is back.
folder2, store2, daemon2 = fresh()
AT = time.time() - 86400
BURST = []
for n, (at, cmd) in enumerate(
        [(AT, 'show version'), (AT + 30, 'show run'), (AT + 90, 'configure terminal'),
         # ...and two hours later, which is a different sitting
         (AT + 7200, 'show logging'), (AT + 7230, 'exit')]):
    BURST.append('%s\t10.0.0.1\tnovak\ttty1\t10.20.30.40\tstop\ttask_id=%d\t'
                 'timezone=UTC\tservice=shell\tstart_time=%d\tpriv-lvl=15\tcmd=%s <cr>'
                 % (time.strftime('%b %d %H:%M:%S', time.localtime(at)), n, int(at), cmd))
daemon2.read_records(BURST, kind='tacplus')
ok('five commands', rows2 := store2.db.execute(
    "SELECT COUNT(*) AS n FROM passed WHERE kind='tacplus-cmd'").fetchone()['n'], 5)
ok('...in two sittings, cut where the prompt sat quiet',
   store2.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind='tacplus'")
   .fetchone()['n'], 2)
first = dict(store2.db.execute(
    "SELECT * FROM passed WHERE kind='tacplus' ORDER BY ts ASC LIMIT 1").fetchone())
ok('the first sitting holds the first three',
   len(daemon2.commands_for_login(first)['commands']), 3)
ok('...and it says it was read out of the commands',
   first['subtype'], 'Session|read from the commands')
# ...and the same lines again make the same two sittings, not four.
daemon2.read_records(BURST, kind='tacplus')
ok('reading the same lines again adds nothing',
   store2.db.execute("SELECT COUNT(*) AS n FROM passed").fetchone()['n'], 7)
# ...and a daemon that was restarted carries on the sitting it was in
# rather than opening a second one beside it.
daemon3 = isemon.Daemon(store2)
daemon3.read_records(
    ['%s\t10.0.0.1\tnovak\ttty1\t10.20.30.40\tstop\ttask_id=99\ttimezone=UTC\t'
     'service=shell\tstart_time=%d\tpriv-lvl=15\tcmd=show clock <cr>'
     % (time.strftime('%b %d %H:%M:%S', time.localtime(AT + 7300)), int(AT + 7300))],
    kind='tacplus')
ok('a restart in the middle of a sitting does not open a second one',
   store2.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind='tacplus'")
   .fetchone()['n'], 2)

# ---------------------------------------------------------------------------
title('What the rest of this program does with it')
ok('the counted doors know about it',
   'tacplus' in isemon.Storage.DOOR_KINDS and 'tacplus' in isemon.LOGIN_KINDS)
ok('a command is not a login', 'tacplus-cmd' in isemon.LOGIN_KINDS, False)
said = store2.inside(('tacplus',))
ok('the database page can say how much of it there is',
   (said['tacplus']['parts']['sittings'], said['tacplus']['parts']['commands']), (2, 6))
ok('...and it has a group of its own to erase',
   'tacplus' in store2.ERASABLE)
ok('...which is the sittings, the commands and the refusals',
   sorted(store2.ERASABLE['tacplus']['part']), ['failed', 'passed'])
ok('...and forgets where the files were read up to',
   store2.ERASABLE['tacplus']['reread'], ('tacplus',))
gone = store2.erase(['tacplus'])
ok('erasing it takes every one of them',
   store2.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind LIKE 'tacplus%'")
   .fetchone()['n'], 0)
ok('...and says how many that was', gone['tacplus'] >= 8)

# ...and the pass back over the logs can be asked for one module.
ok('the logs can be named one at a time',
   isemon.log_modules_named('tacplus'), ['tacplus'])
ok('...naming a module takes the files it is made of',
   isemon.log_modules_named('otp'), ['otp', 'otp-detail'])
ok('...naming nothing means everything, as it always did',
   isemon.log_modules_named(''), [])
ok('...and "all" says the same thing out loud',
   isemon.log_modules_named('all'), [])
try:
    isemon.log_modules_named('nonsense')
    said = 'it was allowed'
except ValueError:
    said = 'refused'
ok('a log nobody has is refused rather than silently ignored', said, 'refused')

# ---------------------------------------------------------------------------
title('The page it is drawn on')
ok('a door of its own, offered only while the logs are read',
   "{kind: 'tacplus', words: 'TAC_Plus'" in PAGE_SRC
   and "if (!(STATUS || {}).tacplus_on) return;" in PAGE_SRC)
ok('...with the same columns TACACS has, because it is the same question',
   'tacplus: [\'When\', \'Name\', addrHeads(\'From\'), \'Device\', \'Commands\''
   in PAGE_SRC)
ok('...and a row of its own on the refusals, with no ban button on it',
   'function tacplusRow(tr, r) {' in PAGE_SRC)
ok('the commands of a sitting open on either daemon’s rows',
   "not in ('tacacs', 'tacplus'):" in DAEMON_SRC)
ok('the settings have a page of their own',
   'id="pane-tacplus"' in PAGE_SRC and "tacplus: ['tacplus', 'tacplus_paths'" in PAGE_SRC)
ok('...and each of them is greyed out while the module is off',
   "tacplus_paths: ['tacplus', '1']" in PAGE_SRC)
ok('the database page says how much of it is stored',
   'id="db-inside"' in PAGE_SRC and "'inside': daemon.held('db-inside'" in DAEMON_SRC)
ok('nothing read here is ever judged',
   'Never judged, and it is worth being plain about why' in DAEMON_SRC)
# ...and the words over a filter that CHANGE with the door are said the
# page's own way. A `title` put back on something that already explains
# itself is two boxes over one thing, which is the one rule this page has
# about explaining anything.
# A module switched off offers no door. A site that reads no ISE was shown
# VPN and TACACS anyway, and both lists opened on the VPN one: an empty list
# under a door to a system it does not have.
ok('ISE\u2019s doors follow the switch that says whether ISE is read',
   "var ISE_DOORS = ['vpn', 'tacacs', 'dot1x-lan', 'dot1x-wifi', 'mab-lan', 'mab-wifi',"
   in PAGE_SRC and 'return s.ise_on === false;' in PAGE_SRC)
ok('...and a list never opens on a door that is not offered',
   'if (doorToShow(FKIND) !== FKIND) return showFailedKind(FKIND);' in PAGE_SRC
   and 'if (doorToShow(PKIND) !== PKIND) return passedTab(PKIND);' in PAGE_SRC)
ok('...nor stays on one when the switch moves under it',
   'if (doorsNow !== DOORS_SEEN) {' in PAGE_SRC)
ok('...and nothing is hidden before the daemon has said what is on',
   'if (!s) return false;' in PAGE_SRC)
# ...and the front page follows the same rule, with a band of its own for it.
ok('the front page offers no VPN door while ISE is not read',
   "if (!doorSwitchedOff('vpn')) out.push({door: 'vpn'" in PAGE_SRC)
ok('...and opens on the first door that is offered',
   'ovShowDoor(want[0].door);' in PAGE_SRC)
ok('...where tac_plus has a door and a band of its own',
   "out.push({door: 'tacplus', words: 'TAC_Plus'" in PAGE_SRC
   and "['tacacs', 'tacplus', 'network', 'otp', 'eduroam', 'npsvpn', 'npsnet', 'radvpn', 'radnet']"
   in PAGE_SRC)
ok('...and a legend that shows only what is being read',
   "node.hidden = s.ise_on === false;" in PAGE_SRC and 'id="leg-tac-bad"' in PAGE_SRC)
ok('the procedure and the files to copy are shipped',
   all((HERE.parent / f).exists() for f in (
       'docs/tacplus-setup.md', 'deploy/tacplus/50-tacplus.conf',
       'deploy/tacplus/60-tacplus-ship.conf', 'deploy/tacplus/05-tacplus-store.conf')))
ok('...none of them names any one site\u2019s machine',
   [f for f in ('docs/tacplus-setup.md', 'docs/tacplus-logs.md',
                'deploy/tacplus/50-tacplus.conf', 'deploy/tacplus/60-tacplus-ship.conf')
    if __import__('base64').b64decode('Zm5vbA==').decode() in (HERE.parent / f).read_text(encoding='utf-8').lower()], [])
ok('words that change are never put back as a browser tooltip',
   'function sayOver(over, words) {' in PAGE_SRC
   and 'sayOver(box, said ? said[1] : DOOR_FILTER_PLAIN[which][1]);' in PAGE_SRC)

shutil.rmtree(folder, ignore_errors=True)
shutil.rmtree(folder2, ignore_errors=True)
title('A secret typed on a switch is not kept in the record either')
SECRET_LINE = ('Sep 16 11:56:52' + T + '192.9.212.254' + T + 'admin' + T + 'tty1' + T
               + '10.10.10.9' + T + 'stop' + T + 'task_id=9947' + T + 'timezone=UTC' + T
               + 'service=shell' + T + 'start_time=1631786213' + T + 'priv-lvl=15' + T
               + 'cmd=username x secret S3cr3tPw <cr>')
rec = [r for r in isemon.tacplus_parse_lines([SECRET_LINE], {})][0]
stored = isemon.detail_within(rec.flat(), 60000)
ok('the record as stored names the secret, not what it was',
   ('S3cr3tPw' in stored, 'secret (hidden)' in stored), (False, True))
ok('...and ISE\u2019s command set the same, in its own shape',
   isemon.fields_kept({'CmdSet': '[ CmdAV=enable CmdArgAV=secret CmdArgAV=0 '
                                 'CmdArgAV=Sw1tchPw CmdArgAV=<cr> ]'})['CmdSet'],
   '[ CmdAV=enable CmdArgAV=secret CmdArgAV=0 CmdArgAV=(hidden) CmdArgAV=<cr> ]')
ok('...a record stored whole by an older version is shown without it',
   'S3cr3tPw' in isemon.detail_kept('{"Command": "username x secret S3cr3tPw"}'), False)
# ...and taken out of the rows an older version stored whole.
folderS = tempfile.mkdtemp(prefix='isemon-secret-')
isemon.STATE_DIR = Path(folderS)
isemon.DB_FILE = Path(folderS) / 'secret.db'
storeS = isemon.Storage()
storeS.add_passed({'session': 'old/1', 'ts': 1700000000.0, 'ip': '', 'username': 'admin',
                   'kind': 'tacplus-cmd', 'device': '192.9.212.254', 'cmd': 'username x',
                   'detail': json.dumps({'Command': 'username x secret S3cr3tPw',
                                         'Account': 'admin'})})
ok('an older version\u2019s record holds the secret', 'S3cr3tPw' in storeS.unpack_detail(
    storeS.db.execute("SELECT detail FROM passed WHERE session='old/1'").fetchone()['detail']),
   True)
ok('the one-time repair rewrites it', storeS.mend_command_secrets(force=True), 1)
ok('...after which the database no longer holds it', 'S3cr3tPw' in storeS.unpack_detail(
    storeS.db.execute("SELECT detail FROM passed WHERE session='old/1'").fetchone()['detail']),
   False)
ok('...and a second run finds nothing', storeS.mend_command_secrets(force=True), 0)
ok('...and is marked done only once it is', storeS.mended_once('command_secrets', '1'), True)
storeS.db.close()
shutil.rmtree(folderS, ignore_errors=True)
ok('...and a record with no command in it is left exactly as it was',
   isemon.detail_kept('{"User-Name": "jan"}'), '{"User-Name": "jan"}')

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
