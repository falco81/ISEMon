#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clocks.py - a log line with no zone in it, which is most of them.

ISE writes the offset that was in force on every record it writes, so an ISE
record says exactly which second it happened in and nothing on this machine
can move it. The token log and the eduroam log write

    Sep 25 10:21:25

and nothing else. A time like that is not a moment until somebody says where
it was written, and the reader has only one thing to go on: the zone of the
machine doing the reading. Where the two agree - which is nearly everywhere
- that is right and costs nothing. Where they do not, every record is hours
from where it belongs and nothing looks wrong: the lines parse, the rows
arrive, the counts count, and the only thing the matter is which second they
are filed under. That is the one kind of wrong nobody finds, because finding
it means holding the screen up beside the log.

This is the whole of that, in the shape it was actually found in: a machine
left on America/New_York while its syslog carried Prague time, six hours of
records in the future, and a screen that looked perfectly ordinary.

    ./test/clocks.py
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Before isemon is imported, because the zone is read out of the environment
# at import and this suite is about a machine whose zone is wrong.
os.environ['TZ'] = 'America/New_York'
time.tzset()

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0

# 2026-09-25 11:34:00 in Prague, which is 05:34 where this machine thinks it
# is. Every time in this file is worked out from it rather than from the
# clock, so the suite says the same thing in January as in July.
NOW = 1790328840.0
PRAGUE = 1790328768.0          # 2026-09-25 11:32:48 Prague, the last line below


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


def when(ts):
    """A moment as UTC, for saying what went wrong in words worth reading."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))


def fresh(prefix='isemon-clock-'):
    folder = tempfile.mkdtemp(prefix=prefix)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'c.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'c.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon._ZONES.clear()
    otp = Path(folder) / 'otp'
    edu = Path(folder) / 'edu'
    otp.mkdir()
    edu.mkdir()
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'feeds_ban': 0, 'mikrotik_host': '',
        'ise_paths': [str(Path(folder) / 'ise')], 'read_passed': 1,
        'otp': 1, 'otp_paths': [str(otp)],
        'eduroam': 1, 'eduroam_paths': [str(edu)],
        'log_zone': '', 'judge_max_age_h': 0, 'debug': False,
    })
    (Path(folder) / 'ise').mkdir()
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    return folder, otp, edu, store, daemon


def prague_now(when=None):
    """A syslog line stamped the way a machine in Prague stamps one, now.

    The checks below that go through the reader use the real clock, because
    that is what the reader uses. A line with a time written into it is
    ahead of New York for part of the day and behind it for the rest, which
    is a suite that passes in the morning and fails after lunch - and did.
    """
    from zoneinfo import ZoneInfo
    at = isemon.datetime.fromtimestamp(when or time.time(), ZoneInfo('Europe/Prague'))
    return at.strftime('%b %d %H:%M:%S')


# The line off the machine this was found on, word for word.
OTP_LINE = ('Sep 25 11:32:48 otp totp.cgi[4182]: Success: user=ok_rubi7939@corp-example.int, '
            'mode=PAM_SM_AUTH, host=127.0.0.1, message=Valid token used')
EDU_LINE = ('Sep 25 11:32:48 edurad1 radius: Fri Sep 25 11:32:48 2026 : Auth: (10551100) '
            'Login OK: [jk@example.cz/<via Auth-Type = eap>] (from client wlc9800 port 2915 '
            'cli DE-18-C7-2E-5D-C6)')
# ...and an ISE record of the same second, which carries its own offset.
ISE_LINES = [
    'Sep 25 11:32:48 ise2 CISE_Failed_Attempts 0000000001 3 0 2026-09-25 11:32:48.500 +02:00 '
    '0229674592 5400 NOTICE Failed-Attempt: Authentication failed, ConfigVersionId=86, '
    'Device IP Address=172.22.0.137, UserName=jnovak, Protocol=Radius, '
    'NetworkDeviceName=FTD-VPN, Calling-Station-ID=203.0.113.9, '
    'AcsSessionID=ise2/569337134/1,',
    'Sep 25 11:32:48 ise2 CISE_Failed_Attempts 0000000001 3 1 AuthenticationMethod=PAP_ASCII, '
    'FailureReason=22056 Subject not found,',
    'Sep 25 11:32:48 ise2 CISE_Failed_Attempts 0000000001 3 2 EndPointIPAddress=203.0.113.9, '
    'Response={RadiusPacketType=AccessReject; }',
]


# ---------------------------------------------------------------------------
title('What a zone may be written as')
ok('nothing at all means this machine’s own', isemon.zone_named(''), None)
ok('...and so does the word for it', isemon.zone_named('local'), None)
ok('UTC is UTC', isemon.zone_named('UTC'), isemon.timezone.utc)
ok('...as is the letter for it', isemon.zone_named('Z'), isemon.timezone.utc)
ok('a fixed offset with a colon',
   isemon.zone_named('+02:00').utcoffset(None).total_seconds(), 7200.0)
ok('...without one',
   isemon.zone_named('+0200').utcoffset(None).total_seconds(), 7200.0)
ok('...and a negative one',
   isemon.zone_named('-04:00').utcoffset(None).total_seconds(), -14400.0)
ok('a zone out of the database knows its own offset',
   isemon.datetime.fromtimestamp(NOW, isemon.zone_named('Europe/Prague'))
   .utcoffset().total_seconds(), 7200.0)
ok('...and knows it changes: the same zone in January is an hour less',
   isemon.datetime.fromtimestamp(1767000000, isemon.zone_named('Europe/Prague'))
   .utcoffset().total_seconds(), 3600.0)


def refused(text):
    try:
        isemon.zone_named(text)
        return ''
    except ValueError as e:
        return str(e)


ok('a misspelt zone is refused, with the shape of a right one in the words',
   'Europe/Prague' in refused('Europe/Praha'))
ok('...and so is anything else that is not one', bool(refused('somewhere')))
ok('an offset no place on earth has is refused',
   'further from UTC' in refused('+99:00'))
ok('a zone nobody could act on never reaches the reader: the setting refuses it',
   bool(isemon.check_setting_error('log_zone', 'Europe/Praha')
        if hasattr(isemon, 'check_setting_error') else refused('Europe/Praha')))


# ---------------------------------------------------------------------------
title('The machine that was on New York time while its syslog was on Prague time')
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon._ZONES.clear()
wrong = isemon.otp_record_from(OTP_LINE, NOW)
ok('the line reads perfectly - that is the trouble', wrong is not None)
ok('...and lands six hours from where it belongs', wrong.ts - PRAGUE, 21600.0)
ok('...which is in the future, and a line cannot be written before it happens',
   wrong.ts > NOW)
ok('...six hours being exactly what New York is from Prague',
   when(wrong.ts), '2026-09-25 15:32:48')

isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()
right = isemon.otp_record_from(OTP_LINE, NOW)
ok('told where the log is written, the same line is the right second',
   right.ts, PRAGUE)
ok('...and is no longer in the future', right.ts < NOW)
isemon.CONFIG['log_zone'] = '+02:00'
ok('a fixed offset does as well for a machine with no zone database',
   isemon.otp_record_from(OTP_LINE, NOW).ts, PRAGUE)
isemon.CONFIG['log_zone'] = 'UTC'
ok('...and any other zone moves it by exactly that much',
   isemon.otp_record_from(OTP_LINE, NOW).ts, PRAGUE + 7200)

title('The eduroam log is the same log with different words in it')
isemon.CONFIG['log_zone'] = ''
isemon._ZONES.clear()
ok('it goes out by the same six hours',
   isemon.edu_record_from(EDU_LINE, NOW).ts - PRAGUE, 21600.0)
isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()
ok('...and comes back to the right second the same way',
   isemon.edu_record_from(EDU_LINE, NOW).ts, PRAGUE)

title('...and ISE is not touched by any of it, because it says where it was')
for said in ('', 'Europe/Prague', 'UTC', 'Pacific/Auckland'):
    isemon.CONFIG['log_zone'] = said
    isemon._ZONES.clear()
    got = isemon.ise_parse_lines(ISE_LINES, None)
    ok('an ISE record is the same second whatever this is set to (%s)'
       % (said or 'this machine’s own'), got[0].ts, PRAGUE + 0.5)
isemon.CONFIG['log_zone'] = ''
isemon._ZONES.clear()

title('...and neither is the eduroam accounting, which is written as seconds')
DETAIL = ('Fri Sep 25 11:32:48 2026\n'
          '\tUser-Name = "jk@example.cz"\n'
          '\tCalling-Station-Id = "DE-18-C7-2E-5D-C6"\n'
          '\tFramed-IP-Address = 172.25.113.54\n'
          '\tAcct-Status-Type = Start\n'
          '\tTimestamp = %d\n\n' % int(PRAGUE))
for said in ('', 'Europe/Prague', 'Pacific/Auckland'):
    isemon.CONFIG['log_zone'] = said
    isemon._ZONES.clear()
    ok('an accounting record is the same second whatever this is set to (%s)'
       % (said or 'this machine\u2019s own'),
       isemon.edu_detail_lines(DETAIL.splitlines())[0].ts, PRAGUE)
isemon.CONFIG['log_zone'] = ''
isemon._ZONES.clear()

title('A clock that is hours fast stays where it can be seen')
ok('a line thirty hours ahead is not quietly filed a year back',
   when(isemon.otp_when('Sep', '26', '18:00:00', NOW, isemon.zone_named('UTC'))),
   '2026-09-26 18:00:00')
ok('...so the thing that watches for it has something to see',
   isemon.otp_when('Sep', '26', '18:00:00', NOW, isemon.zone_named('UTC')) > NOW)

title('The year syslog leaves out is still guessed in the zone that is set')
ok('a December line read on New Year’s Day is last December',
   when(isemon.otp_when('Dec', '31', '23:58:00', 1767225600.0, isemon.zone_named('UTC'))),
   '2025-12-31 23:58:00')
ok('...and a line of today is today',
   when(isemon.otp_when('Sep', '25', '09:32:48', NOW, isemon.zone_named('UTC'))),
   '2026-09-25 09:32:48')


# ---------------------------------------------------------------------------
title('A zone that cannot be used says so, rather than looking set')
isemon.CONFIG['log_zone'] = 'Europe/Praha'
isemon._ZONES.clear()
ok('a config file edited by hand is not checked by anything, so the reader says it',
   'Europe/Praha' in isemon.zone_trouble())
ok('...and says which zone the logs are being read in meanwhile',
   'this machine' in isemon.zone_trouble())
ok('...while the reading itself carries on rather than dropping every record',
   isemon.otp_record_from(OTP_LINE, NOW) is not None)
isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()
ok('a zone that exists is no trouble at all', isemon.zone_trouble(), '')
isemon.CONFIG['log_zone'] = ''
ok('...and neither is none', isemon.zone_trouble(), '')

title('An offset is a place, not arithmetic')
for said in ('+02:75', '+0:61', '-00:90'):
    ok('%s has more than sixty minutes in it and is refused' % said,
       'sixty minutes' in refused(said))
ok('...while a zone that really is on the quarter hour is fine',
   isemon.zone_named('+05:45').utcoffset(None).total_seconds(), 20700.0)

# ---------------------------------------------------------------------------
title('Saying so: a line dated after the moment it was read')
ok('an offset is written the way people write one',
   [isemon.offset_written(7200), isemon.offset_written(-14400),
    isemon.offset_written(19800), isemon.offset_written(0)],
   ['+02:00', '-04:00', '+05:30', '+00:00'])
ok('...and is rounded to the quarter hour, because a clock is never exact',
   isemon.offset_written(7200 + 130), '+02:00')

ok('a clock a day fast is not named as a zone: no place on earth is +16:00',
   isemon.zone_guess(72000, NOW), '')
ok('...though the furthest place there really is, +14:00, is still named',
   [isemon.zone_guess(n, NOW) for n in (21600, 64800, 68400)],
   ['+02:00', '+14:00', ''])

words = isemon.clock_words('/var/log/remote/otp/totp.cgi.log', 21600, NOW)
ok('the words name the file', 'totp.cgi.log' in words)
ok('...say how far out it is', '6 h' in words)
ok('...say what it is being read as', 'read as -04:00' in words)
ok('...and say nothing about a zone when the difference is not one a zone could be, '
   'because then it is a clock and the zone is the one thing that is right',
   'written at' in isemon.clock_words('x', 21600 + 700, NOW), False)
ok('...nor when the file has only just been picked up and its newest line may be an hour old',
   'written at' in isemon.clock_words('x', 21600, NOW, False), False)
ok('...and name the zone it was really written in, rather than leaving that '
   'to whoever reads this at three in the morning', 'written at +02:00' in words)
ok('nothing is said about a log that is not ahead', isemon.clock_words('x', 0), '')

folder, otp, edu, store, daemon = fresh()


class Tail(object):
    def __init__(self, source):
        self.source = source
        self.path = '/var/log/remote/%s/a.log' % source
        self.ahead = 0
        self.ahead_said = 0.0


ise = Tail('ise')
# An ISE record carries its own zone, so it cannot be out BY a zone - and it
# was left unasked for that reason. But it can still be dated hours from now,
# and then the reason is the one that matters more: the machine writing it and
# the machine reading it disagree about the time, which stops every record
# being judged as soon as the difference passes `judge_max_age_h`. Nothing
# banned, every page full, nothing said. So it is asked, like every other log.
ok('an ISE file dated six hours on is marked too: a zone it cannot be out by, '
   'a clock it can', daemon.note_clock(ise, NOW + 21600, NOW), 21600)
ok('...and is marked', ise.ahead, 21600)
said = [e for e in store.events(limit=20)[0] if 'dated' in (e['detail'] or '')]
ok('...and said out loud once', len(said), 1)
ok('...with the advice a record that carries its own zone needs, which is not '
   'about a zone', 'clocks on the same time source' in (said[0]['detail'] or ''), True)
ok('...and not the advice about a zone setting',
   'the zone the logs without one' in (said[0]['detail'] or ''), False)
ok('...and an ISE file whose times make sense is left alone',
   daemon.note_clock(Tail('ise'), NOW + 60, NOW), 0)

token = Tail('otp')
ok('a token file dated six hours on is marked',
   daemon.note_clock(token, NOW + 21600, NOW), 21600)
ok('...and said out loud once',
   len([e for e in store.events(limit=20)[0] if 'dated' in (e['detail'] or '')]), 2)
ok('...and not again a minute later',
   daemon.note_clock(token, NOW + 60 + 21600, NOW + 60) and
   len([e for e in store.events(limit=20)[0] if 'dated' in (e['detail'] or '')]), 2)
ok('...but again once the day has moved on',
   daemon.note_clock(token, NOW + 25200 + 21600, NOW + 25200) and
   len([e for e in store.events(limit=20)[0] if 'dated' in (e['detail'] or '')]), 3)

near = Tail('otp')
ok('two machines a minute apart are not a zone and are left alone',
   daemon.note_clock(near, NOW + 60, NOW), 0)
ok('...nor is a log being read for the first time, which is all in the past',
   daemon.note_clock(near, NOW - 86400 * 30, NOW), 0)
ok('...and the mark goes as soon as the times make sense again',
   [daemon.note_clock(token, NOW - 5, NOW), token.ahead], [0, 0])


# ---------------------------------------------------------------------------
title('Putting it right afterwards, which is reading the log again')
shutil.rmtree(folder, ignore_errors=True)
folder, otp, edu, store, daemon = fresh()
# Written as a machine in Prague writes it, at this second, so that what
# the reader makes of it is six hours out whatever the hour is.
WROTE_AT = float(int(time.time()))
# Six hours for most of the year, five in the weeks when one of the two
# has changed its clocks and the other has not yet.
GAP = float(round(sum(
    sign * isemon.datetime.fromtimestamp(WROTE_AT, __import__('zoneinfo').ZoneInfo(zone))
    .utcoffset().total_seconds()
    for sign, zone in ((1, 'Europe/Prague'), (-1, 'America/New_York')))))
(otp / isemon.CONFIG['otp_name']).write_text(
    OTP_LINE.replace('Sep 25 11:32:48', prague_now(WROTE_AT)) + '\n')
(edu / isemon.CONFIG['eduroam_name']).write_text(
    EDU_LINE.replace('Sep 25 11:32:48', prague_now(WROTE_AT), 1) + '\n')
(Path(folder) / 'ise' / isemon.CONFIG['ise_failed_name']).write_text('\n'.join(ISE_LINES) + '\n')
daemon.restore_tails()
daemon.read_logs()
rows = store.db.execute('SELECT session, ts FROM passed').fetchall()
ok('the token line and the eduroam line are both in', len(rows), 2)
ok('...both six hours out, because this machine is still on the wrong zone',
   sorted(round(r['ts'] - WROTE_AT) for r in rows), [GAP, GAP])
ok('...and the ISE record is in and is right',
   [when(r['ts']) for r in store.db.execute('SELECT ts FROM failed')],
   ['2026-09-25 09:32:48'])
ok('the file that is out is marked as out, on the page as well as in the log',
   sorted(t['ahead'] > 0 for t in daemon.status()['logs']), [False, False, False, True, True])

# The machine's zone is put right - which is what actually happened - and the
# records already written keep the times they were written with.
isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()
daemon.read_logs()
ok('reading again changes nothing on its own: those lines are already read',
   len(store.db.execute('SELECT 1 FROM passed').fetchall()), 2)

had = store.erasable()
groups = {g['key']: g for g in had}
ok('the token records are their own thing to erase', groups['otp']['rows'], 1)
ok('...as are the eduroam ones', groups['eduroam']['rows'], 1)
ok('...and the old group still means every record there is, those two included',
   groups['records']['rows'], 3)

gone = store.erase(['otp'])
daemon.drop_tails(['otp'])
ok('erasing the token records takes the one row', gone['otp'], 1)
ok('...and leaves the eduroam row where it was',
   len(store.db.execute("SELECT 1 FROM passed WHERE session >= 'edu/' "
                        "AND session < 'edu0'").fetchall()), 1)
ok('...and the ISE record',
   len(store.db.execute('SELECT 1 FROM failed').fetchall()), 1)
ok('...and forgets where the token log was read up to',
   [p for p in (store.meta_json('tails', {}) or {}) if 'otp' in p], [])
ok('...without forgetting where the others were \u2014 two ISE files and two eduroam ones',
   len([p for p in (store.meta_json('tails', {}) or {}) if 'otp' not in p]), 4)

daemon.read_logs()
back = store.db.execute("SELECT ts FROM passed WHERE session >= 'otp/' "
                        "AND session < 'otp0'").fetchall()
ok('the next pass reads the token log again from the beginning', len(back), 1)
ok('...and this time the line is the right second', back[0]['ts'], WROTE_AT)
ok('...which is the whole point of the exercise', when(back[0]['ts']), when(WROTE_AT))
ok('...and that file is no longer marked as ahead of the clock',
   [t['ahead'] for t in daemon.status()['logs'] if 'totp' in t['path']], [0])
ok('...while the eduroam log, which has not been read again yet, still is',
   [t['ahead'] > 0 for t in daemon.status()['logs'] if 'radius.log' in t['path']], [True])

title('...and the complaint survives a restart, because the file still is ahead')
# The zone put back to this machine's, which is what a daemon restarted
# before anybody has fixed anything is looking at.
isemon.CONFIG['log_zone'] = ''
isemon._ZONES.clear()
# Dated WROTE_AT rather than "now": the check below compares the row with
# WROTE_AT, and a second rolling over between the two made it fail for one
# second in every sixty.
(edu / isemon.CONFIG['eduroam_name']).write_text(
    EDU_LINE.replace('Sep 25 11:32:48', prague_now(WROTE_AT), 1) + '\n'
    + EDU_LINE.replace('Sep 25 11:32:48', prague_now(WROTE_AT - 60), 1)
    .replace('10551100', '10551101') + '\n')
daemon.read_logs()
daemon.save_tails()
again = isemon.Daemon(store)
again.restore_tails()
ok('a daemon started again still knows that file is dated ahead',
   [t['ahead'] > 0 for t in again.status()['logs'] if 'radius.log' in t['path']], [True])
ok('...and does not carry it to a file that never was',
   [t['ahead'] for t in again.status()['logs'] if 'CISE' in t['path']], [0, 0])

isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()
store.erase(['eduroam'])
daemon.drop_tails(['eduroam', 'eduroam-detail'])
daemon.read_logs()
ok('the eduroam log goes the same way', store.db.execute(
    "SELECT ts FROM passed WHERE session >= 'edu/' AND session < 'edu0'"
).fetchone()['ts'], WROTE_AT)

title('Going back over every log does not double what it cannot judge')
# What a token or eduroam record is called carries the second its line says,
# so the same line read again in a different zone is a different record. The
# pass that applies what the logs earn therefore leaves those two logs alone
# - there is nothing in either for it to apply.
before = store.db.execute("SELECT COUNT(*) AS n FROM passed").fetchone()['n']
isemon.CONFIG['log_zone'] = 'UTC'          # somebody corrects the zone...
isemon._ZONES.clear()
daemon.rescan()                             # ...and then presses the button
ok('the token and eduroam rows are not written a second time',
   store.db.execute("SELECT COUNT(*) AS n FROM passed").fetchone()['n'], before)
ok('...and the ISE records are read again as they always were',
   store.db.execute("SELECT COUNT(*) AS n FROM failed").fetchone()['n'], 1)
isemon.CONFIG['log_zone'] = 'Europe/Prague'
isemon._ZONES.clear()

title('The erase takes the door it names and nothing that merely looks like it')
# An ISE node called `otp` writes session ids beginning `otp/`, and a range
# over the session id would have taken its VPN records with the token ones.
with store.db_write() as db:
    db.execute("INSERT INTO failed (session, ts, server, ip, username, kind) "
               "VALUES ('otp/569337134/7', ?, 'otp', '203.0.113.9', 'jnovak', 'vpn')",
               (PRAGUE,))
    db.execute("INSERT INTO failed (session, ts, server, ip, username, kind) "
               "VALUES ('edu/569337134/8', ?, 'edu', '203.0.113.9', 'jnovak', 'vpn')",
               (PRAGUE,))
had = store.db.execute("SELECT COUNT(*) AS n FROM failed WHERE kind='vpn'").fetchone()['n']
store.erase(['otp', 'eduroam'])
ok('a VPN record from a node that happens to be called otp is not a token record',
   store.db.execute("SELECT COUNT(*) AS n FROM failed WHERE kind='vpn'").fetchone()['n'], had)
ok('...and the same for one called edu',
   sorted(r['session'] for r in
          store.db.execute("SELECT session FROM failed WHERE kind='vpn' "
                           "AND (session LIKE 'otp/%' OR session LIKE 'edu/%')")),
   ['edu/569337134/8', 'otp/569337134/7'])

title('...and forgetting where a log was read never reaches the ISE logs')
# A site whose token folder is the parent of its ISE folders: legal, and
# under a plain prefix test it would have had both ISE logs re-read.
isemon.CONFIG['otp_paths'] = [str(Path(folder))]
store.set_meta('tails', json.dumps({
    str(Path(folder) / 'ise' / 'CISE_Failed_Attempts.log'): {'offset': 500},
    str(Path(folder) / 'otp' / 'totp.cgi.log'): {'offset': 700},
}))
store.forget_tails('otp')
left = sorted(os.path.basename(p) for p in (store.meta_json('tails', {}) or {}))
ok('the ISE position is where it was', left, ['CISE_Failed_Attempts.log'])

title('...and none of it can let anybody in or keep anybody out')
ok('nothing was banned by any of this', len(store.blocked_all()), 0)
ok('the settings are where they were', isemon.CONFIG['log_zone'], 'Europe/Prague')
ok('erasing a log’s records never touches the accounts',
   [r['name'] for r in store.users()], [r['name'] for r in store.users()])
ok('...and an ISE log is never one of the things that can be re-read: what is '
   'no longer in it cannot be got back', isemon.log_folders('ise'), [])

shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
# A bar a day wide has to be a day where the person reading it lives, and the
# database groups by seconds since 1970 - so the folding into days is done
# here, where there is a calendar. In most of the world a local day starts on
# a UTC hour boundary and the chart can be asked for by the hour; in India,
# Nepal and South Australia it does not, and an hourly slot straddles two
# local days. Everything in the first half hour of every day was counted on
# the day before, and everything in the first half hour of the window was
# dropped outright.
title('A day that does not start on the hour')
for zone, offset in (('Europe/Prague', 7200), ('Asia/Kolkata', 19800),
                     ('Australia/Adelaide', 34200), ('Asia/Kathmandu', 20700)):
    os.environ['TZ'] = zone
    time.tzset()
    folder, otp, edu, store, daemon = fresh()
    # Four moments around one local midnight, written as what the clock in
    # that zone says. The day they belong to is not in doubt to anybody
    # looking at a screen there: 23:50 is yesterday and 00:10 is today.
    midnight = (int((NOW - 86400 * 30) // 86400) * 86400) - offset + 86400
    want = {}
    for minutes, who in ((-70, 'late'), (-10, 'just-before'),
                         (10, 'just-after'), (70, 'well-into')):
        at = midnight + minutes * 60
        day = int(time.mktime(time.localtime(at)[:3] + (0, 0, 0, 0, 0, -1)))
        want.setdefault(day, []).append(who)
        store.add_failed({'session': 'clock/%s' % who, 'ts': at, 'ip': '203.0.113.7',
                          'username': who, 'server': 'ise2', 'kind': 'vpn',
                          'reason': 'a test', 'detail': '{}'})
    # A window reaching back to that night from the real clock, whatever day
    # the test is run on: the moments are fixed, the clock is not.
    reach = int((time.time() - midnight) // 3600) + 72
    bars = {int(b['ts']): b for b in store.auth_counts(reach, 86400)}
    ok('in %s every bar is a local midnight' % zone,
       all(time.localtime(ts)[3:6] == (0, 0, 0) for ts in bars), True)
    for day, who in want.items():
        ok('...and the %d refusal(s) of %s are on that day'
           % (len(who), time.strftime('%d-%m', time.localtime(day))),
           bars.get(day, {}).get('failed'), len(who))
    ok('...and none of them were lost', sum(b['failed'] for b in bars.values()), 4)
    shutil.rmtree(folder, ignore_errors=True)
os.environ['TZ'] = 'America/New_York'
time.tzset()

print('\nThe night the clocks go back')
from datetime import datetime
_was_zone = isemon.CONFIG.get('log_zone')
isemon.CONFIG['log_zone'] = 'Europe/Prague'
from zoneinfo import ZoneInfo as _Z
_pz = _Z('Europe/Prague')
isemon._NPS_LAST['ts'] = 0.0
said_at = []
for clock in ('01:59:00', '02:30:00', '02:59:59', '02:00:05', '02:30:00', '03:00:00'):
    m = isemon.NPS_START.search('"NPS01","IAS",10/25/2026,%s,1,' % clock)
    said_at.append(datetime.fromtimestamp(isemon.nps_when(m), _pz).strftime('%H:%M:%S%z'))
ok('02:00 to 02:59 read twice is two different hours, in the order they happened',
   said_at, ['01:59:00+0200', '02:30:00+0200', '02:59:59+0200',
             '02:00:05+0100', '02:30:00+0100', '03:00:00+0100'])
ok('...and so always later than the line before',
   sorted(said_at, key=lambda t: (t[-5:] != '+0200', t)) == said_at, True)
# A request read in the first 02:30 and its answer in the second are an hour
# apart; a request and answer both in the second one are the same moment.
isemon._NPS_LAST['ts'] = 0.0
isemon.nps_when(isemon.NPS_START.search('"NPS01","IAS",10/25/2026,02:59:30,1,'))
ask_ = isemon.nps_when(isemon.NPS_START.search('"NPS01","IAS",10/25/2026,02:10:00,1,'))
ans_ = isemon.nps_when(isemon.NPS_START.search('"NPS01","IAS",10/25/2026,02:10:00,2,'))
ok('...a request and its answer in the second one are the same moment', ans_ - ask_, 0.0)
isemon.CONFIG['log_zone'] = _was_zone

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
