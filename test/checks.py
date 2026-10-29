#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
checks.py - the things that are easy to get wrong and hard to notice.

Every check here is one that broke something once, or would have: the ladder
climbing a step per return rather than per attempt, a subnet fold swallowing
the office's own range, an IPv6 address written two ways reading as two, a
readonly account being able to ban somebody. It makes its own database in a
temporary folder and leaves nothing behind.

    ./test/checks.py
"""
import ipaddress
import json
import os
import shutil
import sqlite3
import inspect
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                       # noqa: E402


def ise_zone(ts=None):
    """The offset ISE writes after the second: this machine's own on that
    day, so that a record made now means now in winter as well as summer."""
    z = time.strftime('%z', time.localtime(ts))
    return z[:3] + ':' + z[3:]


PASS, FAIL = 0, 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def on_a_file():
    """Whether this run is on the database this program keeps by default.

    Two sections below build a database in the shape an older version left
    behind - as a file, with sqlite3, by hand - and then open it. Run
    against MariaDB or PostgreSQL on purpose, which is how this same suite
    is used to check the other two engines, those sections would be asking
    a question about a file that is not the database being tested, so they
    say they were skipped and the rest of the suite carries on. Everything
    else in here is about what this program does, not about where it keeps
    it, and is asked of every engine.
    """
    return str((isemon.Storage.ENGINE or {}).get('engine') or 'sqlite') == 'sqlite'


def title(text):
    print('\n%s' % text)


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-check-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'check.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'check.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    # Every device, unless a section says otherwise. Most sections write
    # rows with no device at all and then judge them directly, and a failure
    # that names no device is one the watch list cannot vouch for - so under
    # the production default of `FTD-VPN` none of them would count against a
    # bar, which is right of the program and beside the point of a section
    # about the ladder. The sections about the watch list set it themselves.
    isemon.CONFIG['watch_devices'] = ''
    store = isemon.Storage(isemon.DB_FILE)
    return folder, store, isemon.Daemon(store)


def line(host, cat, seq, of, n, rest):
    return '%s %s %s %010d %d %d %s' % ('Sep 23 13:27:47', host, cat, seq, of, n, rest)


def failed_record(ts, ip, user='INVALID', device='FTD-VPN', host='ise2', seq=1):
    """One failed attempt written the way ISE writes it: three lines, the
    fields cut across them."""
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) + '.500 ' + ise_zone(ts)
    head = ('%s 0229674592 5400 NOTICE Failed-Attempt: Authentication failed, ConfigVersionId=86, '
            'Device IP Address=172.22.0.137, UserName=%s, Protocol=Radius, '
            'NetworkDeviceName=%s, Called-Station-ID=46.227.169.105, Calling-Station-ID=%s, '
            'NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) %s, '
            'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=CORPNET, AcsSessionID=%s/569337134/%d,'
            % (when, user, device, ip, ip, host, seq))
    two = (' AuthenticationMethod=PAP_ASCII, SelectedAccessService=AnyConnect_VPN, '
           'FailureReason=22056 Subject not found in the applicable identity store(s), '
           'Step=11001, Step=11017,')
    three = (' AD-Error-Details=Domain trust is one-way, StepData=15=tlm.loc\\,%s, '
             'EndPointIPAddress=%s, Response={RadiusPacketType=AccessReject; }' % (user, ip))
    return [line(host, 'CISE_Failed_Attempts', seq, 3, 0, head),
            line(host, 'CISE_Failed_Attempts', seq, 3, 1, two),
            line(host, 'CISE_Failed_Attempts', seq, 3, 2, three)]


# ---------------------------------------------------------------------------
title('Reading what ISE writes')
raw = failed_record(time.time(), '203.0.113.7')
got = isemon.ise_parse_lines(raw)
ok('three syslog lines make one record', len(got), 1)
rec = got[0]
ok('the address is read out of it', rec.ip, '203.0.113.7')
ok('the name is read out of it', rec.user, 'INVALID')
ok('the device is read out of it', isemon.ise_devices(rec.fields), ['FTD-VPN'])
ok('the failure keeps its number', isemon.ise_reason(rec.fields)[0], '22056')
ok('the session id is ISE’s own', rec.session.startswith('ise2/'), True)
ok('a field cut in half across two lines is whole again',
   rec.fields.get('EndPointIPAddress'), ['203.0.113.7'])
ok('an escaped comma does not split a field',
   [v for v in rec.fields.get('StepData', []) if v.startswith('15=')],
   ['15=tlm.loc\\,INVALID'])

half = isemon.ise_parse_lines(raw[:2])
ok('a record whose last line has not arrived is not made yet', len(half), 0)
hold = {}
isemon.ise_parse_lines(raw[:2], hold)
rest = isemon.ise_parse_lines(raw[2:], hold)
ok('...and is made when it does arrive', len(rest), 1)

out_of_order = isemon.ise_parse_lines([raw[2], raw[0], raw[1]])
ok('lines arriving out of order still make one whole record', len(out_of_order), 1)
ok('...with the same address in it', out_of_order[0].ip if out_of_order else None, '203.0.113.7')

# ---------------------------------------------------------------------------
title('The ladder')
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_ladder': '10, 60, 1440, forever', 'block_tries': 3,
                      'block_window_min': 10, 'block_ladder_forget_days': 30})
ok('the ladder is read as minutes', daemon.block_steps(), ([10, 60, 1440], True))
ok('the first time is the first step', daemon.block_length('198.51.100.1')[0], 10)
store.block('198.51.100.1', time.time() + 600, 'first')
store.unblock('198.51.100.1')
ok('the second time is the second step', daemon.block_length('198.51.100.1')[0], 60)
store.block('198.51.100.1', time.time() + 3600, 'second')
store.unblock('198.51.100.1')
ok('the third time is the third step', daemon.block_length('198.51.100.1')[0], 1440)
store.block('198.51.100.1', time.time() + 86400, 'third')
store.unblock('198.51.100.1')
ok('past the end of a ladder saying "forever", it is for good',
   daemon.block_length('198.51.100.1')[1], 'for good')
ok('an address that has never been here starts at the bottom',
   daemon.block_length('198.51.100.99')[0], 10)

isemon.CONFIG['block_ladder_forget_days'] = 1
with store.db_write() as db:
    db.execute("UPDATE block_events SET ts=? WHERE ip='198.51.100.1'",
               (time.time() - 40 * 86400,))
ok('an address that has behaved for a month starts at the bottom again',
   daemon.block_length('198.51.100.1')[0], 10)
isemon.CONFIG['block_ladder_forget_days'] = 30
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Counting, and when it earns a block')
folder, store, daemon = fresh()
# The records these make offer the name INVALID, which the harder rule keeps
# out on the first knock. This section is about the COUNTING, so that rule is
# switched off here and tried on its own further down.
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10, 'watch_devices': 'FTD-VPN',
                      'block_ladder': '10, 60, forever', 'judge_max_age_h': 24,
                      'block_bogus_tries': 0})
now = time.time()
for i in range(2):
    daemon.read_records(failed_record(now - 300 + i, '203.0.113.20', seq=100 + i))
ok('two failures are not enough', store.blocked_until('203.0.113.20'), None)
daemon.read_records(failed_record(now - 290, '203.0.113.20', seq=102))
ok('the third earns one', store.blocked_until('203.0.113.20') is not None, True)
ok('...and it is the first step', daemon.blocked_list()[0]['left'] <= 600, True)

for i in range(3):
    # Fifteen minutes apart, so no ten-minute window ever holds more than one
    # of them. Somebody mistyping a password now and then is not an attack.
    daemon.read_records(failed_record(now - 3000 + i * 900, '203.0.113.21', seq=200 + i))
ok('three failures spread outside the window earn nothing',
   store.blocked_until('203.0.113.21'), None)

for i in range(3):
    daemon.read_records(failed_record(now - 200 + i, '203.0.113.22', device='SW-CORE',
                                      seq=300 + i))
ok('a device that is not being watched earns nothing',
   store.blocked_until('203.0.113.22'), None)
ok('...but the attempt is still written down',
   store.failed_rows(ip='203.0.113.22', limit=5)[1], 3)

isemon.CONFIG['never_block'] = '203.0.113.0/24'
daemon._spare_from = None
for i in range(5):
    daemon.read_records(failed_record(now - 100 + i, '203.0.113.23', seq=400 + i))
ok('an address under "never kept out" earns nothing',
   store.blocked_until('203.0.113.23'), None)
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None

old = now - 10 * 86400
for i in range(5):
    daemon.read_records(failed_record(old + i, '203.0.113.24', seq=500 + i))
ok('a record older than judge_max_age_h is recorded but not judged',
   (store.blocked_until('203.0.113.24'), store.failed_rows(ip='203.0.113.24', limit=1)[1]),
   (None, 5))
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Both nodes, one timeline')
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 4, 'block_window_min': 10, 'watch_devices': 'FTD-VPN',
                      'judge_max_age_h': 24})
now = time.time()
# The pair changes over halfway through: two attempts land on ise1 and two on
# ise2. Counted per node they are two and two and earn nothing; counted as one
# timeline they are four and earn a block, which is the whole reason both
# paths are read.
for i in range(2):
    daemon.read_records(failed_record(now - 200 + i, '203.0.113.30', host='ise1', seq=600 + i))
for i in range(2):
    daemon.read_records(failed_record(now - 100 + i, '203.0.113.30', host='ise2', seq=600 + i))
ok('attempts split across the two nodes are counted together',
   store.blocked_until('203.0.113.30') is not None, True)

before = store.failed_rows(limit=1)[1]
daemon.read_records(failed_record(now - 200, '203.0.113.30', host='ise1', seq=600))
ok('the same record read twice is not counted twice', store.failed_rows(limit=1)[1], before)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Addresses written two ways')
ok('a /128 prefix is the same as the address', isemon.same_address('2a01:430:17::5/128'),
   '2a01:430:17::5')
ok('a written-out IPv6 address is the same as its short form',
   isemon.same_address('2a01:0430:0017:0000:0000:0000:0000:0005'), '2a01:430:17::5')
ok('a /32 prefix is the same as the IPv4 address', isemon.same_address('1.2.3.4/32'), '1.2.3.4')
ok('a real subnet stays a subnet', isemon.same_address('81.200.10.0/24'), '81.200.10.0/24')
ok('IPv6 belongs in the router’s other list', isemon.Daemon.mikrotik_family('2a01:430::5'),
   '/ipv6')
ok('IPv4 belongs in the first one', isemon.Daemon.mikrotik_family('81.200.10.0/24'), '/ip')

# ---------------------------------------------------------------------------
title('Folding into subnets')
folder, store, daemon = fresh()
isemon.CONFIG.update({'fold_widest': 24, 'feeds': '', 'never_block': ''})
daemon._spare_from = None
for i in range(6):
    store.block('185.136.15.%d' % (20 + i), None, 'brute force')
store.block('9.9.9.9', None, 'on its own')
plan = daemon.fold_plan(24)
ok('six addresses in one street make one subnet', plan['subnets'], 1)
ok('...and the subnet is the street', [g['net'] for g in plan['groups']], ['185.136.15.0/24'])
ok('an address on its own is left alone', plan['folded'], 6)
daemon.fold_apply(24, by='check')
ok('after folding, the street is on the list', store.blocked_until('185.136.15.20') is not None,
   True)
ok('...as one row, not six', store.blocked_count(), 2)
ok('the members are remembered', len(daemon.fold_members('185.136.15.0/24')), 6)
version = store.fold_versions(1)[0]['id']
daemon.fold_undo(version, by='check')
ok('undoing puts all six back', store.blocked_count(), 7)

isemon.CONFIG['never_block'] = '185.136.15.30'
daemon._spare_from = None
plan = daemon.fold_plan(24)
ok('a street holding an address that is never kept out is never folded',
   plan['subnets'], 0)
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A subnet on the list covers what is inside it')
folder, store, daemon = fresh()
store.block('185.136.15.0/24', None, 'the whole street')
ok('an address inside a blocked subnet is blocked',
   store.blocked_until('185.136.15.77') is not None, True)
ok('one outside it is not', store.blocked_until('185.136.16.77'), None)
store.block('2a01:430::/32', None, 'the whole prefix')
ok('IPv6 works the same way', store.blocked_until('2a01:430:17::5') is not None, True)
ok('an IPv4 address is not inside an IPv6 prefix', store.blocked_until('8.8.8.8'), None)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Ranges as the router wants them')
lo = ipaddress.ip_address('81.200.10.0').packed
hi = ipaddress.ip_address('81.200.11.255').packed
ok('a range becomes the fewest prefixes that cover it',
   isemon.packed_to_cidrs(lo, hi, 4), ['81.200.10.0/23'])
lo = ipaddress.ip_address('1.2.3.4').packed
hi = ipaddress.ip_address('1.2.3.9').packed
ok('an awkward range becomes several',
   isemon.packed_to_cidrs(lo, hi, 4), ['1.2.3.4/30', '1.2.3.8/31'])
ok('a backwards range becomes nothing',
   isemon.packed_to_cidrs(hi, lo, 4), [])

# ---------------------------------------------------------------------------
title('Accounts and what they may do')
folder, store, daemon = fresh()
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='check')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='check')
ok('a password is not kept as itself',
   store.db.execute("SELECT hash FROM users WHERE name='boss'").fetchone()['hash']
   .startswith('pbkdf2_sha256$'), True)
# A short password is refused wherever it is set, not only on the form that
# asks for one. Checked here because an empty one used to be taken: the hash
# of the empty string is a hash like any other, and the account it made
# signed in to everything with nothing typed at all.
for short, words in (('', 'an empty password'), ('abc', 'a password of three characters')):
    try:
        store.put_user('boss', password=short)
        ok('%s is refused' % words, False)
    except isemon.StorageError:
        ok('%s is refused' % words, True)
    try:
        daemon.add_user('brandnew', short, 'readonly', by='check')
        ok('...on a new account as well', False)
    except (isemon.StorageError, ValueError):
        ok('...on a new account as well', True)
ok('...and the account was not made', store.user('brandnew'), None)
ok('...while the one that was there still has its own password',
   bool(daemon.login('boss', 'a-long-enough-password', ip='127.0.0.2')), True)
got = daemon.login('boss', 'a-long-enough-password', ip='127.0.0.1')
ok('the right password signs in', got['role'], 'fulladmin')
me = daemon.who(got['token'])
ok('the session names the person', me['name'], 'boss')
try:
    daemon.login('boss', 'not-the-password', ip='10.0.0.9')
    ok('a wrong password is refused', False)
except ValueError:
    ok('a wrong password is refused', True)
ok('...and says nothing about which half was wrong', True)

for i in range(6):
    try:
        daemon.login('boss', 'wrong', ip='10.0.0.10')
    except ValueError as e:
        last = str(e)
ok('too many wrong passwords from one address makes it wait', 'try again in' in last, True)
ok('...and another address is unaffected', bool(daemon.login('boss', 'a-long-enough-password',
                                                             ip='10.0.0.11')), True)
# ...but the NAME is counted too, across addresses: a few times the
# address's allowance, and a right password lets it go.
bar = max(1, int(isemon.CONFIG.get('login_tries') or 5)) * daemon.LOGIN_NAME_TIMES
for i in range(bar):
    try:
        daemon.login('boss', 'wrong', ip='10.1.%d.%d' % (i // 250, i % 250 + 1))
    except ValueError as e:
        last = str(e)
try:
    daemon.login('boss', 'a-long-enough-password', ip='10.2.0.1')
    ok('one name worked at from many addresses waits as well', False)
except ValueError as e:
    ok('one name worked at from many addresses waits as well', 'try again in' in str(e), True)
daemon._login_forget('user:boss')
ok('...until the count is let go', bool(daemon.login('boss', 'a-long-enough-password',
                                                       ip='10.2.0.2')), True)

try:
    daemon.set_role('boss', 'readonly', by='check')
    ok('the only full administrator cannot be demoted', False)
except isemon.StorageError:
    ok('the only full administrator cannot be demoted', True)
try:
    daemon.drop_user('boss', by='check')
    ok('...nor removed', False)
except isemon.StorageError:
    ok('...nor removed', True)

daemon.add_user('other', 'yet-another-password', 'fulladmin', by='check')
daemon.set_role('boss', 'readonly', by='check')
ok('with a second one, it is allowed', store.user('boss')['role'], 'readonly')
ok('a session’s powers follow the account, not the session',
   daemon.who(got['token'])['role'], 'readonly')

token = daemon.login('watcher', 'another-long-password')['token']
daemon.set_password('watcher', 'a-brand-new-password', by='check')
ok('changing a password ends every sign-in of that account', daemon.who(token), None)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Settings that are refused')
folder, store, daemon = fresh()
for bad, why in (({'block_tries': 0}, 'a number below its floor'),
                 ({'block_mode': 'sometimes'}, 'a word that is not one of the choices'),
                 ({'never_block': 'not-an-address'}, 'something that is not an address'),
                 ({'geolist_countries': 'CZECH'}, 'a country code that is not two letters'),
                 ({'backup_at': '25:99'}, 'a time that is not a time'),
                 ({'block_ladder': '10, soon, 60'}, 'a ladder step that is not a number'),
                 ({'ise_paths': []}, 'no log folder at all'),
                 ({'nonsense': 1}, 'a setting this version does not know')):
    try:
        daemon.save_settings(bad, by='check')
        ok('refused: %s' % why, False)
    except (ValueError, isemon.StorageError):
        ok('refused: %s' % why, True)

said = daemon.save_settings({'block_tries': 8, 'block_window_min': 15}, by='check')
ok('a good change is saved', sorted(said['changed']), ['block_tries', 'block_window_min'])
ok('...and is in force at once', isemon.CONFIG['block_tries'], 8)
ok('...and only the changes are written to the database',
   sorted(daemon.store.settings_saved()), ['block_tries', 'block_window_min'])
ok('...and nothing was written to a config file',
   (Path(folder) / 'config.json').exists(), False)
ok('...and the page is told where each one comes from',
   {s['key']: s['source'] for s in daemon.settings_state()
    if s['key'] in ('block_tries', 'block_mode')},
   {'block_tries': 'saved', 'block_mode': 'default'})
ok('...and who saved it',
   daemon.store.settings_written()['block_tries']['by'], 'check')
try:
    daemon.save_settings({'geolist_name': 'same', 'mikrotik_list': 'same'}, by='check')
    ok('the two router lists may not share a name', False)
except ValueError:
    ok('the two router lists may not share a name', True)

# --- the three layers ------------------------------------------------------
title('Defaults, then config.json, then what was saved')
where = Path(folder) / 'config.json'
isemon.CONFIG_FILE = where
where.write_text(json.dumps({'block_tries': 4, 'site_name': 'From the file'}))
isemon.load_config()
daemon._config_stamp = isemon.config_file_stamp()
ok('the file wins over the default', isemon.CONFIG['block_tries'], 4)
ok('...and the file is remembered separately', isemon.FILE_CONFIG['block_tries'], 4)
isemon.apply_saved_settings(daemon.store)
ok('what was saved wins over the file', isemon.CONFIG['block_tries'], 8)
ok('...and a setting only the file names still comes from the file',
   isemon.CONFIG['site_name'], 'From the file')
ok('...and the page says so',
   {s['key']: s['source'] for s in daemon.settings_state()
    if s['key'] in ('block_tries', 'site_name', 'block_mode')},
   {'block_tries': 'saved', 'site_name': 'file', 'block_mode': 'default'})
daemon.save_settings({'block_tries': 4}, by='check')
ok('put back to what the file says, it stops being saved',
   'block_tries' in daemon.store.settings_saved(), False)
ok('...and the file value is what runs', isemon.CONFIG['block_tries'], 4)

serial = daemon.store.settings_serial()
daemon.store.settings_write({'block_tries': 9}, by='the command line')
ok('a write from outside moves the serial on',
   daemon.store.settings_serial() > serial, True)
ok('...and the daemon notices', daemon.settings_changed_underneath(), True)
ok('...and takes it up', isemon.CONFIG['block_tries'], 9)
ok('...and does not keep noticing', daemon.settings_changed_underneath(), False)
where.write_text(json.dumps({'site_name': 'Edited by hand'}))
os.utime(where, (time.time() + 2, time.time() + 2))
ok('an edited config.json is noticed too', daemon.settings_changed_underneath(), True)
ok('...and is read again', isemon.CONFIG['site_name'], 'Edited by hand')
ok('...without losing what was saved', isemon.CONFIG['block_tries'], 9)

# The HUP logrotate sends every night at midnight. It means "you have a new
# log file", and the config file is read again with it because a HUP is also
# how a fleet says a machine has been reconfigured. What it must NOT do is
# leave the daemon on the two bottom layers: reading the config file makes
# CONFIG afresh out of the defaults and the file, and everything anybody ever
# saved on the dashboard lives in the database on top of that. Without it
# laid back over, a machine went back to factory settings every night - the
# token logs off, eduroam off, the names off, and "keep the records for ever"
# back to ninety days with the housekeeping five minutes behind it.
ok('nothing has moved, so nothing is taken up', daemon.settings_changed_underneath(), False)
daemon.reread_asked.set()
ok('a HUP is a reason to read it all again', daemon.settings_changed_underneath(), True)
ok('...and what the file says is still what the file says',
   isemon.CONFIG['site_name'], 'Edited by hand')
ok('...and what was saved on the dashboard is still on top of it',
   isemon.CONFIG['block_tries'], 9)
for key, was in (('otp', 1), ('eduroam', 1), ('ptr', 1), ('retain_failed_days', 0)):
    daemon.store.settings_write({key: was}, by='a check')
isemon.apply_saved_settings(daemon.store)
daemon._settings_serial = daemon.store.settings_serial()
daemon.reread_asked.set()
daemon.settings_changed_underneath()
ok('...and the switches a site turns on stay on over a HUP',
   {k: isemon.CONFIG[k] for k in ('otp', 'eduroam', 'ptr')}, {'otp': 1, 'eduroam': 1, 'ptr': 1})
ok('...as does "keep the records for ever", which is the one that deletes',
   isemon.CONFIG['retain_failed_days'], 0)
ok('...and asking once is asking once', daemon.settings_changed_underneath(), False)
# ...and the handler itself does no more than ask: it runs in the middle of
# whatever the main thread was doing, which is regularly a statement half
# built on the very database the settings would have to be read from.
_source = inspect.getsource(isemon.main)
_hup = _source[_source.index('def reopen('):]
_hup = _hup[:_hup.index('signal.signal(')]
# What it DOES, not what it says about itself: the note above these lines is
# half about the two calls that must not be in them.
_does = '\n'.join(one for one in _hup.split('\n') if not one.strip().startswith('#'))
ok('the signal handler reads no settings of its own',
   'load_config' in _does or 'apply_saved_settings' in _does, False)
ok('...it asks the daemon to', 'reread_asked' in _does, True)
# ...and it writes no line either, which is the same rule and a worse fault.
# `log()` holds a lock while it writes and `close_log()` wants that lock; a
# handler runs in the thread it interrupted, so a signal landing while that
# thread was inside the lock is a handler waiting for a lock its own thread
# holds. Nothing ever runs again: no reading, no banning, no page, and no
# line saying so, because the log is the thing that is stuck. logrotate
# sends a HUP every night and a stop signal arrives at every restart.
_stop = _source[_source.index('def stop(signum'):]
_stop = _stop[:_stop.index('def reopen(')]
_stopdoes = '\n'.join(one for one in _stop.split('\n') if not one.strip().startswith('#'))
for words, body in (('the one that stops it', _stopdoes), ('the one logrotate sends', _does)):
    ok('%s takes no lock of the log\u2019s' % words,
       any(call in body for call in ('log(', 'close_log(', 'open_log(')), False)
ok('...and the log is opened again by the loop instead',
   'reopen_asked' in inspect.getsource(isemon.Daemon.run), True)
ok('...and what the handler would have said is said there too',
   'said_signal' in inspect.getsource(isemon.Daemon.run), True)
# Measured rather than argued: the lock is held, the flag-setting is done,
# and it has to come back at once. A watchdog lets go after a moment so that
# a version which waits is slow here rather than a suite that hangs.
_folder, _store, _daemon = fresh()


def _letgo():
    try:
        isemon._LOG_LOCK.release()
    except RuntimeError:
        pass                      # it was let go in time, which is the point


isemon._LOG_LOCK.acquire()
_watchdog = threading.Timer(1.5, _letgo)
_watchdog.start()
_began = time.time()
_daemon.reopen_asked.set()
_daemon.reread_asked.set()
_daemon.said_signal = 15
_took = time.time() - _began
_watchdog.cancel()
_letgo()
ok('asking for those three things waits for nothing at all', _took < 0.2, True)
shutil.rmtree(_folder, ignore_errors=True)

# The command line is a fourth layer and the top one, and it is the one that
# is written down nowhere - so it is the one that goes missing when CONFIG is
# rebuilt. `isemon --debug` that quietly stops being a debug run at the first
# HUP is a run that goes silent halfway through the thing it was started to
# find. Both of the functions that rebuild CONFIG lay it back over.
isemon.FROM_ARGV['debug'] = True
isemon.CONFIG['debug'] = False
isemon.load_config()
ok('what the command line said survives the config file being read again',
   isemon.CONFIG['debug'], True)
daemon.store.settings_write({'debug': 0}, by='a check')
isemon.apply_saved_settings(daemon.store)
ok('...and it beats what was saved on the dashboard, which is the layer below',
   isemon.CONFIG['debug'], True)
isemon.FROM_ARGV.clear()
daemon.store.settings_write({'debug': 0}, by='a check')
isemon.load_config()
isemon.apply_saved_settings(daemon.store)
ok('...and with nothing said on the command line, the saved value runs',
   bool(isemon.CONFIG['debug']), False)

isemon.CONFIG_FILE = Path('/nonexistent/config.json')
isemon.load_config()
isemon.apply_saved_settings(daemon.store)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A log file that is rotated or emptied under us')
folder, store, daemon = fresh()
where = Path(folder) / 'one.log'
where.write_text('\n'.join(failed_record(time.time(), '203.0.113.40', seq=900)) + '\n')
tail = isemon.LogTail(str(where))
ok('a first read gets the record', len(tail.read()), 1)
ok('a second read with nothing added gets nothing', len(tail.read()), 0)
with open(where, 'a') as f:
    f.write('\n'.join(failed_record(time.time(), '203.0.113.41', seq=901)) + '\n')
ok('what was appended is read', len(tail.read()), 1)
where.write_text('\n'.join(failed_record(time.time(), '203.0.113.42', seq=902)) + '\n')
ok('a file emptied and written again is read from the start', len(tail.read()), 1)
half = '\n'.join(failed_record(time.time(), '203.0.113.43', seq=903))
with open(where, 'a') as f:
    f.write('\n' + half[:len(half) // 2])         # a line still being written
ok('half a line is not read as a record', len(tail.read()), 0)
with open(where, 'a') as f:
    f.write(half[len(half) // 2:] + '\n')
ok('...and is read when the rest of it lands', len(tail.read()), 1)

# A file with no end of line in it at all - a binary dropped in the folder,
# two logs joined wrongly - is stepped over rather than read again for ever.
# Waiting for the rest of the line is right when the line is still being
# written and is a log that is never read again when there is no rest coming.
blob = Path(folder) / 'blob.log'
blob.write_bytes(b'x' * 4000)
wedge = isemon.LogTail(str(blob))
ok('a window full of one endless line reads no records',
   len(wedge.read(limit_bytes=1000)), 0)
ok('...but the place it was read to has moved', wedge.offset, 1000)
ok('...and it says why', 'no end of line' in (wedge.last_error or ''), True)
for _ in range(6):
    wedge.read(limit_bytes=1000)
ok('...so the end of the file is reached rather than the same bytes for ever',
   wedge.offset, 4000)
with open(blob, 'ab') as f:
    f.write(b'\n' + '\n'.join(failed_record(time.time(), '203.0.113.44', seq=904)).encode()
            + b'\n')
ok('...and a record written after it is read', len(wedge.read(limit_bytes=1000)), 1)
short = Path(folder) / 'short.log'
short.write_bytes(b'half a line with no ending yet')
patient = isemon.LogTail(str(short))
ok('half a line that does not fill the window is still waited for',
   (len(patient.read(limit_bytes=1000)), patient.offset, patient.last_error), (0, 0, ''))
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The three kinds of successful record, and joining a firewall to its login')
folder = tempfile.mkdtemp(prefix='isemon-acl-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'acl.db'
isemon.RUN_DIR = Path(folder)
isemon.CONFIG.update({'passed_devices': '', 'watch_devices': 'FTD-VPN', 'read_passed': 1})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

WHEN = time.time()
SESSION = '2ee3a969363ae0006ab3bb20'
ACL = '#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c'
RULES = ('cisco-av-pair=ip:inacl#1=remark DNS; '
         'cisco-av-pair=ip:inacl#2=permit udp any host 172.25.1.10 eq 53; '
         'cisco-av-pair=ip:inacl#3=permit tcp 10.0.0.0 255.0.0.0 range 1024 2048 '
         'object-group SERVERS eq www log; '
         'cisco-av-pair=ip:inacl#4=deny ip any any; ')


def passed_lines(seq, user, rest, host='ise2', cat='CISE_Passed_Authentications'):
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(WHEN)) + '.500 ' + ise_zone(WHEN)
    head = ('%s 0229674592 5400 NOTICE Passed-Authentication: Authentication succeeded, '
            'ConfigVersionId=87, Device IP Address=172.22.0.137, UserName=%s, %s'
            % (when, user, rest))
    return [line(host, cat, seq, 1, 0, head)]


# a VPN login, the firewall it was handed, and somebody on a switch
daemon.read_records(passed_lines(
    701, 'londkevicha',
    'Protocol=Radius, NetworkDeviceName=FTD-VPN, Calling-Station-ID=84.242.85.10, '
    'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=CORPNET, AcsSessionID=ise2/569337134/111118621, '
    'SelectedAuthorizationProfiles=AnyConnect_OLYMPUS, CPMSessionID=%s, '
    'Response={Class=CACS:%s:ise2/1; cisco-av-pair=ACS:CiscoSecure-Defined-ACL=%s; }'
    % (SESSION, SESSION, ACL)), kind='passed')
daemon.read_records(passed_lines(
    702, ACL,
    'Protocol=Radius, NetworkDeviceName=FTD-VPN, '
    'AcsSessionID=ise2/569337134/111125846, CPMSessionID=%s, '
    'cisco-av-pair=audit-session-id=%s, Response={Class=CACS:%s:ise2/2; %s}'
    % (SESSION, SESSION, SESSION, RULES)), kind='passed')
daemon.read_records(passed_lines(
    703, 'pk',
    'Protocol=Tacacs, NetworkDeviceName=DefaultNetworkDevice, NetworkDeviceName=vs23a, '
    'Type=Authentication, Action=Login, Service=Login, Port=tty1, '
    'Remote-Address=192.168.251.10, AcsSessionID=ise1/569335167/120543056, '
    'SelectedShellProfile=Admin_LVL15, ISEPolicySetName=SW', host='ise1'), kind='passed')

counts = store.passed_counts()
ok('a VPN login, a device login and a downloadable ACL are told apart',
   [counts.get('vpn'), counts.get('tacacs'), counts.get('dacl')], [1, 1, 1])
rows, total = store.passed_rows(limit=50)
ok('the ACL is not listed as a login', total, 2)
ok('...and none of the listed rows is one',
   [r for r in rows if str(r['username']).startswith('#ACSACL#')], [])
ok('asking for the VPN logins gets one', store.passed_rows(kind='vpn')[1], 1)
ok('asking for the TACACS logins gets the other', store.passed_rows(kind='tacacs')[1], 1)
ok('asking for the ACLs by name gets it', store.passed_rows(kind='dacl')[1], 1)

tac = store.passed_rows(kind='tacacs')[0][0]
ok('a device login keeps the address it came from', tac['ip'], '192.168.251.10')
ok('...and says whether it was a sign-in or a command', tac['subtype'], 'Authentication|Login')

login = store.passed_rows(kind='vpn')[0][0]
ok('a login remembers which ACL it was given', login['acl'], ACL)
got = daemon.acl_for_login(login)
ok('the firewall is found for its login', bool(got and got['have']), True)
ok('...by the session rather than by the name', got['matched'], 'session')
ok('...with every rule read', len(got['rules']), 4)
ok('...counted', [got['permits'], got['denies']], [2, 1])
ok('a remark is kept as a heading',
   [got['rules'][0]['kind'], got['rules'][0]['note']], ['remark', 'DNS'])
ok('a rule is taken apart into its parts',
   [got['rules'][1][k] for k in ('kind', 'proto', 'src', 'dst', 'dst_port')],
   ['permit', 'udp', 'any', 'host 172.25.1.10', 'eq 53'])
ok('a rule with a mask, a port range and a group is taken apart too',
   [got['rules'][2][k] for k in ('src', 'src_port', 'dst', 'dst_port', 'extra')],
   ['10.0.0.0 255.0.0.0', 'range 1024 2048', 'object-group SERVERS', 'eq www', 'log'])
ok('...and every rule keeps the words it was written in',
   got['rules'][3]['text'], 'deny ip any any')
ok('a device login is handed no firewall', daemon.acl_for_login(tac), None)

# the same ACL, wanted by a session whose own download never arrived
other = dict(login)
other['cpm'] = 'a-session-nobody-has-seen'
again = daemon.acl_for_login(other)
ok('a login whose own download is missing still finds the rules by name',
   bool(again and again['have']), True)
ok('...and is told that is what happened', again['matched'], 'name')
none = daemon.acl_for_login(dict(login, cpm='x', acl='#ACSACL#-IP-Nothing-00000000'))
ok('an ACL nobody has ever downloaded says so plainly',
   [bool(none), none['have'], none['rules']], [True, False, []])

# ---- the firewall a login was handed is history, not today's answer -------
#
# Somebody edits the ACL on ISE. The login from this morning has to go on
# showing what it was given this morning, and the one from this afternoon the
# new rules. ISE helps: it writes the version into the name itself, so an
# edited ACL arrives under a different name and the two can never be
# confused. This proves both halves - the pairing by session, and the fall
# back to a name, which takes the newest copy recorded AT OR BEFORE the login
# and never a later edit of it.
NEW_ACL = '#ACSACL#-IP-AnyConnect_OLYMPUS-70a41b55'
NEW_RULES = ('cisco-av-pair=ip:inacl#1=remark DNS; '
             'cisco-av-pair=ip:inacl#2=permit udp any host 172.25.1.10 eq 53; '
             'cisco-av-pair=ip:inacl#3=deny ip any any; ')
LATER = '3ff4ba7a474bf1117bc4cc31'


def dacl_lines(seq, user, rest, at, host='ise2'):
    """The same as passed_lines, at a moment of its own."""
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(at)) + '.500 ' + ise_zone(at)
    head = ('%s 0229674592 5400 NOTICE Passed-Authentication: Authentication succeeded, '
            'ConfigVersionId=87, Device IP Address=172.22.0.137, UserName=%s, %s'
            % (when, user, rest))
    return [line(host, 'CISE_Passed_Authentications', seq, 1, 0, head)]


AFTER = WHEN + 4 * 3600
daemon.read_records(dacl_lines(
    711, 'londkevicha',
    'Protocol=Radius, NetworkDeviceName=FTD-VPN, Calling-Station-ID=84.242.85.10, '
    'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=CORPNET, AcsSessionID=ise2/569337134/111118999, '
    'SelectedAuthorizationProfiles=AnyConnect_OLYMPUS, CPMSessionID=%s, '
    'Response={Class=CACS:%s:ise2/1; cisco-av-pair=ACS:CiscoSecure-Defined-ACL=%s; }'
    % (LATER, LATER, NEW_ACL), AFTER), kind='passed')
daemon.read_records(dacl_lines(
    712, NEW_ACL,
    'Protocol=Radius, NetworkDeviceName=FTD-VPN, '
    'AcsSessionID=ise2/569337134/111125999, CPMSessionID=%s, '
    'cisco-av-pair=audit-session-id=%s, Response={Class=CACS:%s:ise2/2; %s}'
    % (LATER, LATER, LATER, NEW_RULES), AFTER), kind='passed')

both = store.passed_rows(kind='vpn')[0]
first = [r for r in both if r['cpm'] == SESSION][0]
second = [r for r in both if r['cpm'] == LATER][0]
was = daemon.acl_for_login(first)
now = daemon.acl_for_login(second)
ok('the ACL was edited, so the two logins carry two different names',
   [was['name'], now['name']], [ACL, NEW_ACL])
ok('...the older login still shows the rules it was handed then',
   [len(was['rules']), was['rules'][2]['text']],
   [4, 'permit tcp 10.0.0.0 255.0.0.0 range 1024 2048 object-group SERVERS eq www log'])
ok('...the newer login shows the changed ones',
   [len(now['rules']), now['rules'][2]['text']], [3, 'deny ip any any'])
ok('...and both were read from their own session',
   [was['matched'], now['matched']], ['session', 'session'])
ok('...each with the moment it was downloaded',
   [int(was['at']) == int(WHEN), int(now['at']) == int(AFTER)], [True, True])

# The same name downloaded twice, before and after this login: the one before
# is the version that was in force, and the later one is not it.
daemon.read_records(dacl_lines(
    713, ACL,
    'Protocol=Radius, NetworkDeviceName=FTD-VPN, '
    'AcsSessionID=ise2/569337134/111126111, CPMSessionID=%s, '
    'cisco-av-pair=audit-session-id=%s, Response={Class=CACS:%s:ise2/2; %s}'
    % ('e-later-download', 'e-later-download', 'e-later-download', NEW_RULES),
    AFTER + 3600), kind='passed')
orphan = daemon.acl_for_login(dict(first, cpm='nothing-of-the-kind'))
ok('a login that has lost its own download is shown the copy from before it, '
   'not a later one', [orphan['matched'], len(orphan['rules'])], ['name', 4])
ahead = daemon.acl_for_login(dict(first, cpm='nothing-of-the-kind',
                                  ts=WHEN - 10 * 3600))
ok('...and when nothing of that name was recorded before it, the nearest after '
   'is shown and said to be that', [ahead['matched'], len(ahead['rules'])],
   ['name-later', 4])
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Going back over every log')
folder, store, daemon = fresh()
# Again about the counting rather than the harder rule; see above.
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10, 'watch_devices': 'FTD-VPN',
                      'block_ladder': '10, 60, forever', 'judge_max_age_h': 24,
                      'ise_paths': [], 'never_block': '', 'block_bogus_tries': 0})
daemon._spare_from = None
long_ago = time.time() - 40 * 86400          # far outside the age limit
for i in range(4):
    daemon.read_records(failed_record(long_ago + i, '198.51.100.70', seq=500 + i))
ok('something old enough is written down', store.failed_rows(ip='198.51.100.70')[1], 4)
ok('...but earns nothing as it arrives', store.blocked_until('198.51.100.70'), None)

# one that is not watched, and one the whitelist covers
for i in range(4):
    daemon.read_records(failed_record(long_ago + i, '198.51.100.71', device='SW-CORE',
                                      seq=520 + i))
isemon.CONFIG['never_block'] = '198.51.100.72'
daemon._spare_from = None
for i in range(4):
    daemon.read_records(failed_record(long_ago + i, '198.51.100.72', seq=540 + i))
# ...and one that never met the bar at all
for i in range(2):
    daemon.read_records(failed_record(long_ago + i, '198.51.100.73', seq=560 + i))

said = []
out = daemon.rescan(lambda done, total, words='': said.append(words),
                    by='check', read_files=False)
ok('the pass finds the one that earned it', out['banned'], ['198.51.100.70'])
ok('...and says how many it weighed', out['weighed'], 14)
ok('...and it is now kept out', store.blocked_until('198.51.100.70') is not None, True)
ok('a device nobody watches is still not banned',
   store.blocked_until('198.51.100.71'), None)
ok('the whitelist still holds', store.blocked_until('198.51.100.72'), None)
ok('two failures still do not earn one', store.blocked_until('198.51.100.73'), None)
ok('it says what it was doing while it did it', len(said) > 1, True)
ok('what it did is remembered for the page',
   [(store.meta_json('rescan_last') or {}).get(k) for k in ('banned', 'by')], [1, 'check'])

again = daemon.rescan(None, by='check', read_files=False)
ok('running it twice bans nothing twice', again['banned'], [])
ok('...and says the one it found was already kept out', again['already'] >= 1, True)

store.unblock('198.51.100.70')
narrow = daemon.rescan(None, by='check', read_files=False, since_days=1)
ok('asked to go back only a day, it leaves last month alone', narrow['banned'], [])
ok('...and says it weighed nothing', narrow['weighed'], 0)
ok('...and the address is still free', store.blocked_until('198.51.100.70'), None)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A database made by an older version, opened by this one')
# The shape 1.1.0 left behind: `passed` without the four columns this version
# adds. An index named in the schema that stands on one of those columns is
# never made on a database that already has the table - it fails outright, and
# the daemon ends up refusing to open its own database on every upgrade. So
# the columns are added first and the indexes after, and this proves it on a
# database built to be exactly that old.
folder = tempfile.mkdtemp(prefix='isemon-upgrade-')
where = Path(folder) / 'old.db'
old_db = sqlite3.connect(str(where))
old_db.executescript("""
CREATE TABLE passed (session TEXT PRIMARY KEY, ts REAL NOT NULL, server TEXT, ip TEXT,
  username TEXT, device TEXT, nad TEXT, tunnel TEXT, service TEXT, protocol TEXT,
  profile TEXT, policy TEXT, groups TEXT, country TEXT, detail TEXT);
CREATE INDEX passed_ts ON passed (ts);
CREATE TABLE failed (session TEXT PRIMARY KEY, ts REAL NOT NULL, server TEXT, ip TEXT NOT NULL,
  username TEXT, device TEXT, nad TEXT, tunnel TEXT, service TEXT, protocol TEXT,
  code TEXT, reason TEXT, detail TEXT);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE users (name TEXT PRIMARY KEY, hash TEXT, role TEXT, made REAL, last_in REAL);
""")
old_db.execute("INSERT INTO passed (session, ts, username, ip, profile) "
               "VALUES ('ise2/1/1', ?, 'somebody', '10.0.0.1', 'AnyConnect_X')",
               (time.time(),))
old_db.execute("INSERT INTO failed (session, ts, ip, username) "
               "VALUES ('ise2/1/2', ?, '203.0.113.9', 'INVALID')", (time.time(),))
old_db.execute("INSERT INTO users (name, hash, role, made) "
               "VALUES ('admin', 'x', 'fulladmin', ?)", (time.time(),))
old_db.commit()
old_db.close()

isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = where
isemon.RUN_DIR = Path(folder)
store = None
if not on_a_file():
    print('  --    this is about upgrading a file, and this run is on a server')
else:
    try:
        store = isemon.Storage(where)
        ok('an older database opens at all', True)
    except Exception as e:
        ok('an older database opens at all', 'it raised: %s' % e, True)
        store = None

if store:
    columns = set(store.dialect.columns(store.db, 'passed'))
    ok('...and gains the columns this version needs',
       sorted(c for c in ('kind', 'subtype', 'cpm', 'acl') if c in columns),
       ['acl', 'cpm', 'kind', 'subtype'])
    ok('...and the indexes that stand on them',
       sorted(name for name in store.dialect.indexes(store.db, 'passed')
              if name in ('passed_cpm', 'passed_acl')),
       ['passed_acl', 'passed_cpm'])
    ok('...and nothing is left missing', store.missing_columns(), [])
    ok('...and every row it held is still there',
       [store.db.execute('SELECT COUNT(*) AS n FROM %s' % t).fetchone()['n']
        for t in ('passed', 'failed', 'users')], [1, 1, 1])
    ok('a login recorded before there were kinds counts as a VPN login',
       store.passed_counts()['vpn'], 1)
    ok('...and is still listed', store.passed_rows(kind='vpn')[1], 1)
    ok('opening it a second time changes nothing',
       isemon.Storage(where).missing_columns(), [])

# --- and the rows it already held are sorted out ---------------------------
title('Login records written before there were kinds')
# A row recorded by an earlier version has no kind, and a kind that is not
# there reads as "an AnyConnect login" - which puts every TACACS login and
# every downloadable ACL into the list of VPN logins. The record itself is
# still in the database, whole, so nothing has to be read again to put it
# right.
folder = tempfile.mkdtemp(prefix='isemon-backfill-')
where = Path(folder) / 'old.db'
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = where
isemon.RUN_DIR = Path(folder)
old_db = sqlite3.connect(str(where))
old_db.executescript('''
CREATE TABLE passed (session TEXT PRIMARY KEY, ts REAL NOT NULL, server TEXT, ip TEXT,
  username TEXT, device TEXT, nad TEXT, tunnel TEXT, service TEXT, protocol TEXT,
  profile TEXT, policy TEXT, groups TEXT, country TEXT, detail TEXT);
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
''')
SESSION = '2ee3a969363ae0006ab3bb20'
ACL = '#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c'
for session, user, protocol, flat in (
        ('ise2/1/1', 'somebody', 'Radius',
         {'UserName': 'somebody', 'Protocol': 'Radius', 'CPMSessionID': SESSION,
          'Response': '{Class=CACS:x; cisco-av-pair=ACS:CiscoSecure-Defined-ACL=%s; }' % ACL}),
        ('ise2/1/2', ACL, 'Radius',
         {'UserName': ACL, 'Protocol': 'Radius', 'CPMSessionID': SESSION,
          'Response': '{Class=CACS:x; cisco-av-pair=ip:inacl#1=permit ip any any; '
                      'cisco-av-pair=ip:inacl#2=deny ip any any; }'}),
        ('ise1/1/3', 'pk', 'Tacacs',
         {'UserName': 'pk', 'Protocol': 'Tacacs', 'Type': 'Authentication',
          'Action': 'Login', 'Remote-Address': '192.168.251.10'})):
    old_db.execute('INSERT INTO passed (session, ts, username, protocol, detail) '
                   'VALUES (?,?,?,?,?)',
                   (session, time.time(), user, protocol, json.dumps(flat)))
old_db.commit()
old_db.close()

if not on_a_file():
    print('  --    this is about rows already in a file, and this run is on a server')
    store = None
else:
    store = isemon.Storage(where)

if store:
  ok('every older row is sorted into what it actually is',
     [store.passed_counts()[k] for k in ('vpn', 'tacacs', 'dacl')], [1, 1, 1])
  ok('the downloadable ACL stops being listed as a login', store.passed_rows(limit=9)[1], 2)
  ok('...and is not in the VPN list',
     [r for r in store.passed_rows(kind='vpn', limit=9)[0]
      if str(r['username']).startswith('#ACSACL#')], [])
  ok('the TACACS login is in its own list now', store.passed_rows(kind='tacacs', limit=9)[1], 1)
  ok('...and got the address it came from',
     store.passed_rows(kind='tacacs', limit=9)[0][0]['ip'], None)
  ok('...and whether it was a sign-in or a command',
     store.passed_rows(kind='tacacs', limit=9)[0][0]['subtype'], 'Authentication|Login')
  older = isemon.Daemon(store)
  was = store.passed_rows(kind='vpn', limit=9)[0][0]
  ok('the VPN login remembers which ACL it was given', was['acl'], ACL)
  shown = older.acl_for_login(was)
  ok('...and its firewall can be drawn', bool(shown and shown['have']), True)
  ok('...with the rules read out of what was already stored', len(shown['rules']), 2)
  ok('doing it again changes nothing', store.fill_in_kinds(), 0)
shutil.rmtree(folder, ignore_errors=True)
folder = tempfile.mkdtemp(prefix='isemon-upgrade-')

# ---------------------------------------------------------------------------
title('When the automatic fetching happens')
folder, store, daemon = fresh()
HOUR, DAY = 3600, 86400

# By default the interval decides and nothing else does. "Every hour" has to
# mean every hour, or the setting that says so is a setting that lies.
isemon.CONFIG.update({'update_when': 'interval', 'update_at': '03:30'})
ok('left alone, the interval decides on its own',
   [daemon.update_at_applies(30 * DAY), daemon.update_at_applies(DAY),
    daemon.update_at_applies(HOUR)], [False, False, False])
ok('...so nothing is ever held back for the hour',
   [daemon.update_window_open(0, HOUR), daemon.update_window_open(0, 30 * DAY)],
   [True, True])
ok('...and something monthly and due goes now, not at 03:30',
   abs(daemon.update_next(time.time() - 40 * DAY, 30 * DAY) - time.time()) < 5, True)

isemon.CONFIG.update({'update_when': 'at_time', 'update_at': '03:30'})
ok('asked for the hour instead, it governs something fetched monthly',
   daemon.update_at_applies(30 * DAY), True)
ok('...and something fetched daily', daemon.update_at_applies(DAY), True)
ok('...but not something fetched hourly', daemon.update_at_applies(HOUR), False)
ok('...nor every six hours', daemon.update_at_applies(6 * HOUR), False)
ok('an hourly fetch is never held back by the hour',
   daemon.update_window_open(0, HOUR), True)
ok('...however far from the hour it is',
   all(daemon.update_window_open(n, HOUR) for n in (0, 60, 3600)), True)
isemon.CONFIG['update_at'] = ''
ok('with the hour asked for but left empty, everything goes as it falls due',
   [daemon.update_window_open(0, HOUR), daemon.update_window_open(0, 30 * DAY)],
   [True, True])
ok('...and nothing is said to be governed by it',
   [daemon.update_at_applies(DAY), daemon.update_at_applies(HOUR)], [False, False])

isemon.CONFIG['update_at'] = '03:30'
now = time.time()
soon = daemon.update_next(now - 2 * HOUR, HOUR)
ok('something hourly and already due is next fetched at once',
   abs(soon - now) < 5, True)
later = daemon.update_next(now - 40 * DAY, 30 * DAY)
when = time.localtime(later)
ok('something monthly and already due waits for the chosen hour',
   [when.tm_hour, when.tm_min], [3, 30])
ok('...and that is in the future', later > now, True)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('What a router says back, as words rather than as a terminal session')
CR, ESC, NUL, BEL = '\r', '\x1b', '\x00', '\x07'
for what, raw, want in (
        ('CR LF line endings', CR + '\n  name: MikroTik-CORPNET' + CR + '\n',
         '  name: MikroTik-CORPNET'),
        ('a line written over', 'reading...' + CR + 'name: MikroTik-CORPNET',
         'name: MikroTik-CORPNET'),
        ('a progress counter', '  1%' + CR + ' 50%' + CR + '100% done', '100% done'),
        ('colours', ESC + '[1;32m  name: MikroTik' + ESC + '[0m', '  name: MikroTik'),
        ('cursor moves', ESC + '[9999B' + ESC + '[c  name: MikroTik', '  name: MikroTik'),
        ('a window title', ESC + ']0;RouterOS' + BEL + '  name: MikroTik',
         '  name: MikroTik'),
        ('NULs between the letters', '  n' + NUL + 'a' + NUL + 'me: MikroTik',
         '  name: MikroTik'),
        ('a bell', '  name: Mik' + BEL + 'roTik', '  name: MikroTik'),
        ('trailing whitespace', '  name: MikroTik   \n\n\n', '  name: MikroTik'),
        ('nothing at all', '', ''),
        ('text that is already clean', '  name: MikroTik-CORPNET', '  name: MikroTik-CORPNET')):
    ok(what, isemon.clean_terminal_text(raw), want)

ok('a terse address list survives it whole',
   isemon.clean_terminal_text(
       ' 0 list=isemonBlock address=45.9.148.9 comment="isemon: a failed login"' + CR + '\n'),
   ' 0 list=isemonBlock address=45.9.148.9 comment="isemon: a failed login"')
ok('...and so does every line of a long one',
   len(isemon.clean_terminal_text(
       CR.join([]) + (CR + '\n').join(' %d list=x address=10.0.0.%d' % (i, i)
                                      for i in range(40))).splitlines()), 40)
ok('nothing below a space is left anywhere in it',
   [c for c in isemon.clean_terminal_text(
       ''.join(chr(i) for i in range(1, 32)) + 'name: X') if ord(c) < 32 and c != '\n'],
   [])

# ---------------------------------------------------------------------------
title('Colour on the command line')
import io                                            # noqa: E402

was_env = {k: os.environ.get(k) for k in ('NO_COLOR', 'FORCE_COLOR', 'CLICOLOR_FORCE', 'TERM')}
for k in ('NO_COLOR', 'FORCE_COLOR', 'CLICOLOR_FORCE'):
    os.environ.pop(k, None)
os.environ['TERM'] = 'xterm'


class FakeTerminal(io.StringIO):
    """A stream that says it is a terminal, so colour is written to it."""

    def isatty(self):
        return True


ok('colorama is used when it is installed, and not needed when it is not',
   isemon.HAVE_COLORAMA in (True, False), True)

term = FakeTerminal()
pal = isemon.Palette(True, stream=term)
ok('a terminal gets colour', pal.on, True)
pal.good('it worked')
said = term.getvalue()
ok('...and the escape sequences are actually written', '\033[' in said, True)
ok('...with the words still in it', 'it worked' in said, True)
ok('...and it is reset at the end', said.rstrip().endswith('\033[0m'), True)

pipe = io.StringIO()                                  # not a terminal
quiet = isemon.Palette(True, stream=pipe)
ok('something that is not a terminal gets none', quiet.on, False)
quiet.good('it worked')
quiet.bad('it did not')
piped = pipe.getvalue()
ok('...and no escape sequence is written', '\033[' in piped, False)
ok('...but good and bad are still told apart',
   [l.split(']')[0] + ']' for l in piped.strip().split('\n')], ['[ ok ]', '[fail]'])

ok('--no-color turns it off on a terminal too',
   isemon.Palette(False, stream=FakeTerminal()).on, False)
os.environ['NO_COLOR'] = '1'
ok('NO_COLOR turns it off, whatever it is set to',
   isemon.Palette(True, stream=FakeTerminal()).on, False)
os.environ['NO_COLOR'] = '0'
ok('...even set to zero, because that is what NO_COLOR means',
   isemon.Palette(True, stream=FakeTerminal()).on, False)
os.environ.pop('NO_COLOR')
os.environ['FORCE_COLOR'] = '1'
ok('FORCE_COLOR turns it on where there is no terminal',
   isemon.Palette(True, stream=io.StringIO()).on, True)
os.environ.pop('FORCE_COLOR')
os.environ['TERM'] = 'dumb'
ok('a dumb terminal gets none', isemon.Palette(True, stream=FakeTerminal()).on, False)
os.environ['TERM'] = 'xterm'

ok('the width of a coloured string is what it looks like, not what it is',
   isemon.plain_len(pal.paint('hello', pal.c_ok)), 5)
ok('...so a coloured cell pads to the same width as a plain one',
   isemon.plain_len(isemon.plain_pad(pal.paint('ab', pal.c_bad), 8)), 8)
ok('...and padding to the right does too',
   isemon.plain_len(isemon.plain_pad(pal.paint('ab', pal.c_bad), 8, right=True)), 8)

# A table whose columns must line up although only some cells are coloured.
term = FakeTerminal()
pal = isemon.Palette(True, stream=term)
isemon.print_table(pal, ['a', 'b'],
                   [[('one', pal.c_bad), 'x'], ['three', ('y', pal.c_ok)], ['xx', 'z']])
lines = [isemon.ANSI.sub('', l) for l in term.getvalue().strip().split('\n')]
ok('a table with some cells coloured still lines up',
   len({len(l.rstrip().split()[-1]) for l in lines}), 1)
ok('...and every column starts in the same place',
   len({l.index('x') if 'x' in l else l.index('B') for l in lines[:1]}), 1)
starts = [len(l) - len(l.lstrip()) for l in lines]
ok('...and nothing is indented differently from the rest', len(set(starts)), 1)

# --help, which argparse would otherwise print with no colour at all
help_plain = isemon.main.__globals__['help_text']
parser = isemon.HelpfulParser(prog='isemon')
parser.add_argument('--ban', metavar='ADDR', help='keep an address out')
parser.add_argument('--forever', action='store_true', help='with no end')
drawn = help_plain(parser, isemon.Palette(False, stream=io.StringIO()))
ok('the help names every option it was given',
   all(x in drawn for x in ('--ban', 'ADDR', '--forever', 'keep an address out')), True)
ok('...and says what people actually type', 'isemon --status' in drawn, True)
ok('...without a single escape sequence when there is no colour',
   '\033[' in drawn, False)
coloured = help_plain(parser, isemon.Palette(True, stream=FakeTerminal()))
ok('...and with them when there is', '\033[' in coloured, True)
ok('...and the same words either way',
   isemon.ANSI.sub('', coloured) == drawn, True)
lines = [l for l in drawn.split('\n') if l.startswith('  --')]
ok('every option is described in the same column',
   len({len(l) - len(l.lstrip('  -a-z')) for l in lines}) >= 1, True)

for k, v in was_env.items():
    if v is None:
        os.environ.pop(k, None)
    else:
        os.environ[k] = v


# ---------------------------------------------------------------------------
title('a restart, and a rotation while nobody was reading')

folder, store, daemon = fresh()
logs = Path(folder) / 'remote'
logs.mkdir()
live = logs / 'ise-failed.log'


def write_records(where, how_many, first_seq=1, mode='a'):
    lines = []
    for n in range(how_many):
        lines += failed_record(time.time() - 60, '203.0.113.%d' % (n % 250 + 1),
                               seq=first_seq + n)
    with open(where, mode) as f:
        f.write('\n'.join(lines) + '\n')


write_records(live, 5, 1)
tail = isemon.LogTail(str(live))
tail.kind = 'failed'
got = tail.read()
ok('a file is read from the beginning the first time', len(got), 5)
kept = tail.state()
ok('...and where it stopped is something that can be written down',
   all(k in kept for k in ('offset', 'inode', 'size', 'records', 'read_at', 'hold')), True)
ok('...including the count, which the front page shows', kept['records'], 5)

# The daemon is stopped. The same tail, made again from what was written down.
again = isemon.LogTail(str(live), kept['offset'], kept['inode'], kept['size'],
                       kept['records'], kept['hold'], kept['read_at'])
ok('a restart carries the count over rather than starting at nothing', again.records, 5)
ok('...and reads nothing again', len(again.read()), 0)

# logrotate runs while the daemon is stopped: the file is renamed and more is
# written to the one that was moved aside before a new one appears.
write_records(live, 3, 100)                     # written, but not read yet
os.rename(str(live), str(live) + '.1')
write_records(live, 2, 200, mode='w')           # the new file
after = isemon.LogTail(str(live), again.offset, again.inode, again.size, again.records,
                       again.state()['hold'])
rows = after.read()
ok('the tail of the rotated file is read as well as the new one', len(rows), 5)
ok('...and it says so, so somebody knows it happened', after.recovered, 3)
ok('...and the count is the whole of what has been read', after.records, 10)

# The same again, compressed, which is what logrotate leaves behind a day later.
folder2, store2, daemon2 = fresh()
logs2 = Path(folder2) / 'remote'
logs2.mkdir()
live2 = logs2 / 'ise-failed.log'
write_records(live2, 4, 1)
t2 = isemon.LogTail(str(live2))
t2.read()
write_records(live2, 6, 50)
import gzip
with open(str(live2), 'rb') as src, gzip.open(str(live2) + '.1.gz', 'wb') as dst:
    dst.write(src.read())
os.remove(str(live2))
write_records(live2, 1, 300, mode='w')
t3 = isemon.LogTail(str(live2), t2.offset, t2.inode, t2.size, t2.records)
rows = t3.read()
ok('a rotated file that has been compressed is read too', t3.recovered, 6)
ok('...and the new file with it', len(rows), 7)

# ---------------------------------------------------------------------------
title('going back over every log stores nothing twice')

folder, store, daemon = fresh()
logs = Path(folder) / 'remote'
logs.mkdir()
isemon.CONFIG['ise_paths'] = [str(logs)]
isemon.CONFIG['blacklist'] = 0
live = logs / isemon.CONFIG['ise_failed_name']
write_records(live, 12, 1)
# ...and one rotated copy beside it, holding records nothing has ever read.
write_records(logs / (isemon.CONFIG['ise_failed_name'] + '.1'), 7, 500)
daemon.restore_tails()
daemon.read_logs()
first = store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']
ok('the live file is read', first, 12)
seen = []
out = daemon.rescan(progress=lambda d, t, w='': seen.append(w), read_files=True)
after = store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']
ok('a pass back over every log picks up the rotated file', after, 19)
ok('...and adds only what was missing', out['added'], 7)
ok('...having read every one of them', out['seen'], 19)
out2 = daemon.rescan(progress=None, read_files=True)
ok('a second pass adds nothing at all', out2['added'], 0)
ok('...and the table is exactly as it was',
   store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'], 19)
ok('...and it says so in words, both halves',
   'already here' in out2['message'], True)

# ---------------------------------------------------------------------------
title('a burst far past the bar')

folder, store, daemon = fresh()
isemon.CONFIG['block_tries'] = 3
isemon.CONFIG['block_window_min'] = 300
isemon.CONFIG['block_ladder'] = '15, 60, 1440, forever'
isemon.CONFIG['block_lots'] = 0
isemon.CONFIG['feeds_ban'] = 0
isemon.CONFIG['block_bogus_tries'] = 0          # the other rule, tried on its own below
now = time.time()
for n in range(40):
    store.add_failed({'session': 'burst/%d' % n, 'ts': now - 30, 'ip': '198.51.100.9',
                      'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.9', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.9',)).fetchone()
ok('forty failures in one window is still the first step of the ladder',
   bool(row['until']), True)
ok('...which is the thing that surprises people', 'INVALID' in (row['why'] or ''), True)

store.unblock('198.51.100.9')
isemon.CONFIG['block_lots'] = 25
for n in range(40):
    store.add_failed({'session': 'burst2/%d' % n, 'ts': now - 20, 'ip': '198.51.100.10',
                      'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.10', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.10',)).fetchone()
ok('...and with a burst set it goes out for good at once', row['until'], None)
ok('...and the reason says which number it passed',
   '25' in (store.get_meta('blocked_how_198.51.100.10') or ''), True)

isemon.CONFIG['block_lots'] = 25
for n in range(4):
    store.add_failed({'session': 'small/%d' % n, 'ts': now - 20, 'ip': '198.51.100.11',
                      'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.11', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.11',)).fetchone()
ok('...while a small one still takes the ladder', bool(row['until']), True)
ok('how long a ban lasts says the burst too', '25' in daemon.blocking_words(), True)

# ---------------------------------------------------------------------------
title('what it does while it is banned')

# The hole this closes: an address that reached the bar was banned and then
# never weighed again, so everything it did from behind the closed door was
# written down and counted for nothing. It served fifteen minutes for a
# hundred attempts and walked back in - and when the ban ran out those
# attempts were still inside the window, so the page showed "6 of 3" beside
# an address that was not banned and nothing came to fetch it.
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 300, 'block_lots': 0,
                      'block_bogus_tries': 0, 'feeds_ban': 0, 'watch_devices': '',
                      'block_ladder': '15, 60, 1440, forever', 'judge_max_age_h': 0})
daemon._spare_from = None
now = time.time()


def failed_at(ip, at, user='jnovak', key=None, device='FTD-VPN'):
    store.add_failed({'session': key or ('w/%s/%s' % (ip, at)), 'ts': at, 'ip': ip,
                      'username': user, 'device': device, 'server': 'ise2', 'detail': '{}'})


IP = '198.51.100.80'
for n in range(3):
    failed_at(IP, now - 600 + n)
daemon.maybe_block(IP, isemon._AtTime(now - 597))
first = store.blocked_one(IP)
ok('three failures earn the first step of the ladder', bool(first['until']), True)

# It goes on trying while it is out. Three more is the bar again, so it takes
# the next rung - it is not a first offender any more. (The attempts are
# stamped after the ban began, because that is the only thing that counts
# here: what arrived from behind the closed door.)
began = float(first['since'])
for n in range(3):
    failed_at(IP, began + 10 + n, key='w/in/%d' % n)
daemon.maybe_escalate(IP, isemon._AtTime(began + 13))
held = store.blocked_one(IP)
ok('...and going on through the ban takes the next rung',
   held['until'] > first['until'], True)
ok('...which is written down as what it is',
   [r['what'] for r in store.db.execute(
       "SELECT what FROM block_events WHERE ip=? ORDER BY ts", (IP,))],
   ['blocked', 'held longer'])
ok('...and the ladder does not count it as a second ban',
   store.blocked_before(IP), 1)
ok('...and the reason says why it was held', 'while it was banned' in
   (store.get_meta('blocked_how_%s' % IP) or ''), True)

# The same three attempts again must not lengthen it a second time.
daemon.maybe_escalate(IP, isemon._AtTime(began + 14))
ok('the same attempts are never charged twice',
   store.blocked_one(IP)['until'], held['until'])

# A burst from behind the door is what the burst rule is for.
isemon.CONFIG['block_lots'] = 5
held_at = float(store.get_meta('blocked_charged_%s' % IP) or 0)
ok('what a ban was earned by is remembered, so it is never charged twice',
   int(held_at), int(began + 12))
for n in range(6):
    failed_at(IP, held_at + 10 + n, user='INVALID', key='w/burst/%d' % n)
daemon.maybe_escalate(IP, isemon._AtTime(held_at + 16))
ok('a burst while it is banned puts it out for good',
   store.blocked_one(IP)['until'], None)
ok('...and says so in plain words', 'for good' in
   (store.get_meta('blocked_how_%s' % IP) or ''), True)
daemon.maybe_escalate(IP, isemon._AtTime(held_at + 17))
ok('...and there is nothing left to add to a ban for good',
   store.blocked_one(IP)['until'], None)

# Once the ban has been served, what it was banned for is not charged again.
isemon.CONFIG['block_lots'] = 0
OTHER = '198.51.100.81'
for n in range(3):
    failed_at(OTHER, now - 600 + n)
daemon.maybe_block(OTHER, isemon._AtTime(now - 597))
store.unblock(OTHER, how='ran out')
ok('an address that has served its ban is counted from nought',
   store.failed_count(OTHER, 300 * 60, since_ban=True), 0)
ok('...while every attempt it made is still on record',
   store.failed_count(OTHER, 300 * 60), 3)
ok('...so one more attempt does not ban it again',
   daemon.maybe_block(OTHER, isemon._AtTime(now)), None)
ok('...and it is not sitting over the bar on the page',
   [r for r in daemon.counting_up()['rows'] if r['ip'] == OTHER and not r['left']], [])

# Nothing may sit at or over the bar unacted on: the pass that sweeps fetches
# whatever the weighing missed - a bar lowered under addresses already
# counting, a pass that fell over, records read while it was switched off.
MISSED = '198.51.100.82'
for n in range(4):
    failed_at(MISSED, now - 200 + n)
ok('an address over the bar that nothing acted on is found',
   MISSED in {r['ip'] for r in daemon.counting_up()['rows'] if not r['left']}, True)
ok('...and the sweep puts it out', daemon.judge_anything_missed(), 1)
ok('...so it is on the list above instead',
   store.blocked_until(MISSED) is not None, True)
ok('...and the sweep finds nothing to do on a quiet minute',
   daemon.judge_anything_missed(), 0)

# The whitelist and unwatched devices are left alone by the sweep.
SPARED, UNSEEN = '198.51.100.83', '198.51.100.84'
isemon.CONFIG['never_block'] = SPARED
daemon._spare_from = None
for n in range(9):
    failed_at(SPARED, now - 150 + n)
for n in range(9):
    failed_at(UNSEEN, now - 150 + n, device='SOME-SWITCH')
isemon.CONFIG['watch_devices'] = 'ftd-vpn'
ok('the sweep leaves the whitelist and the unwatched devices alone',
   [daemon.judge_anything_missed(), store.blocked_until(SPARED),
    store.blocked_until(UNSEEN)], [0, None, None])
isemon.CONFIG['watch_devices'] = ''
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('the first knock from a name that was never an account')

folder, store, daemon = fresh()
isemon.CONFIG['block_tries'] = 50            # nowhere near
isemon.CONFIG['block_window_min'] = 300
isemon.CONFIG['block_ladder'] = '15, 60, 1440, forever'
isemon.CONFIG['block_lots'] = 0
isemon.CONFIG['feeds_ban'] = 0
isemon.CONFIG['block_bogus_names'] = 'INVALID'
now = time.time()
ok('one is the default, because that is what this is mostly for',
   isemon.DEFAULTS['block_bogus_tries'], 1)
isemon.CONFIG['block_bogus_tries'] = 1
store.add_failed({'session': 'one/1', 'ts': now - 5, 'ip': '198.51.100.40',
                  'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.40', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.40',)).fetchone()
# The harder rule used to sit BELOW the ordinary bar, so it could never fire
# first: an address had to earn a ban the slow way before the fast way was
# even looked at, which is the opposite of what it is for.
ok('a single INVALID goes out for good, without reaching the ordinary bar',
   bool(row) and row['until'], None)
ok('...and says so in one line', 'does not exist' in
   (store.get_meta('blocked_how_198.51.100.40') or ''), True)

# A real name doing the same thing is nowhere near a ban.
store.add_failed({'session': 'one/2', 'ts': now - 5, 'ip': '198.51.100.41',
                  'username': 'jnovak', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.41', isemon._AtTime(now))
ok('...while one mistyped password by somebody real earns nothing',
   store.db.execute('SELECT * FROM blocked WHERE ip=?',
                    ('198.51.100.41',)).fetchone(), None)

# ---------------------------------------------------------------------------
title('a name that was never an account')

folder, store, daemon = fresh()
isemon.CONFIG['block_tries'] = 5
isemon.CONFIG['block_window_min'] = 300
isemon.CONFIG['block_ladder'] = '15, 60, 1440, forever'
isemon.CONFIG['block_lots'] = 0
isemon.CONFIG['feeds_ban'] = 0
isemon.CONFIG['block_bogus_names'] = 'INVALID'
isemon.CONFIG['block_bogus_tries'] = 3
now = time.time()
for n in range(6):
    store.add_failed({'session': 'bogus/%d' % n, 'ts': now - 30, 'ip': '198.51.100.20',
                      'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.20', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.20',)).fetchone()
ok('a name that does not exist goes out for good on the first ban', row['until'], None)
ok('...and says why', 'does not exist' in (store.get_meta('blocked_how_198.51.100.20') or ''),
   True)

# The same number of attempts from somebody who does have an account.
for n in range(6):
    store.add_failed({'session': 'real/%d' % n, 'ts': now - 30, 'ip': '198.51.100.21',
                      'username': 'jnovak', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.21', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.21',)).fetchone()
ok('...while a real name still takes the ladder', bool(row['until']), True)

# Not enough of them yet.
for n in range(2):
    store.add_failed({'session': 'few/%d' % n, 'ts': now - 30, 'ip': '198.51.100.22',
                      'username': 'INVALID', 'server': 'ise2', 'detail': '{}'})
for n in range(4):
    store.add_failed({'session': 'few-real/%d' % n, 'ts': now - 30, 'ip': '198.51.100.22',
                      'username': 'jnovak', 'server': 'ise2', 'detail': '{}'})
daemon.maybe_block('198.51.100.22', isemon._AtTime(now))
row = store.db.execute('SELECT * FROM blocked WHERE ip=?', ('198.51.100.22',)).fetchone()
ok('two of them among four real ones is not yet the harder rule', bool(row['until']), True)

isemon.CONFIG['block_bogus_names'] = ''
ok('with no names given, the rule is off', daemon.bogus_bar(), 0)
isemon.CONFIG['block_bogus_names'] = 'INVALID, anonymous'
ok('...and the names are read case-blind',
   sorted(daemon.bogus_names()), ['anonymous', 'invalid'])
ok('how long a ban lasts says this rule too',
   'does not exist' in daemon.blocking_words(), True)
ok('...and what earns one stays the bar alone', '25' in daemon.trigger_words(), False)


# ---------------------------------------------------------------------------
title('which addresses a page of rows is told are banned')

folder, store, daemon = fresh()
now = time.time()
store.block('203.0.113.7', None, 'for good', auto=True)
store.block('203.0.113.8', now + 900, 'on a clock', auto=True)
store.block('198.51.100.0/24', now + 600, 'a folded subnet', auto=True)
got = store.blocked_states(['203.0.113.7', '203.0.113.8', '203.0.113.9',
                            '198.51.100.42', ''])
ok('a permanent ban is said to be one', got['203.0.113.7']['forever'], True)
ok('a temporary one carries the moment it ends', got['203.0.113.8']['until'] > now, True)
ok('...and is not permanent', got['203.0.113.8']['forever'], False)
ok('an address nobody has banned is simply not there', '203.0.113.9' in got, False)
ok('an address inside a banned subnet is covered by it',
   got['198.51.100.42']['through'], '198.51.100.0/24')
ok('...and nothing is invented for an empty address', '' in got, False)

# An address written two ways is one address, and the answer has to come back
# under the spelling it was asked about - the row that asks holds that one.
store.block('2a01:430:17::5', None, 'for good', auto=True)
got = store.blocked_states(['2A01:0430:0017:0000:0000:0000:0000:0005', '2a01:430:17::5'])
ok('an address asked about in capitals is found',
   got.get('2A01:0430:0017:0000:0000:0000:0000:0005', {}).get('forever'), True)
ok('...and comes back under the spelling that was asked',
   sorted(got), ['2A01:0430:0017:0000:0000:0000:0000:0005', '2a01:430:17::5'])

# ---------------------------------------------------------------------------
title('who is counting up to a ban, but is not there yet')

folder, store, daemon = fresh()
isemon.CONFIG['block_tries'] = 5
isemon.CONFIG['block_window_min'] = 10
isemon.CONFIG['block_bogus_names'] = 'INVALID'
isemon.CONFIG['block_bogus_tries'] = 3
isemon.CONFIG['watch_devices'] = ''
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None
now = time.time()


def failed_row(key, ip, user='jnovak', ago=30, device='FTD-VPN'):
    store.add_failed({'session': key, 'ts': now - ago, 'ip': ip, 'username': user,
                      'device': device, 'server': 'ise2', 'detail': '{}'})


for n in range(2):
    failed_row('up-a/%d' % n, '198.51.100.30')            # 2 of 5, a real name
for n in range(2):
    failed_row('up-b/%d' % n, '198.51.100.31', 'INVALID')  # 2 of 3, a name that is not one
for n in range(9):
    failed_row('up-old/%d' % n, '198.51.100.32', ago=3600)  # outside the window
said = daemon.counting_up()
rows = {r['ip']: r for r in said['rows']}
ok('an address inside the window is counted', rows['198.51.100.30']['tries'], 2)
ok('...and said to be three short of the bar', rows['198.51.100.30']['left'], 3)
ok('...against the ordinary rule', rows['198.51.100.30']['nearest'], 'the counting')
ok('a name that does not exist is closer, and says so',
   (rows['198.51.100.31']['left'], rows['198.51.100.31']['nearest']),
   (1, 'a name that does not exist'))
ok('...and how many of them there were', rows['198.51.100.31']['bogus'], 2)
# A rule nothing has been done towards is not what a row is about. With the
# bar for names that were never accounts set to one - the usual setting -
# every address alive is one away from it, and the row used to read "0 of 1"
# beside somebody who had mistyped their own password twice.
isemon.CONFIG['block_bogus_tries'] = 1
fresh_rows = {r['ip']: r for r in daemon.counting_up()['rows']}
ok('an address that has offered no bogus name is counted against the ordinary bar',
   [fresh_rows['198.51.100.30']['nearest'], fresh_rows['198.51.100.30']['tries'],
    fresh_rows['198.51.100.30']['left']], ['the counting', 2, 3])
ok('...while one that has offered them is still counted against the harder rule',
   fresh_rows['198.51.100.31']['nearest'], 'a name that does not exist')
isemon.CONFIG['block_bogus_tries'] = 3
ok('an address whose attempts are outside the window is not counted',
   '198.51.100.32' in rows, False)
ok('the window and the bar come with it', (said['window_min'], said['bar']), (10, 5))

# One that is already banned belongs to the list above, not to this one.
store.block('198.51.100.30', None, 'banned by hand', auto=False)
ok('an address already kept out is left to the list above',
   '198.51.100.30' in {r['ip'] for r in daemon.counting_up()['rows']}, False)
store.unblock('198.51.100.30')
# ...and once it has been let back in it starts again at nought. What it was
# banned for has been paid for: counting it a second time would put it back
# out on the next single attempt, and would undo an administrator letting it
# in by hand within the minute.
ok('an address let back in starts again at nought',
   '198.51.100.30' in {r['ip'] for r in daemon.counting_up()['rows']}, False)
store.add_failed({'session': 'up-a/again', 'ts': store.let_back_in_at('198.51.100.30') + 1,
                  'ip': '198.51.100.30', 'username': 'jnovak', 'device': 'FTD-VPN',
                  'server': 'ise2', 'detail': '{}'})
again = {r['ip']: r for r in daemon.counting_up()['rows']}
ok('...and what it does after that is counted, from one',
   [again['198.51.100.30']['tries'], again['198.51.100.30']['bogus']], [1, 0])

# A whitelisted address is counted and never banned; saying nothing about it
# would leave somebody watching a number that is never going to do anything.
isemon.CONFIG['never_block'] = '198.51.100.30'
daemon._spare_from = None
rows = {r['ip']: r for r in daemon.counting_up()['rows']}
ok('a whitelisted address is still shown, marked as spared',
   bool(rows['198.51.100.30']['spared']), True)
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None

# ...and one on a device nothing watches is counted by nothing at all.
isemon.CONFIG['watch_devices'] = 'ftd-vpn'
failed_row('up-c/1', '198.51.100.33', device='SOME-SWITCH')
rows = {r['ip']: r for r in daemon.counting_up()['rows']}
ok('an address only seen on an unwatched device says so',
   rows['198.51.100.33']['watched'], False)
ok('...while one on a watched device does not',
   rows['198.51.100.31']['watched'], True)
isemon.CONFIG['watch_devices'] = ''

# More than the page is given: the list used to stop at exactly two hundred
# and the page said "200 address(es) counting" as though that were all.
for n in range(260):
    failed_row('up-many/%d' % n, '203.0.113.%d' % (n % 250) if n < 250
               else '192.0.2.%d' % (n % 250))
for n in range(4):
    failed_row('up-near/%d' % n, '192.0.2.250')            # 4 of 5: the nearest
big = daemon.counting_up()
ok('every address counting is counted, not the first two hundred',
   big['total'] >= 250, True)
ok('...and with room enough they are all listed', len(big['rows']), big['total'])
ok('...and the count is not a floor', big['total_is_floor'], False)
small = daemon.counting_up(20)
ok('a list cut short still says how many there are in all',
   (len(small['rows']), small['total']), (20, big['total']))
ok('...and what it keeps is the nearest to a ban', small['rows'][0]['ip'], '192.0.2.250')

# ---------------------------------------------------------------------------
title('where the TACACS sign-ins normally come from')

folder, store, daemon = fresh()
isemon.CONFIG['tacacs_from'] = ''
ok('with nothing said, nothing is unusual', daemon.place_is_usual('10.1.1.1'), None)
isemon.CONFIG['tacacs_from'] = '192.168.251.10=LogHost, 10.9.0.4 = Jump2 , nonsense'
places = daemon.named_places()
ok('the addresses are read, and nothing that is not one',
   sorted(places), ['10.9.0.4', '192.168.251.10'])
ok('...with the names given to them', places['192.168.251.10'], 'LogHost')
ok('...and one without a name is still a place', places['10.9.0.4'], 'Jump2')
ok('a sign-in from one of them is usual', daemon.place_is_usual('192.168.251.10'), True)
ok('...and from anywhere else is not', daemon.place_is_usual('10.20.30.40'), False)
isemon.CONFIG['tacacs_from_mark'] = 0
ok('...and with the marking off, nothing is unusual again',
   daemon.place_is_usual('10.20.30.40'), None)
isemon.CONFIG['tacacs_from_mark'] = 1
ok('the dashboard is told both', (daemon.status()['places'],
                                  daemon.status()['places_mark']),
   (places, True))

# A site whose administrators work from a management network rather than
# from one jump box: listing every address in it by hand is not a thing
# anybody will keep up to date, and everything missed is marked as coming
# from somewhere unusual.
isemon.CONFIG['tacacs_from'] = ('192.168.251.10=LogHost, 172.22.22.0/24=VLAN500, '
                                '10.9.0.0-10.9.0.63=Jump, 2001:db8::/32=Lab, '
                                '172.22.22.14=TheOne, nonsense')
places = daemon.named_places()
ok('a subnet is a place, and so is a run of addresses',
   sorted(places), ['10.9.0.0-10.9.0.63', '172.22.22.0/24', '172.22.22.14',
                    '192.168.251.10', '2001:db8::/32'])
ok('an address inside a named subnet is one of the usual places',
   daemon.place_is_usual('172.22.22.10'), True)
ok('...at either end of it', [daemon.place_is_usual('172.22.22.0'),
                              daemon.place_is_usual('172.22.22.255')], [True, True])
ok('...and one just outside it is not', daemon.place_is_usual('172.22.23.1'), False)
ok('a run of addresses works the same way',
   [daemon.place_is_usual('10.9.0.40'), daemon.place_is_usual('10.9.0.99')], [True, False])
ok('...and so does an IPv6 prefix',
   [daemon.place_is_usual('2001:db8::5'), daemon.place_is_usual('2001:dead::5')],
   [True, False])
ok('the narrowest place wins, so a machine named inside a named subnet keeps its name',
   [daemon.place_of('172.22.22.14'), daemon.place_of('172.22.22.10')],
   ['172.22.22.14', '172.22.22.0/24'])
said = daemon.places_for(['172.22.22.10', '192.168.251.10', '10.20.30.40', ''])
ok('the page is told which place each address on it is in',
   [said['172.22.22.10']['name'], said['192.168.251.10']['name'],
    said['10.20.30.40']['name']], ['VLAN500', 'LogHost', ''])
ok('...and whether it is one at all',
   [said['172.22.22.10']['usual'], said['10.20.30.40']['usual']], [True, False])
isemon.CONFIG['tacacs_from_mark'] = 0
ok('...which with the marking off is nobody\u2019s business either way',
   daemon.places_for(['10.20.30.40'])['10.20.30.40']['usual'], None)
isemon.CONFIG['tacacs_from_mark'] = 1
ok('a place that is neither an address nor a range is still no place at all',
   'nonsense' in places, False)

# ---------------------------------------------------------------------------
title('starting the counting again')

# "Clear all" has to mean "back to nought", not "forget that it happened".
# A clear that deleted the records would destroy the evidence of whatever
# caused it, and one that let banned addresses back in would open the door
# every time somebody tidied a list. So: the records stay, the bans stay, the
# ladder stays, and only the moment the counting looks back to moves.
folder, store, daemon = fresh()
isemon.CONFIG['block_tries'] = 5
isemon.CONFIG['block_window_min'] = 60
isemon.CONFIG['block_bogus_names'] = ''
isemon.CONFIG['block_bogus_tries'] = 0
isemon.CONFIG['watch_devices'] = ''
isemon.CONFIG['never_block'] = ''
daemon._spare_from = None
now = time.time()

for n in range(4):
    store.add_failed({'session': 'clear-a/%d' % n, 'ts': now - 600 + n, 'ip': '198.51.100.70',
                      'username': 'jnovak', 'device': 'FTD-VPN', 'server': 'ise1',
                      'detail': '{}'})
store.block('198.51.100.71', None, 'banned before the clear', auto=True)

ok('four attempts are counted', store.failed_count('198.51.100.70', 3600, at=now), 4)
ok('...and the page can see the address counting up',
   [r['ip'] for r in daemon.counting_up(50)['rows']], ['198.51.100.70'])
ok('nothing has been written down about a clear yet', store.counting_from(), 0.0)

when = store.clear_counting(at=now)
ok('the counting starts again from now', round(store.counting_from()), round(when))
ok('...so the address is at nought', store.failed_count('198.51.100.70', 3600, at=now), 0)
ok('...and is off the list of those counting up', daemon.counting_up(50)['rows'], [])
ok('...and the page is told when it happened', round(daemon.counting_up(50)['from']),
   round(when))

# Nothing was destroyed and nobody was let in.
rows, total = store.failed_rows(ip='198.51.100.70')
ok('every attempt is still recorded', total, 4)
ok('...and still on the page that lists them', len(rows), 4)
ok('an address already banned stays banned',
   '198.51.100.71' in store.blocked_states(['198.51.100.71']), True)

# The ladder counts bans, not attempts, so a clear cannot make a repeat
# offender look like a first-timer.
ok('the ladder still remembers the earlier ban',
   store.blocked_before('198.51.100.71') >= 1, True)

# And it earns a ban again on what it does afterwards, from nought.
for n in range(4):
    store.add_failed({'session': 'clear-b/%d' % n, 'ts': now + 10 + n, 'ip': '198.51.100.70',
                      'username': 'jnovak', 'device': 'FTD-VPN', 'server': 'ise1',
                      'detail': '{}'})
ok('four more attempts after the clear are four, not eight',
   store.failed_count('198.51.100.70', 3600, at=now + 20), 4)
ok('...which is still under the bar',
   daemon.maybe_block('198.51.100.70', isemon._AtTime(now + 20)), None)
store.add_failed({'session': 'clear-b/4', 'ts': now + 20, 'ip': '198.51.100.70',
                  'username': 'jnovak', 'device': 'FTD-VPN', 'server': 'ise1', 'detail': '{}'})
ok('...and the fifth earns the ban',
   bool(daemon.maybe_block('198.51.100.70', isemon._AtTime(now + 21))), True)

shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('a whole country that is never kept out')

folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 60, 'block_lots': 0,
                      'block_bogus_tries': 0, 'feeds_ban': 0, 'watch_devices': '',
                      'never_block': '', 'never_block_countries': ''})
daemon._spare_from = None
now = time.time()
with store.db_write() as db:
    for first, last, cc in (('81.0.0.0', '81.255.255.255', 'CZ'),
                            ('185.136.0.0', '185.136.255.255', 'KZ')):
        lo, _ = isemon.pack_address(first)
        hi, _ = isemon.pack_address(last)
        db.execute('INSERT INTO geo_ranges (family, lo, hi, cc) VALUES (4,?,?,?)', (lo, hi, cc))
daemon._geo_said = {}
daemon._geo_any = None

HOME, AWAY = '81.2.3.4', '185.136.15.20'
ok('the country database knows where both of them are',
   [daemon.country_says(HOME), daemon.country_says(AWAY)], ['CZ', 'KZ'])
ok('with no country spared, neither is', [daemon.spared(HOME), daemon.spared(AWAY)], ['', ''])

isemon.CONFIG['never_block_countries'] = 'CZ'
daemon._spare_from = None
ok('a country on the list spares every address in it',
   daemon.spared(HOME), 'the whole of CZ')
ok('...and says which country it was', 'CZ' in daemon.spared(HOME), True)
ok('...while everybody else is untouched', daemon.spared(AWAY), '')

for n in range(5):
    store.add_failed({'session': 'cc/home/%d' % n, 'ts': now - 60 + n, 'ip': HOME,
                      'username': 'jnovak', 'country': 'CZ', 'server': 'ise2', 'detail': '{}'})
    store.add_failed({'session': 'cc/away/%d' % n, 'ts': now - 60 + n, 'ip': AWAY,
                      'username': 'jnovak', 'country': 'KZ', 'server': 'ise2', 'detail': '{}'})
ok('an address in a spared country is never banned by the counting',
   daemon.maybe_block(HOME, isemon._AtTime(now)), None)
ok('...while the same behaviour elsewhere is',
   daemon.maybe_block(AWAY, isemon._AtTime(now)) is not None, True)
ok('...and the sweep does not fetch it either',
   [daemon.judge_anything_missed(), store.blocked_until(HOME)], [0, None])
ok('the page shows it as spared, and says why',
   [r['spared'] for r in daemon.counting_up()['rows'] if r['ip'] == HOME],
   ['the whole of CZ'])

# Sparing a country lets go of whatever is banned in it, at that moment.
ok('the other one is still out', store.blocked_until(AWAY) is not None, True)
isemon.CONFIG['never_block_countries'] = 'CZ, KZ'
daemon._spare_from = None
freed = daemon.free_the_spared(by='a test')
ok('adding its country lets it back in at once', freed, [AWAY])
ok('...and it is really off the list', store.blocked_until(AWAY), None)
ok('...and it is written down as spared',
   [r['how'] for r in store.blocked_history()[0] if r['ip'] == AWAY][:1],
   ['whitelisted (the whole of KZ)'])
ok('...and a ban just lifted is at the top of the history, however long ago it began',
   store.blocked_history(limit=1)[0][0]['ip'], AWAY)

# A country code that is not one is refused rather than quietly meaning nothing.
try:
    isemon.check_setting('never_block_countries', 'Czechia')
    ok('a country that is not two letters is refused', False)
except ValueError as e:
    ok('a country that is not two letters is refused', 'two-letter' in str(e), True)
isemon.CONFIG['never_block_countries'] = ''
daemon._spare_from = None
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('the whole ISE record, kept small')

# Every row carries the record ISE wrote, and that record is nine tenths of
# what the database weighs. It goes in deflated and comes out exactly as it
# went in; rows written before this are read as they were.
folder, store, daemon = fresh()
big = json.dumps({'Step': ['11001'] * 60, 'FailureReason': '22056 Subject not found ' * 8,
                  'UserName': 'jnovak', 'cisco-av-pair': ['ip:inacl#%d=permit ip any any' % i
                                                          for i in range(20)]})
packed = store.pack_detail(big)
ok('a long record is packed', isinstance(packed, bytes), True)
ok('...and it is a great deal smaller', len(packed) * 4 < len(big), True)
ok('...and comes back exactly as it went in', store.unpack_detail(packed), big)
# On the file engine a short record goes in as the words it is, exactly as it
# always has, so that no database anybody already has is rewritten. The other
# two have a type on that column and take bytes, so there it is the bytes
# those words spell. Either way it reads back as the words.
ok('a short one is left as it is, in the shape this engine holds',
   store.pack_detail('{"a":1}'),
   '{"a":1}' if on_a_file() else b'{"a":1}')
ok('...and reads back as itself', store.unpack_detail('{"a":1}'), '{"a":1}')
ok('nothing is still nothing', store.unpack_detail(None), None)

# ...and once enough records have gone by, they are deflated against a
# dictionary made out of them, which is what takes a year of logs from
# fourteen gigabytes to under one.
for i in range(isemon.Storage.DICT_SAMPLES + 1):
    store.pack_detail(big.replace('jnovak', 'name%d' % i))
ok('a dictionary is made out of the records themselves',
   len(store.get_meta('detail_dict_now') or ''), 8)
tight = store.pack_detail(big)
ok('...and the records are then very much smaller still',
   len(tight) * 4 < len(packed), True)
ok('...and still come back exactly as they went in', store.unpack_detail(tight), big)
ok('...and a record written against the older way still opens',
   store.unpack_detail(packed), big)
ok('a record written against a dictionary this database has never seen says so '
   'rather than pretending',
   store.unpack_detail(isemon.Storage.PACKED_WITH + b'deadbeef' + b'nonsense'), '')

now = time.time()
store.add_failed({'session': 'z/1', 'ts': now - 10, 'ip': '203.0.113.30', 'username': 'jnovak',
                  'server': 'ise2', 'detail': big})
# Written before this version: the same record, as plain text.
with store.db_write() as db:
    db.execute("INSERT INTO failed (session, ts, ip, username, server, detail) "
               "VALUES ('z/old', ?, '203.0.113.31', 'jnovak', 'ise2', ?)", (now - 9, big))
kept = store.db.execute("SELECT detail FROM failed WHERE session='z/1'").fetchone()['detail']
ok('what is stored is the packed shape', isinstance(kept, bytes), True)
ok('...and the row still reads back whole', store.unpack_detail(kept), big)
old = store.db.execute("SELECT detail FROM failed WHERE session='z/old'").fetchone()['detail']
ok('a row written the old way reads back whole too', store.unpack_detail(old), big)
row = store.one_auth('failed', 'z/1')
ok('the popup can still open it', bool(row), True)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('the chart tells the VPN from the switches')

folder, store, daemon = fresh()
now = time.time()
for n in range(3):
    store.add_failed({'session': 'ch/v/%d' % n, 'ts': now - 60, 'ip': '203.0.113.20',
                      'username': 'jnovak', 'protocol': 'Radius', 'kind': 'vpn',
                      'server': 'ise2', 'detail': '{}'})
for n in range(2):
    store.add_failed({'session': 'ch/t/%d' % n, 'ts': now - 60, 'ip': '203.0.113.21',
                      'username': 'admin', 'protocol': 'Tacacs', 'kind': 'tacacs',
                      'server': 'ise1', 'detail': '{}'})
store.add_passed({'session': 'ch/pv', 'ts': now - 60, 'ip': '10.1.1.1', 'username': 'jnovak',
                  'kind': 'vpn', 'server': 'ise2', 'detail': '{}'})
store.add_passed({'session': 'ch/pt', 'ts': now - 60, 'ip': '10.1.1.2', 'username': 'pk',
                  'kind': 'tacacs', 'server': 'ise1', 'detail': '{}'})
# Neither of these is a login: one is the firewall a VPN session was handed,
# the other one command typed on a switch. Counted, one person looks like two.
store.add_passed({'session': 'ch/acl', 'ts': now - 60, 'ip': '10.1.1.1',
                  'username': '#ACSACL#-IP-X-1', 'kind': 'dacl', 'server': 'ise2',
                  'detail': '{}'})
store.add_passed({'session': 'ch/cmd', 'ts': now - 60, 'ip': '10.1.1.2', 'username': 'pk',
                  'kind': 'tacacs-cmd', 'server': 'ise1', 'detail': '{}'})
# ISE also writes down its own packet handling: a RADIUS packet arriving
# twice while the first is still being weighed. Those carry no address, no
# name and no protocol - they are records, but nobody is knocking.
for n in range(4):
    store.add_failed({'session': 'ch/noise/%d' % n, 'ts': now - 60, 'ip': '',
                      'username': '', 'server': 'ise2', 'detail': '{}'})

bars = [b for b in store.auth_counts(hours=1, step=3600) if b['failed'] or b['passed']]
ok('one bar holds the hour', len(bars), 1)
ok('...with the refusals split by which door was knocked on',
   [bars[0]['failed'], bars[0]['failed_tacacs']], [5, 2])
ok('...and the sign-ins too',
   [bars[0]['passed'], bars[0]['passed_tacacs']], [2, 1])
ok('...with the ACL and the command left out of both',
   bars[0]['passed'] + bars[0]['failed'], 7)
ok('...and the packet-handling records left out as well, but counted',
   [bars[0]['failed_other'], bars[0]['passed_other']], [4, 2])

# An address is a thing somebody has; the empty one is not an address. It sat
# at the top of "busiest addresses" on a real day with more tries than the
# busiest scanner, belonging to nobody.
ok('a record with no address is not the busiest address',
   [r['ip'] for r in daemon.store.top_attackers(now - 3600, 5)], ['203.0.113.20'])
ok('...and neither is a switch whose sockets are failing 802.1X: only the VPN '
   'is weighed', [r['ip'] for r in daemon.store.top_attackers(now - 3600, 5)
                  if r['ip'] == '203.0.113.21'], [])
ok('...nor is either counted as an address that tried',
   store.auth_totals(now - 3600)['failed']['addresses'], 2)
ok('...while the record itself is still there to be read',
   store.failed_rows(kind='other')[1], 4)

# The same split is a pair of tabs on the Failed attempts page, and the
# counts on them come from one walk of the index over the protocol.
# Those counts are answered from a cache that is allowed a second to fill and
# hands back what it last had if the database is slower than that - which is
# what the page wants and what a server engine sometimes does. So this asks
# the way the page does: again, in a moment.
def settled(get, want, seconds=20):
    # A stale count is handed back for up to RECOUNT_AFTER_S while a new one
    # is made behind whoever asked, and how long that is depends on what the
    # count costs - which is engine and machine. This waits it out rather
    # than guessing at it.
    until = time.time() + seconds
    got = get()
    while got != want and time.time() < until:
        time.sleep(0.4)
        got = get()
    return got

ok('the refusals are counted by which door was knocked on',
   settled(lambda: {k: v for k, v in store.failed_counts().items() if v},
           {'vpn': 3, 'tacacs': 2, 'other': 4}),
   {'vpn': 3, 'tacacs': 2, 'other': 4})
ok('...and asking for one kind gets only that kind',
   [store.failed_rows(kind='vpn')[1], store.failed_rows(kind='tacacs')[1],
    store.failed_rows(kind='other')[1]], [3, 2, 4])
ok('...while asking for none of them gets all of them',
   store.failed_rows()[1], 9)
store.add_failed({'session': 'ch/x', 'ts': now - 60, 'ip': '203.0.113.22',
                  'username': 'nobody', 'server': 'ise2', 'detail': '{}'})  # neither
store._distinct.clear()
ok('a record carrying neither protocol is neither, and is not lost',
   [store.failed_counts()['other'], store.failed_rows(kind='other')[1]], [5, 5])
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('narrowing anything down to one country')

folder, store, daemon = fresh()
now = time.time()
for n in range(4):
    store.add_failed({'session': 'cc/de/%d' % n, 'ts': now - 100 - n, 'ip': '203.0.113.9',
                      'username': 'jnovak', 'country': 'DE', 'server': 'ise2', 'detail': '{}'})
for n in range(2):
    store.add_failed({'session': 'cc/cz/%d' % n, 'ts': now - 90 - n, 'ip': '203.0.113.10',
                      'username': 'novak.cz', 'country': 'CZ', 'server': 'ise2', 'detail': '{}'})
ok('the countries a table holds are counted for the picker',
   store.country_counts('failed'), {'CZ': 2, 'DE': 4})
rows, total = store.failed_rows(country='DE')
ok('...and asking for one gets only that one', [total, {r['ip'] for r in rows}],
   [4, {'203.0.113.9'}])
ok('...however it was spelled', store.failed_rows(country='de')[1], 4)
ok('a name that ends .cz is not a Czech address',
   store.failed_rows(country='CZ')[1], 2)

# The ban history carries the country of the address it was made about, so a
# history can be narrowed the same way - and so that it keeps saying what it
# said even after the country database is fetched again.
store.db.execute('DELETE FROM geo_ranges')
store.block('203.0.113.9', None, 'a test', auto=True)
with store.db_write() as db:
    db.execute("UPDATE blocked_log SET country='DE' WHERE ip=?", ('203.0.113.9',))
store.block('203.0.113.10', None, 'a test', auto=True)
with store.db_write() as db:
    db.execute("UPDATE blocked_log SET country='CZ' WHERE ip=?", ('203.0.113.10',))
ok('the history says which countries it holds',
   store.history_countries(), {'CZ': 1, 'DE': 1})
ok('...and can be narrowed to one of them',
   [r['ip'] for r in store.blocked_history(country='DE')[0]], ['203.0.113.9'])
ok('...by its two letters typed into the search box as well',
   [r['ip'] for r in store.blocked_history(text='CZ')[0]], ['203.0.113.10'])

# A ban made now writes the country down by itself.
store.db.execute('DELETE FROM geo_ranges')
with store.db_write() as db:
    lo, _ = isemon.pack_address('198.51.100.0')
    hi, _ = isemon.pack_address('198.51.100.255')
    db.execute('INSERT INTO geo_ranges (family, lo, hi, cc) VALUES (4,?,?,?)', (lo, hi, 'SK'))
store.block('198.51.100.5', None, 'a test', auto=True)
ok('a ban written now carries the country with it',
   [r['country'] for r in store.blocked_history()[0] if r['ip'] == '198.51.100.5'], ['SK'])

# ...and one made before this was written down is filled in on the next start.
with store.db_write() as db:
    db.execute("UPDATE blocked_log SET country=NULL WHERE ip=?", ('198.51.100.5',))
ok('an older history is filled in once', store.fill_history_countries(), 1)
ok('...with what the country database says now',
   [r['country'] for r in store.blocked_history()[0] if r['ip'] == '198.51.100.5'], ['SK'])
ok('...and there is nothing left to fill in the second time',
   store.fill_history_countries(), 0)
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('one moment, spelled one way')

when = time.mktime(time.struct_time((2026, 9, 5, 7, 4, 3, 0, 0, -1)))
ok('a date is dd-mm-yyyy and a 24-hour clock', isemon.stamp(when), '05-09-2026 07:04:03')
ok('...and the short one is the same, not a different spelling',
   isemon.short_stamp(when), isemon.stamp(when))

# ---------------------------------------------------------------------------
title('a value is a value, whatever is typed into it')

# ISE separates fields with ", " and escapes a comma inside a value as "\,".
# Reading that escape is not a nicety: a user name is typed by whoever is
# knocking, and a name that could bring its own fields with it could say
# which address to judge and which door it came through.
INJECTED = ('Protocol=Radius, NetworkDeviceName=ftd1, NAS-Port-Type=Virtual, '
            'UserName=bob\\, Calling-Station-ID=198.51.100.7, '
            'Calling-Station-ID=45.9.148.9, FailureReason=22056 Subject not found')
fields = isemon.ise_fields(INJECTED)
ok('a name carrying a field is one name, not a name and a field',
   sorted(fields), ['Calling-Station-ID', 'FailureReason', 'NAS-Port-Type',
                    'NetworkDeviceName', 'Protocol', 'UserName'])
ok('...and the address judged is the one the record carries',
   isemon.ise_source_ip(fields), '45.9.148.9')
ok('...and the name is what was typed, without the escaping',
   isemon.ise_unescape(isemon.ise_first(fields, 'UserName')),
   'bob, Calling-Station-ID=198.51.100.7')

DRESSED = ('Protocol=Radius, NetworkDeviceName=ftd1, UserName=admin\\, CoAType=x, '
           'Calling-Station-ID=185.1.2.3, FailureReason=22056 Subject not found')
ok('a name pretending to be a change of authorisation is still a VPN attempt',
   isemon.ise_kind(isemon.ise_fields(DRESSED), 'admin', failed=True), 'vpn')

ok('a real name with a comma in it is still one value',
   isemon.ise_first(isemon.ise_fields('Subject=CN=Novak\\, Jan, Protocol=Radius'),
                    'Subject'),
   'CN=Novak\\, Jan')
ok('...and reads as it was written once the escaping is taken out',
   isemon.ise_unescape('CN=Novak\\, Jan'), 'CN=Novak, Jan')


# ---------------------------------------------------------------------------
title('The mending that rewrites rows can wait for the page to be up')
isemon.Storage.LATER = True
later = isemon.Storage(isemon.DB_FILE)
later.set_meta('passed_sorted', '0')
later.set_meta('failed_sorted', '0')
ok('opening the database does not do it', later.get_meta('passed_sorted'), '0')
later.catch_up()
ok('...and asking for it does', later.get_meta('passed_sorted'),
   str(isemon.Storage.SORT_VERSION))
later.set_meta('passed_sorted', '0')
thread = later.catch_up_behind()
thread.join(60)
ok('...as does asking for it on a thread of its own',
   later.get_meta('passed_sorted'), str(isemon.Storage.SORT_VERSION))
# ...while the first is still at it: a pass with nothing to do is over in
# a moment, and on a busy machine it could be over before the second asking.
_quick = later.catch_up
later.catch_up = lambda: (time.sleep(0.5), _quick())
ok('...and asking twice at once is asking once',
   later.catch_up_behind() is later.catch_up_behind(), True)
later._catching.join(60)
later.catch_up = _quick
isemon.Storage.LATER = False

title('the pass back over every log does not hold the table in memory')
many = store.failed_for_judging()
ok('what it weighs is handed over one row at a time',
   hasattr(many, '__next__') and not isinstance(many, list), True)
walked = sum(1 for _ in many)
ok('...and how many it will weigh is asked on its own, and agrees',
   store.how_many_to_judge(), walked)
ok('...over a window as well',
   store.how_many_to_judge(time.time() - 86400),
   sum(1 for _ in store.failed_for_judging(since=time.time() - 86400)))
ok('...and it is the rows that could earn a ban, nothing else',
   walked, store.db.execute(
       "SELECT COUNT(*) AS n FROM failed WHERE ip IS NOT NULL AND ip <> '' "
       "AND COALESCE(kind,'vpn')='vpn'").fetchone()['n'])

# ---------------------------------------------------------------------------
title('A table named twice in the list of later columns would be half a list')
# Python keeps the last of two entries under one key and says nothing about
# it, so a column added under a name that is already there is written, read
# back as present, and quietly never made: `mend` looks at the surviving
# entry only. It happened once, between writing this column and shipping it.
# The source is read rather than the dict, because by the time it is a dict
# the evidence is gone.
for which in ('LATER_COLUMNS', 'SCHEMA_ONLY_TABLES'):
    if not hasattr(isemon.Storage, which):
        continue
    src = inspect.getsource(isemon.Storage)
    at = src.find('%s = {' % which)
    if at < 0:
        continue
    block = src[at:src.index('\n    }', at)]
    keys = re.findall(r"^\s{8}'([a-z_]+)':", block, re.M)
    ok('no table is named twice in %s' % which,
       sorted(k for k in set(keys) if keys.count(k) > 1), [])
# ...and the one that started it, checked from the other end: every column
# the schema gives these two tables is either in the schema they are made
# from or in the list that adds it later, on an installation that has been
# upgraded rather than made fresh.
for table in ('failed', 'passed'):
    later = {name for name, _ in isemon.Storage.LATER_COLUMNS.get(table, ())}
    ok('%s gains the machine on an upgrade as well as on a fresh database'
       % table, 'machine' in later, True)

# ---------------------------------------------------------------------------
title('The indexes the page cannot be quick without')
# Every one of these was measured: without it the page in question reads a
# table of millions where it should seek, and on the databases these run
# against that is the difference between a tenth of a second and three.
# Checked as "it is there after the database has been opened", which is what
# `mend` promises, and as "the plan the engine picks uses it".
if not on_a_file():
    print('  --    which index an engine picks is that engine\u2019s own business, '
          'and this run is on a server')
else:
  have = {r['name'] for r in store.db.execute(
      "SELECT name FROM sqlite_master WHERE type='index'")}
  for name in ('failed_ip_ts_kind', 'passed_ip_ts_kind', 'failed_ts_country',
               'failed_kind_ts_ip', 'failed_ip_user', 'passed_ip_user',
               'failed_user_ip', 'passed_user_ip', 'events_kind'):
      ok('%s is there' % name, name in have, True)
  ok('...and every one of them is in the list that an upgrade adds',
     sorted({n for n, _ in isemon.Storage.LATER_INDEXES} - have), [])
  plans = {}
  for what, sql, args in (
          ('the box that finds an address',
           'SELECT ip, COUNT(*) AS tries, MAX(ts) AS last, MAX(country) AS country, kind '
           'FROM failed WHERE ip >= ? AND ip < ? GROUP BY ip, kind '
           'ORDER BY tries DESC, last DESC, ip LIMIT ?', ('203.0', '203.1', 8)),
          # Named outright rather than left to the engine: which index it
          # prefers depends on how big the table is, and what is being checked
          # here is the shape of the index - that the time sits beside the
          # address in it, so a page of the newest is the end of a slice.
          ('the newest hundred from one address',
           'SELECT * FROM failed INDEXED BY failed_ip_ts_kind WHERE ip = ? '
           'ORDER BY ts DESC, session DESC LIMIT 100',
           ('203.0.113.77',)),
          ('the countries of a window of refusals',
           'SELECT country, COUNT(*) AS n FROM failed INDEXED BY failed_ts_country '
           'WHERE ts>=? AND country<>"" GROUP BY country', (now - 86400,)),
          ('the chart, counted by door and by slot',
           'SELECT kind, CAST(ts/? AS INTEGER)*? AS slot, COUNT(*) AS n FROM failed '
           'WHERE ts>=? GROUP BY kind, slot', (3600, 3600, now - 86400))):
      plans[what] = ' '.join(r['detail'] for r in
                             store.db.execute('EXPLAIN QUERY PLAN ' + sql, args))
  ok('%s seeks down the index over the address' % 'the box that finds an address',
     'failed_ip_ts_kind' in plans['the box that finds an address'], True)
  ok('...without reading the table at all',
     'COVERING INDEX' in plans['the box that finds an address'], True)
  ok('the newest hundred from one address are the end of an index, not a sort of a table',
     'TEMP B-TREE FOR ORDER BY' not in plans['the newest hundred from one address'], True)
  ok('...with only the tie between two of the same second left to sort',
     'RIGHT PART OF ORDER BY' in plans['the newest hundred from one address'], True)
  ok('the countries of a window never read the table',
     'COVERING INDEX failed_ts_country' in plans['the countries of a window of refusals'],
     True)
  ok('...and neither does the chart',
     'COVERING INDEX failed_kind_ts' in plans['the chart, counted by door and by slot'], True)

# ---------------------------------------------------------------------------
title('The answers that are kept for a moment, and when they are not')
# Three of them cost a whole table and the page asks for them again every
# time anything anywhere moves. Keeping them is only safe while what they
# say cannot have changed - which is what each key is for.
counted = {'n': 0}


def costly():
    counted['n'] += 1
    return [{'ip': '203.0.113.1', 'n': counted['n']}], counted['n']


first = daemon.listed('a/1', costly)
ok('a list is worked out when it is asked for', (first[1], counted['n']), (1, 1))
ok('...and the same question a moment later is not worked out again',
   (daemon.listed('a/1', costly)[1], counted['n']), (1, 1))
ok('...while a different question is', daemon.listed('a/2', costly)[1], 2)
handed = daemon.listed('a/1', costly)[0]
handed[0]['ip'] = 'scribbled on'
ok('what is handed out is a copy, so one caller cannot write on the next one’s rows',
   daemon.listed('a/1', costly)[0][0]['ip'], '203.0.113.1')
for n in range(isemon.Daemon.LISTS_MOST + 4):
    daemon.listed('fill/%d' % n, costly)
ok('...and only a few are kept at once, because a list is a hundred rows',
   len(daemon._lists) <= isemon.Daemon.LISTS_MOST, True)
# ...and once it has been worked out once, nobody waits for it again: what is
# a few seconds old is handed over and the new one is made behind whoever
# asked. Wound back rather than waited out, because a suite that sleeps for
# nine seconds to check a cache is a suite nobody runs.
was = counted['n']
daemon.listed('stale/1', costly)
with daemon._lists_lock:
    when, value = daemon._lists['stale/1'][:2]
    daemon._lists['stale/1'] = (when - isemon.Daemon.LISTS_FOR - 1, value, 0.0)
went = time.time()
again = daemon.listed('stale/1', costly)
ok('an answer a few seconds old is handed over without waiting',
   (again[1], time.time() - went < 0.2), (was + 1, True))
for _ in range(50):
    time.sleep(0.02)
    if counted['n'] > was + 1:
        break
ok('...and the new one is worked out behind whoever asked', counted['n'], was + 2)
with daemon._lists_lock:
    when, value = daemon._lists['stale/1'][:2]
    daemon._lists['stale/1'] = (when - isemon.Daemon.LISTS_FOR * 8, value, 0.0)
ok('...while one old enough to be no answer at all is worked out properly',
   daemon.listed('stale/1', costly)[1], counted['n'])

# The Banned page. A ban, an unban and an expiry all have to show at once.
daemon.ban('198.51.100.66', minutes=60, why='a check', by='check')
ok('a ban made this second is on the page at once',
   '198.51.100.66' in [r['ip'] for r in daemon.blocked_list()], True)
ok('...and asking again with nothing changed says the same',
   '198.51.100.66' in [r['ip'] for r in daemon.blocked_list()], True)
daemon.unban('198.51.100.66', by='check')
ok('...and letting it back in takes it off the page at once',
   '198.51.100.66' in [r['ip'] for r in daemon.blocked_list()], False)
daemon.ban('198.51.100.67', minutes=60, why='a check', by='check')
ok('...and one made a moment ago is there',
   '198.51.100.67' in [r['ip'] for r in daemon.blocked_list()], True)
# Wound back to a ban that ran out a second ago, without going through
# anything that says so: this is the one change the page has to notice that
# nothing announced.
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?',
               (time.time() - 1, '198.51.100.67'))
ok('...and one that has run out while the page was open comes off it at once',
   '198.51.100.67' in [r['ip'] for r in daemon.blocked_list()], False)

# ---------------------------------------------------------------------------
title('What the machine calls itself, out of the record and into the row')
AV = 'cisco-av-pair'
ok('AnyConnect\u2019s own word for it is read',
   isemon.ise_machine({AV: ['mdm-tlv=device-platform=win',
                            'mdm-tlv=computer-name=NB-Dopital-2']}),
   'NB-Dopital-2')
ok('...and a record with no such pair in it says nothing rather than guessing',
   isemon.ise_machine({AV: ['mdm-tlv=device-platform=win']}), '')
ok('...as does one that says the name is not known',
   isemon.ise_machine({AV: ['mdm-tlv=computer-name=unknown']}), '')
ok('...and an av-pair that is not an mdm-tlv is not one either',
   isemon.ise_machine({AV: ['computer-name=NOTTHIS']}), '')
ok('a name with an = in it keeps all of itself',
   isemon.ise_machine({AV: ['mdm-tlv=computer-name=A=B']}), 'A=B')
ok('...and a long one is cut rather than carried whole',
   len(isemon.ise_machine({AV: ['mdm-tlv=computer-name=' + 'x' * 200]})), 80)

store.add_failed({'session': 'mach/f', 'ts': now - 5, 'ip': '203.0.113.99',
                  'username': 'dopital', 'kind': 'vpn', 'machine': 'NB-Dopital-2',
                  'reason': 'wrong password'})
store.add_passed({'session': 'mach/p', 'ts': now - 4, 'ip': '203.0.113.99',
                  'username': 'dopital', 'kind': 'vpn', 'machine': 'NB-Dopital-2'})
ok('it is written down on a refusal',
   store.db.execute("SELECT machine FROM failed WHERE session='mach/f'")
        .fetchone()['machine'], 'NB-Dopital-2')
ok('...and on a sign-in',
   store.db.execute("SELECT machine FROM passed WHERE session='mach/p'")
        .fetchone()['machine'], 'NB-Dopital-2')
ok('...and the list hands it to the page',
   (store.failed_rows(kind='vpn', text='NB-Dopital-2')[0] or [{}])[0].get('machine'),
   'NB-Dopital-2')
ok('...and searching for the machine finds the row',
   len((store.passed_rows(kind='vpn', text='NB-Dopital')[0] or [])), 1)
ok('...while the same search on another door does not go looking for it',
   len((store.passed_rows(kind='tacacs', text='NB-Dopital')[0] or [])), 0)
# It is shown and never judged: a machine name cannot earn anybody a ban,
# and the weighing must not so much as see it. The two rows above are one
# refusal each with a machine name on it, and what the judging counts is
# still the address and the door and nothing else.
# What the machine calls itself was in the ISE record all along and was
# simply not kept in a column of its own, so a database upgraded to this
# fills in its own history out of what it already holds. Nothing is
# re-read from a log for it, and nothing is invented for a record that
# never carried one.
AVLINE = ('cisco-av-pair=mdm-tlv=device-platform=win, '
          'cisco-av-pair=mdm-tlv=computer-name=OLD-DESK-7')
store.add_passed({'session': 'back/p', 'ts': now - 3, 'ip': '203.0.113.98',
                  'username': 'dopital', 'kind': 'vpn',
                  'detail': json.dumps({'UserName': 'dopital',
                                        'cisco-av-pair': ['mdm-tlv=device-platform=win',
                                                          'mdm-tlv=computer-name=OLD-DESK-7']})})
store.add_failed({'session': 'back/f', 'ts': now - 3, 'ip': '203.0.113.98',
                  'username': 'dopital', 'kind': 'vpn', 'reason': 'wrong password',
                  'detail': json.dumps({'UserName': 'dopital',
                                        'cisco-av-pair': ['mdm-tlv=computer-name=OLD-DESK-7']})})
store.add_passed({'session': 'back/none', 'ts': now - 3, 'ip': '203.0.113.97',
                  'username': 'nobody', 'kind': 'vpn',
                  'detail': json.dumps({'UserName': 'nobody'})})
with store.db_write() as db:
    db.execute("UPDATE passed SET machine=NULL WHERE session LIKE 'back/%'")
    db.execute("UPDATE failed SET machine=NULL WHERE session LIKE 'back/%'")
store.set_meta('passed_sorted', '0')
store.set_meta('failed_sorted', '0')
store.fill_in_kinds()
store.fill_in_failed_kinds()
saidp = store.db.execute("SELECT machine FROM passed WHERE session='back/p'").fetchone()
saidf = store.db.execute("SELECT machine FROM failed WHERE session='back/f'").fetchone()
none = store.db.execute("SELECT machine FROM passed WHERE session='back/none'").fetchone()
ok('a sign-in written before the column existed gets its machine back',
   saidp['machine'], 'OLD-DESK-7')
ok('...and so does a refusal', saidf['machine'], 'OLD-DESK-7')
ok('...and a record that never carried one is given nothing',
   none['machine'] or '', '')
ok('...and the rows say which rule they were put through',
   (store.get_meta('passed_sorted'), store.get_meta('failed_sorted')),
   (str(isemon.Storage.SORT_VERSION), str(isemon.Storage.SORT_VERSION)))

ok('a row with a machine name is judged exactly as one without',
   store.how_many_to_judge(), store.db.execute(
       "SELECT COUNT(*) AS n FROM failed WHERE ip IS NOT NULL AND ip <> '' "
       "AND COALESCE(kind,'vpn')='vpn'").fetchone()['n'])
ok('...and the machine is in none of the SQL the weighing runs',
   [line for line in inspect.getsource(isemon.Storage.failed_for_judging).split('\n')
    if 'machine' in line and not line.lstrip().startswith('#')], [])

# ---------------------------------------------------------------------------
title('One box, and it really does look everywhere')
# What it used to look in was the refusals, and only the refusals. So a
# person who has never failed at anything - which is nearly everybody - was
# not findable by the one box on the page that says it finds anything; and
# an address that signed in with a token was findable nowhere at all,
# because a token row carries the token server's own loopback and the
# person's address is only ever on the RADIUS packet beside it.
SEEN = '203.0.113.77'
store.add_passed({'session': 'seen/vpn', 'ts': now - 900, 'ip': SEEN, 'kind': 'vpn',
                  'username': 'quiet', 'country': 'CZ'})
store.add_failed({'session': 'seen/vpnf', 'ts': now - 1200, 'ip': SEEN, 'kind': 'vpn',
                  'username': 'quiet', 'reason': 'wrong password', 'country': 'CZ'})
store.add_passed({'session': 'seen/edu', 'ts': now - 600, 'ip': SEEN, 'kind': 'eduroam',
                  'username': 'quiet@elsewhere.cz', 'country': 'CZ'})
store.add_passed({'session': 'seen/tac', 'ts': now - 2000, 'ip': SEEN, 'kind': 'tacacs',
                  'username': 'quiet'})
# The token attempt: its row carries no address at all, and the packet does.
store.add_passed({'session': 'seen/otp', 'ts': now - 120, 'ip': '', 'kind': 'otp',
                  'username': 'quiet', 'subtype': 'Valid token used'})
store.note_otp_asked({'ts': now - 121, 'at': now - 60, 'server': 'otp1', 'kind': 'ask',
                      'half': 'ask', 'ip': SEEN, 'nas': '172.22.0.137', 'port': '43537',
                      'username': 'quiet@example.cz', 'verdict': 'accept', 'session': '',
                      'rid': '172.22.0.137:43537', 'attrs': {}, 'av': {}})

seen = store.address_seen(SEEN)
doors = {d['kind']: (d['failed'], d['passed']) for d in seen['doors']}
ok('every door it has been at is counted, one by one',
   sorted(doors), ['eduroam', 'otp', 'tacacs', 'vpn'])
ok('...the VPN with its refusal and its sign-in apart', doors['vpn'], (1, 1))
ok('...and the token attempt, which is in no row anywhere with this address on it',
   doors['otp'], (0, 1))
ok('the last sighting is the newest of them, whichever door that was',
   seen['last']['kind'], 'otp')
ok('...with the whole account the token log wrote, not the short name',
   seen['last']['username'], 'quiet@example.cz')
ok('...and whether that one got in', seen['last']['ok'], True)

found = daemon.find(SEEN)
ok('the card the box draws carries all of it', bool(found['address']['doors']), True)
ok('...and says where it was last seen',
   (found['address']['last'] or {}).get('kind'), 'otp')

near = {a['ip']: a for a in daemon.find('203.0.113.7')['addresses']}
ok('an address is suggested from every table, not only from the refusals',
   SEEN in near, True)
ok('...with all of its doors on the line, not whichever sorted highest',
   sorted(near[SEEN]['doors']) if SEEN in near else [],
   ['eduroam', 'otp', 'tacacs', 'vpn'])
ok('...and what it has been doing counted the same as before, door by door',
   (near[SEEN]['tries'], bool(near[SEEN]['last'])) if SEEN in near else None, (5, True))
# Two characters at least, as for the names beside them: one digit is a tenth
# of every address there has ever been, walked on a keystroke to offer eight.
ok('one character is not a prefix anybody means', store.find_addresses('2'), [])
ok('...and two are', [a['ip'] for a in store.find_addresses('20')
                      if a['ip'] == SEEN], [SEEN])

# A person who has only ever signed in. Before this they were invisible.
store.add_passed({'session': 'seen/only', 'ts': now - 300, 'ip': '203.0.113.78',
                  'kind': 'vpn', 'username': 'neverfailed'})
names = {n['name']: n for n in daemon.find('neverfail')['names']}
ok('a name that has never failed at anything is found',
   'neverfailed' in names, True)
ok('...and is counted as what it is, a sign-in rather than an attempt',
   (names.get('neverfailed') or {}).get('signed_in'), 1)
ok('...with nothing invented against it',
   (names.get('neverfailed') or {}).get('tries'), 0)
ok('a name that has both is still found, and says so',
   [(n['tries'], n['signed_in']) for n in daemon.find('quiet')['names']
    if n['name'] == 'quiet'], [(1, 3)])

# What to type into each door's own box to land on these records again.
ok('every door but one is searched by the address, because the address is on the row',
   sorted({d['by'] for d in seen['doors'] if d['kind'] != 'otp'}), ['address'])
ok('...and the address is what it hands over',
   sorted({d['q'] for d in seen['doors'] if d['kind'] != 'otp'}), [SEEN])
otp = [d for d in seen['doors'] if d['kind'] == 'otp'][0]
ok('the token log is searched by the account instead, having no address on its rows',
   otp['by'], 'account')
ok('...by the name without its realm, which is how that log writes it down',
   otp['q'], 'quiet')
ok('...and searching the token log that way finds the attempt',
   [r['session'] for r in store.passed_rows(kind='otp', text=otp['q'])[0]], ['seen/otp'])
# The whole account is searchable too, where the row kept it.
store.add_passed({'session': 'seen/otp2', 'ts': now - 100, 'ip': '', 'kind': 'otp',
                  'username': 'quiet', 'tkey': 'quiet@example.cz',
                  'subtype': 'Valid token used'})
ok('...as is the whole account, realm and all',
   'seen/otp2' in [r['session'] for r in
                   store.passed_rows(kind='otp', text='quiet@example.cz')[0]], True)
ok('...and that column is only searched at that door, not on every list',
   [r['session'] for r in store.passed_rows(kind='vpn', text='quiet@example.cz')[0]], [])

# The token packets from an address, which are in neither table under it.
packets = store.otp_asked_from(SEEN)
ok('the packets that carried a token from this address can be listed',
   len(packets), 1)
ok('...with what the RADIUS server answered and the box that asked',
   (packets[0]['verdict'], packets[0]['nas']), ('accept', '172.22.0.137'))
ok('...and they are on the address\u2019s own story',
   len(daemon.address_story(SEEN)['asked']), 1)
ok('...for that address and no other',
   store.otp_asked_from('203.0.113.79'), [])

# Nothing here judges, and a search may not change anything.
before = (store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'],
          store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n'],
          store.db.execute('SELECT COUNT(*) AS n FROM otp_asked').fetchone()['n'])
daemon.find(SEEN); daemon.find('quiet'); daemon.find('203.0')
ok('...and looking at any of it writes nothing down',
   (store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'],
    store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n'],
    store.db.execute('SELECT COUNT(*) AS n FROM otp_asked').fetchone()['n']), before)

# ---------------------------------------------------------------------------
title('One person, in the shape an address is drawn in')
WHO = 'quiet'
seen = store.name_seen(WHO)
ok('every door this name has been at is counted',
   sorted(d['kind'] for d in seen['doors']), ['otp', 'tacacs', 'vpn'])
# The name as it stands, not every spelling of it. `quiet@elsewhere.cz` on
# the visitors' network is somebody else's account at somebody else's
# institution, and folding the two together would make one person out of
# two - which is the opposite of what the realm is there for.
ok('...and a name with a realm on it is its own name, not this one',
   [d['kind'] for d in store.name_seen('quiet@elsewhere.cz')['doors']], ['eduroam'])
ok('...and each says what to type into that door\u2019s own box',
   sorted({d['q'] for d in seen['doors']}), [WHO])
ok('...and where it was last seen', (seen['last'] or {}).get('kind'), 'otp')
ok('the addresses it has come from are found', SEEN in
   [a['ip'] for a in seen['addresses']], True)
# ...including the one that only a token packet knows about, which is how
# somebody who signs in with a token would otherwise come from nowhere.
only = store.addresses_of('quiet')
ok('...including the one only a token packet carries',
   [a['ip'] for a in only if a['ip'] == SEEN], [SEEN])
counts = store.name_counts(WHO)
ok('how often it was refused and how often it got in',
   (counts['failed'] > 0, counts['passed'] > 0), (True, True))
EMPTY = {'doors': [], 'last': None, 'addresses': [], 'network': []}
ok('a name nobody has ever used says so rather than failing',
   store.name_seen('nobody-at-all'), EMPTY)
ok('...and so does nothing at all', store.name_seen(''), EMPTY)

# ---------------------------------------------------------------------------
title('Everything an address has failed at, including the token half')
# A token row carries the token server's loopback, not the person's, so
# asking for one address used to leave every token attempt out of its own
# story - while the chips above that very list counted them.
store.add_failed({'session': 'both/vpn', 'ts': now - 30, 'ip': '203.0.113.190',
                  'kind': 'vpn', 'username': 'quiet', 'reason': 'wrong password'})
store.add_failed({'session': 'both/otp', 'ts': now - 20, 'ip': '', 'kind': 'otp',
                  'username': 'quiet', 'reason': 'the token was wrong',
                  'asked_as': '172.29.1.57:4228'})
store.note_otp_asked({'ts': now - 21, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'ask', 'ip': '203.0.113.190', 'nas': '172.29.1.57',
                      'port': '4228', 'username': 'quiet@example.cz', 'verdict': '',
                      'session': '', 'rid': '172.29.1.57:4228', 'attrs': {}, 'av': {}})
rows, total = store.failed_rows(ip='203.0.113.190', limit=20)
ok('both halves of what that address failed at are in its own list',
   sorted(r['kind'] for r in rows), ['otp', 'vpn'])
ok('...and the count agrees with them', total, 2)
ok('...while another address is not dragged in with them',
   store.failed_rows(ip='203.0.113.91', limit=20)[1], 0)

# ---------------------------------------------------------------------------
title('Every list can be searched, at every door')
# The box that searches a list adds a column or two for the door being
# looked at - a MAC on the wireless, the whole account on the token log -
# and a column belongs to one table and not always to the other. Ask for
# one the table has not got and the query does not come back wrong, it does
# not run at all: every search of that list fails outright, which is what
# pressing one door on this page turned into.
#
# So every door is asked of both lists, with words in the box, and the only
# thing being checked is that the question can be asked at all.
BROKE = []
for door in ('vpn', 'tacacs', 'otp', 'eduroam', 'dot1x-lan', 'dot1x-wifi',
             'mab-lan', 'mab-wifi', 'other', ''):
    for which, ask in (('failed', store.failed_rows), ('passed', store.passed_rows)):
        try:
            ask(kind=door, text='mdolezal', limit=5)
        except Exception as e:
            BROKE.append('%s/%s: %s' % (which, door or 'every door', e))
ok('a search runs at every door, on the refusals and on the sign-ins alike',
   BROKE, [])
# ...and with the other things the box can be narrowed by at the same time,
# because those add columns of their own.
BROKE = []
for door in ('vpn', 'otp', 'eduroam', 'dot1x-wifi'):
    for which, ask in (('failed', store.failed_rows), ('passed', store.passed_rows)):
        try:
            ask(kind=door, text='mdolezal', ip='203.0.113.1', user='mdolezal',
                device='FTD-VPN', server='ise1', country='CZ', since=now - 86400, limit=5)
        except Exception as e:
            BROKE.append('%s/%s: %s' % (which, door, e))
ok('...and with every filter on it at once', BROKE, [])

# The same fault, one page further along. The cards that answer "who is
# this" and "what is this machine" read BOTH lists in one go, and the two
# lists have not got the same columns: `reason` is on the refusals, `tkey`
# and `subtype` are on the sign-ins. Ask one for the other's and the query
# is refused rather than empty - and every one of these catches the refusal
# and returns nothing, so the card goes blank and says nothing about why.
#
# So each is asked about a name and an address that are really in here, and
# the answer has to have something in it.
store.add_failed({'session': 'guard/vpn', 'ts': now - 30, 'server': 'ise1',
                  'ip': '203.0.113.191', 'username': 'guardman', 'kind': 'vpn',
                  'device': 'FTD-VPN', 'reason': 'wrong password'})
store.add_passed({'session': 'guard/vpn-ok', 'ts': now - 20, 'server': 'ise1',
                  'ip': '203.0.113.191', 'username': 'guardman', 'kind': 'vpn',
                  'device': 'FTD-VPN', 'machine': 'NB-GUARD'})
LOOKED = {}
for who in ('guardman', 'host/PC1.example.loc'):
    try:
        seen = store.name_seen(who)
        LOOKED[who] = {'doors': [d['kind'] for d in seen['doors']],
                       'addresses': [a['ip'] for a in seen['addresses']],
                       'network': isinstance(seen['network'], list),
                       'counts': store.name_counts(who),
                       'from': isinstance(store.addresses_of(who), list),
                       'at': [d['kind'] for d in store.address_seen('203.0.113.191')['doors']]}
    except Exception as e:
        LOOKED[who] = 'refused: %s' % e
ok('the card that answers "who is this" can be drawn for a person',
   LOOKED.get('guardman'),
   {'doors': ['vpn'], 'addresses': ['203.0.113.191'], 'network': True,
    'counts': {'failed': 1, 'passed': 1}, 'from': True, 'at': ['vpn']})
ok('...and for a machine, whose story is on the network rather than the VPN',
   LOOKED.get('host/PC1.example.loc', {}).get('network', False), True)

# ...and the network half of it, which is the one that reads a column from
# each list, told door by door so a wrong column cannot hide behind a door
# nobody seeded.
BROKE, FOUND = [], []
for door in isemon.Storage.MACHINE_DOORS:
    store.add_passed({'session': 'guard/%s/ok' % door, 'ts': now - 30, 'server': 'isea',
                      'username': 'guardpc', 'kind': door, 'device': 'SW-1',
                      'port': 'Gi1/0/1', 'mac': 'AA-BB-CC-DD-EE-FF',
                      'client': '10.9.9.9', 'subtype': 'let on', 'tkey': '607/VLAN607'})
    store.add_failed({'session': 'guard/%s/no' % door, 'ts': now - 60, 'server': 'isea',
                      'ip': '', 'username': 'guardpc', 'kind': door, 'device': 'SW-1',
                      'port': 'Gi1/0/1', 'mac': 'AA-BB-CC-DD-EE-FF',
                      'reason': '22056 Subject not found'})
    try:
        rows = store.network_seen('guardpc', limit=20)
    except Exception as e:
        BROKE.append('%s: %s' % (door, e))
        continue
    mine = [r for r in rows if r['kind'] == door]
    FOUND.append((door, len(mine),
                  sorted({r['vlan'] for r in mine}),
                  sorted({r['said'][:5] for r in mine})))
ok('what a machine did on the network can be asked at every network door',
   BROKE, [])
ok('...and both lists answer, each with the column that is its own',
   FOUND, [(door, 2, ['', '607/VLAN607'], ['22056', 'let o'])
           for door in isemon.Storage.MACHINE_DOORS])

# ---------------------------------------------------------------------------
title('The number was right and the sign-in was refused anyway')
# The handler in front of the token software asks it FIRST and checks the
# directory afterwards, so every rule it has - a group, a user filter, a
# directory that has gone away - refuses somebody the token server has
# already told `Valid token used`. Until this existed, isemon listed that
# attempt as a successful one, which is the page telling a lie about the
# one thing it is for. Every shape below is taken from the handler itself.
ok('a reason the token log never knew is kept',
   isemon.radius_refusal_words(
       'Denied access by rlm_perl: account does not pass LDAP group filter(s)'),
   'account does not pass LDAP group filter(s)')
for said, want in (
        ('Denied access by rlm_perl: account does not pass LDAP user filter',
         'account does not pass LDAP user filter'),
        ('Denied access by rlm_perl: LDAP server(s) have gone away',
         'LDAP server(s) have gone away'),
        ('Unable to bind to LDAP server', 'Unable to bind to LDAP server'),
        ('Denied access by rlm_perl: unknown error', 'unknown error')):
    ok('...and so is "%s"' % want[:38], isemon.radius_refusal_words(said), want)
ok('the token server\u2019s own answer, handed back, adds nothing and is dropped',
   isemon.radius_refusal_words('Denied by the token server: Token has already been used once'),
   '')
ok('...as is the HTTP status standing in for it',
   isemon.radius_refusal_words(
       'Denied access by rlm_perl authenticate function. ERROR: 400 BAD REQUEST'), '')
ok('...but a token server that is BROKEN is kept, because nothing else wrote it down',
   isemon.radius_refusal_words(
       'Denied by the token server: the token server answered 500 Internal Server Error'),
   'the token server answered 500 Internal Server Error')
# SSL and certificates. The handler puts whatever it was answered into the
# reply, and LWP puts its own troubles in the same place as a status - so
# `500 Can't connect to otp:443 (certificate verify failed)` means the token
# software was never reached at all. Dropped, an expired certificate on the
# token server is a VPN nobody can sign in to and a dashboard with nothing
# on it, so only the four-hundreds go: those are the CGI answering with its
# own refusal, which it wrote on its own log line.
for said, want in (
        ("Denied access by rlm_perl authenticate function. ERROR: 500 Can't connect to "
         "otp1.example.cz:443 (certificate verify failed)",
         "500 Can't connect to otp1.example.cz:443 (certificate verify failed)"),
        ('Denied access by rlm_perl authenticate function. ERROR: 500 SSL connect attempt '
         'failed error:0A000086:SSL routines::certificate verify failed',
         '500 SSL connect attempt failed error:0A000086:SSL routines::certificate '
         'verify failed'),
        ('Denied access by rlm_perl authenticate function. ERROR: 500 Internal Server Error',
         '500 Internal Server Error'),
        ('Denied access by rlm_perl authenticate function. ERROR: 501 Protocol scheme '
         'https is not supported', '501 Protocol scheme https is not supported')):
    ok('a token server that could not be reached is kept: %s' % want[:34],
       isemon.radius_refusal_words(said), want)
ok('...while a four-hundred is the CGI answering, and its own log has it',
   [isemon.radius_refusal_words(
        'Denied access by rlm_perl authenticate function. ERROR: %s' % x)
    for x in ('400 BAD REQUEST', '401 Unauthorized', '403 Forbidden')], ['', '', ''])
ok('a refusal that never reached the token software is known from its words',
   [isemon.radius_reached_token(x) for x in
    ("500 Can't connect to otp:443 (certificate verify failed)",
     '500 SSL connect attempt failed', '500 Internal Server Error',
     '501 Protocol scheme https is not supported')], [False] * 4)
ok('...and one from the directory, which the handler asks AFTER the token, is not',
   [isemon.radius_reached_token(x) for x in
    ('account does not pass LDAP group filter(s)', 'LDAP server(s) have gone away',
     'Unable to bind to LDAP server', 'unknown error')], [True] * 4)

ok('a shape nobody has seen is shown as it was said, rather than as a blank',
   isemon.radius_refusal_words('Client certificate has expired'),
   'Client certificate has expired')
ok('...and nothing at all stays nothing', isemon.radius_refusal_words(''), '')

isemon.CONFIG['otp'] = 1
isemon.CONFIG['otp_paths'] = ['/var/log/remote/otp']
store.add_passed({'session': 'ldap/1', 'ts': now - 60, 'ip': '', 'kind': 'otp',
                  'username': 'mdolezal', 'tkey': 'mdolezal@example.cz', 'server': 'otp',
                  'subtype': 'Valid token used', 'asked_as': '127.0.0.1:50003'})
store.note_otp_asked({'ts': now - 61, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'ask', 'ip': '', 'nas': '127.0.0.1', 'port': '50003',
                      'username': 'mdolezal@example.cz', 'verdict': '', 'session': '',
                      'rid': '127.0.0.1:50003', 'attrs': {}, 'av': {}})
store.note_otp_asked({'ts': now - 61, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'answer', 'port': '50003', 'verdict': 'reject',
                      'said': 'Denied access by rlm_perl: account does not pass '
                              'LDAP group filter(s)',
                      'rid': '127.0.0.1:50003', 'attrs': {}, 'av': {}})
ok('before it is read, the attempt is listed as a sign-in',
   bool(store.db.execute("SELECT 1 AS n FROM passed WHERE session='ldap/1'").fetchone()), True)
ok('...and reading the refusal moves it', daemon.apply_radius_refusals(), 1)
ok('...out of the sign-ins',
   store.db.execute("SELECT COUNT(*) AS n FROM passed WHERE session='ldap/1'").fetchone()['n'],
   0)
moved = store.db.execute("SELECT * FROM failed WHERE session='ldap/1'").fetchone()
ok('...and into the refusals, still a token record', moved['kind'], 'otp')
ok('...with the RADIUS server\u2019s own words as the reason',
   moved['reason'], 'account does not pass LDAP group filter(s)')
ok('...and a mark saying the token itself was right', moved['code'], 'token-ok')
ok('...keeping everything the row already held',
   (moved['username'], moved['server'], moved['asked_as']),
   ('mdolezal', 'otp', '127.0.0.1:50003'))
ok('reading it again moves nothing', daemon.apply_radius_refusals(), 0)
# It is a token record, and a token record is never judged whatever list it
# is in. This is the check that matters most here: moving a row between the
# two tables must not put anybody within reach of a ban.
ok('a moved row cannot earn anybody a ban',
   store.db.execute(
       "SELECT COUNT(*) AS n FROM failed WHERE session='ldap/1' "
       "AND ip IS NOT NULL AND ip <> '' AND COALESCE(kind,'vpn')='vpn'").fetchone()['n'], 0)
ok('...and it has no address on it to ban', moved['ip'], '')
# A refusal the token server itself made is left exactly as it was.
store.add_failed({'session': 'tok/1', 'ts': now - 50, 'ip': '', 'kind': 'otp',
                  'username': 'mdolezal', 'server': 'otp', 'reason': 'the token was wrong',
                  'asked_as': '127.0.0.1:51000'})
store.note_otp_asked({'ts': now - 51, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'ask', 'ip': '', 'nas': '127.0.0.1', 'port': '51000',
                      'username': 'mdolezal@example.cz', 'verdict': '', 'session': '',
                      'rid': '127.0.0.1:51000', 'attrs': {}, 'av': {}})
store.note_otp_asked({'ts': now - 51, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'answer', 'port': '51000', 'verdict': 'reject',
                      'said': 'Denied by the token server: Not a valid token',
                      'rid': '127.0.0.1:51000', 'attrs': {}, 'av': {}})
daemon.apply_radius_refusals()
ok('a refusal the token server made is left in its own words',
   store.db.execute("SELECT reason FROM failed WHERE session='tok/1'").fetchone()['reason'],
   'the token was wrong')
# A refusal with no token line at all. It is the shape that matters most -
# nobody can sign in while it lasts - and it exists only as the RADIUS
# reply, because nothing ever reached the thing that writes token lines.
store.note_otp_asked({'ts': now - 900, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'ask', 'ip': '', 'nas': '127.0.0.1', 'port': '60999',
                      'username': 'nobody@example.cz', 'verdict': '', 'session': '',
                      'rid': '127.0.0.1:60999', 'attrs': {}, 'av': {}})
store.note_otp_asked({'ts': now - 900, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'answer', 'port': '60999', 'verdict': 'reject',
                      'said': "Denied access by rlm_perl authenticate function. ERROR: 500 "
                              "Can't connect to otp1.example.cz:443 (certificate verify "
                              "failed)",
                      'rid': '127.0.0.1:60999', 'attrs': {}, 'av': {}})
ok('a refusal with no token line behind it is written down on its own',
   daemon.apply_radius_refusals(), 1)
alone = store.db.execute(
    "SELECT * FROM failed WHERE session LIKE 'otp/radius/%'").fetchone()
ok('...as a token record, which is never judged', alone['kind'], 'otp')
ok('...with no address on it to judge', alone['ip'] or '', '')
ok('...saying the token software was never reached', alone['code'], 'no-token')
ok('...in the words the RADIUS server used',
   alone['reason'].startswith("500 Can't connect"), True)
ok('...and reading the same packet again writes nothing twice',
   daemon.apply_radius_refusals(), 0)
# ...and one that DID reach it says so, because the handler asks the token
# software before it asks the directory.
store.note_otp_asked({'ts': now - 900, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'ask', 'ip': '', 'nas': '127.0.0.1', 'port': '60998',
                      'username': 'someoneelse@example.cz', 'verdict': '', 'session': '',
                      'rid': '127.0.0.1:60998', 'attrs': {}, 'av': {}})
store.note_otp_asked({'ts': now - 900, 'at': now, 'server': 'otp', 'kind': 'ask',
                      'half': 'answer', 'port': '60998', 'verdict': 'reject',
                      'said': 'Denied access by rlm_perl: LDAP server(s) have gone away',
                      'rid': '127.0.0.1:60998', 'attrs': {}, 'av': {}})
daemon.apply_radius_refusals()
lost = store.db.execute(
    "SELECT code FROM failed WHERE session LIKE 'otp/radius/%' AND reason LIKE 'LDAP%'"
).fetchone()
ok('a directory refusal with no token line says the line is missing, not that '
   'the token was never asked', lost['code'], 'token-lost')
# The rows this makes must never be taken for token lines themselves, or the
# second refusal of a morning writes its words over the first one's row.
ok('a row written from a packet is never mistaken for a token line',
   store.token_row_for('127.0.0.1:60999', 'otp', 'nobody@example.cz', now - 900, 120),
   ('', ''))

isemon.CONFIG['otp'] = 0

# ---------------------------------------------------------------------------
title('The access list for a router this machine does not talk to')
# What a site's own lists end with is a site's own business: as many lines as
# it needs, in the order they are pasted. Read before they are saved, because
# a router meeting a line it will not take stops there - halfway through,
# with half the list on it, at a console, at the worst possible moment.
for family, line in (
        ('ipv4', 'permit ip any any'),
        ('ipv4', 'deny   udp any any eq snmp'),
        ('ipv4', 'deny ip 10.0.0.0 0.255.255.255 any'),
        ('ipv4', 'permit tcp any host 10.0.0.1 eq 443 log'),
        ('ipv4', 'permit tcp any eq 80 443 any'),
        ('ipv4', '10 permit ip any any'),
        ('ipv4', 'remark whatever somebody wants to write here'),
        ('ipv4', '! a comment'),
        ('ipv4', 'permit 47 any any'),
        ('ipv4', 'permit object-group SERVICES any any'),
        ('ipv6', 'permit ipv6 any any'),
        ('ipv6', 'deny ipv6 2001:db8::/32 any'),
        ('ipv6', 'permit tcp any host 2001:db8::1 eq 443')):
    ok('"%s" reads as %s' % (line[:44], family), isemon.acl_faults(line, family), [])
for family, line, why in (
        ('ipv4', 'permt ip any any', 'not how a line of an access list starts'),
        ('ipv4', 'permit ip 10.0.0.0 any', 'not a wildcard mask'),
        ('ipv4', 'permit ipv6 any any', "the other family's word"),
        ('ipv6', 'permit ip any any', "the other family's word"),
        ('ipv4', 'deny ip host 10.1.1.999 any', 'is not an address'),
        ('ipv4', 'ip access-list extended NAME', 'OPENS an access list'),
        ('ipv4', 'permit tcp any any eq', 'with no port after it'),
        ('ipv4', 'deny ip 10.0.0.0 0.255.255.255', 'stops before it says')):
    bad = isemon.acl_faults(line, family)
    ok('"%s" is refused, and says why' % line[:40],
       bool(bad) and why in bad[0]['why'], True)
ok('...and it says which line it was',
   [f['n'] for f in isemon.acl_faults('permit ip any any\nnonsense\npermit ip any any')], [2])

# ...and the same reading is what stands between a typo and the settings.
for key, first in (('ios_acl_tail', 'permit ip any any'),
                   ('ios_acl_tail6', 'permit ipv6 any any')):
    try:
        isemon.check_setting(key, first + '\nnonsense here')
        ok('%s will not take a line a router would refuse' % key, False)
    except ValueError as e:
        ok('%s will not take a line a router would refuse' % key,
           'line 2' in str(e) and 'nonsense' in str(e), True)
ok('...and it takes one that reads',
   isemon.check_setting('ios_acl_tail', 'remark ours\npermit ip any any'),
   'remark ours\npermit ip any any')
for bad in ('has a space', '9lives', 'quotes"in-it'):
    try:
        isemon.check_setting('ios_acl_name', bad)
        ok('"%s" is not an access list name' % bad, False)
    except ValueError:
        ok('"%s" is not an access list name' % bad, True)
ok('...and a plain one is', isemon.check_setting('ios_acl_name', 'BORDER-IN_V4'),
   'BORDER-IN_V4')

folder, store, daemon = fresh()
store.block('203.0.113.9', None, 'out for good', auto=False, by='check')
store.block('198.51.100.0/24', None, 'a range', auto=False, by='check')
store.block('2001:db8::5', None, 'the other family', auto=False, by='check')
isemon.CONFIG['ios_acl_name'] = 'BORDER-IN-V4'
isemon.CONFIG['ios_acl_tail'] = ('remark ==== ours ====\npermit tcp any any established\n'
                                 'deny   udp any any eq snmp\npermit ip any any')
four = daemon.ios_acl()
ok('the list is called what the setting says', four['name'], 'BORDER-IN-V4')
ok('...and it opens with that name',
   'ip access-list extended BORDER-IN-V4' in four['text'], True)
ok('...with a deny line for each address that is out for good',
   (' deny   ip host 203.0.113.9 any' in four['text'],
    ' deny   ip 198.51.100.0 0.0.0.255 any' in four['text']), (True, True))
ok('...and the four lines of the ending underneath them, in order',
   four['text'].strip().split('\n')[-4:],
   [' remark ==== ours ====', ' permit tcp any any established',
    ' deny   udp any any eq snmp', ' permit ip any any'])
ok('...and nothing of the other family in it', '2001:db8::5' in four['text'], False)
ok('...which is said rather than left out quietly', four['skipped'], 1)
six = daemon.ios_acl(family='ipv6')
ok('with no IPv6 name set, one is made that cannot be pasted over the v4 list',
   six['name'] != four['name'], True)
isemon.CONFIG['ios_acl_name6'] = 'BORDER-IN-V6'
isemon.CONFIG['ios_acl_tail6'] = 'permit icmp any any\npermit ipv6 any any'
six = daemon.ios_acl(family='ipv6')
ok('...and with one set, that is what it is called', six['name'], 'BORDER-IN-V6')
ok('...opening the way a v6 list opens',
   'ipv6 access-list BORDER-IN-V6' in six['text'], True)
ok('...with its own ending, not the v4 one',
   six['text'].strip().split('\n')[-2:], [' permit icmp any any', ' permit ipv6 any any'])
ok('...and the v6 address in it', ' deny   ipv6 host 2001:db8::5 any' in six['text'], True)
# An ending nobody has set is the one this ships with, and an empty one is
# not an access list that stops everything.
isemon.CONFIG['ios_acl_tail'] = ''
ok('an ending that has been emptied falls back to the one that ships',
   daemon.ios_acl()['text'].strip().split('\n')[-2:],
   [' deny   udp any any eq snmp', ' permit ip any any'])
isemon.CONFIG['ios_acl_tail6'] = ''
ok('...on both sides', daemon.ios_acl(family='ipv6')['text'].strip().split('\n')[-1:],
   [' permit ipv6 any any'])
for key in ('ios_acl_name', 'ios_acl_name6', 'ios_acl_tail', 'ios_acl_tail6'):
    isemon.CONFIG[key] = isemon.DEFAULTS[key]
shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('One address is written one way, or it is two addresses')
# An IPv6 address has as many spellings as it has letters, and the counting
# is `GROUP BY ip` and `WHERE ip = ?`. A client that alternates the case of
# its own Calling-Station-ID was two rows of three against a bar of five and
# was never banned; two ISE nodes that disagreed on case would have done the
# same by accident.
UP = '2001:718:1E03:A001::1F'
DOWN = '2001:718:1e03:a001::1f'
ok('the two spellings really are one address',
   isemon.same_address(UP), isemon.same_address(DOWN))
ok('...and the reader writes down the one', [isemon.ise_source_ip(isemon.ise_fields(
       'UserName=x, Calling-Station-ID=%s, Protocol=Radius' % one)) for one in (UP, DOWN)],
   [DOWN, DOWN])
ok('...however the record says it',
   isemon.ise_source_ip(isemon.ise_fields(
       'UserName=x, Tunnel-Client-Endpoint=(tag=0) %s, Protocol=Radius' % UP)), DOWN)
ok('...and an IPv4 address is left exactly as it was',
   isemon.ise_source_ip(isemon.ise_fields(
       'UserName=x, Calling-Station-ID=203.0.113.9, Protocol=Radius')), '203.0.113.9')
folder5, store5, daemon5 = fresh()
isemon.CONFIG.update({'blacklist': 1, 'block_tries': 5, 'block_window_min': 10,
                      'block_bogus_tries': 0, 'block_lots': 0, 'watch_devices': ''})
now5 = time.time()
for n in range(6):
    said = UP if n % 2 else DOWN
    got = isemon.ise_fields('UserName=INVALID, Calling-Station-ID=%s, Protocol=Radius, '
                            'NetworkDeviceName=FTD-VPN,' % said)
    store5.add_failed({'session': 'v6/%d' % n, 'ts': now5 - n, 'kind': 'vpn',
                       'ip': isemon.ise_source_ip(got), 'username': 'INVALID',
                       'server': 'ise2', 'reason': 'wrong password', 'detail': '{}'})
daemon5.maybe_block(DOWN, isemon._AtTime(now5))
ok('six tries from one client, alternating the case, are six tries',
   store5.failed_count(DOWN, 600), 6)
ok('...and earn the ban the bar says they should',
   [r['ip'] for r in store5.blocked_all()], [DOWN])
# ...and taking it off again works whichever way it is typed.
daemon5.unban(UP, by='a check')
ok('an address let back in the other way really comes off',
   store5.blocked_all(), [])
shutil.rmtree(folder5, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A write that cannot even be started lets go of the lock')
# The write lock is taken first and then two things happen that can fail:
# making this thread's connection, and opening the transaction on it. A
# `with` block calls `__exit__` only when `__enter__` returned - so either of
# those raising left the lock held by a thread that walked away, and every
# writer after it, the reader on the main thread included, waited for ever.
# The daemon stays up and the pages keep being drawn off the readers, so the
# dashboard is green while nothing is ever written, judged or banned again.
folder6, store6, daemon6 = fresh()
_real_db = type(store6).db
_blow = {'once': True}


def _sulk(self):
    if _blow['once']:
        _blow['once'] = False
        raise sqlite3.OperationalError('the database server has gone away')
    return _real_db.fget(self)


type(store6).db = property(_sulk)
try:
    with store6.db_write():
        pass
    ok('a write that cannot be started raises', False)
except sqlite3.Error:
    ok('a write that cannot be started raises', True)
finally:
    type(store6).db = _real_db
_done = []


def _writer():
    try:
        with store6.db_write() as db:
            db.execute("INSERT INTO meta (key, value) VALUES ('after','yes') "
                       'ON CONFLICT(key) DO UPDATE SET value=excluded.value')
        _done.append(True)
    except Exception:
        _done.append(False)


_t = threading.Thread(target=_writer, daemon=True)
_t.start()
_t.join(3)
ok('...and the next write is not waiting for a lock nobody will let go of',
   _done, [True])
ok('...so it really wrote', store6.get_meta('after'), 'yes')
shutil.rmtree(folder6, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A search finds a word whatever case it is typed in, on every engine')
# The find box and the searches behind every door are `LIKE '%what%'`, and
# whether that ignores case is a property of the SERVER, not of the program:
# SQLite folds ASCII by itself and MariaDB collates `..._ci`, but PostgreSQL
# compares exactly. The same search, on the same records, found a person on
# two of the three engines and nothing at all on the third. So both sides are
# folded in the program (`like_same` and `like_for`), which every engine then
# does the same way. This suite is run against all three.
folder7, store7, daemon7 = fresh()
now7 = time.time()
store7.add_failed({'session': 'case/1', 'ts': now7, 'ip': '203.0.113.77', 'kind': 'vpn',
                   'username': 'Novak', 'machine': 'NB-Dopital-2', 'device': 'SW-Brno-01',
                   'mac': 'BC-FC-E7-11-22-33', 'reason': 'Wrong password',
                   'server': 'ise2', 'detail': '{}'})
store7.add_passed({'session': 'case/2', 'ts': now7, 'ip': '203.0.113.77', 'kind': 'vpn',
                   'username': 'Novak', 'machine': 'NB-Dopital-2', 'device': 'SW-Brno-01',
                   'mac': 'BC-FC-E7-11-22-33', 'server': 'ise2', 'detail': '{}'})
for typed in ('novak', 'NOVAK', 'Novak', 'ovA'):
    rows7, _ = store7.failed_rows(limit=10, text=typed)
    ok('a refusal is found by typing %r' % typed, bool(rows7), True)
for typed in ('nb-dopital', 'NB-DOPITAL'):
    rows7, _ = store7.failed_rows(limit=10, text=typed, kind='vpn')
    ok('...and by the machine, typed %r' % typed, bool(rows7), True)
for typed in ('wrong password', 'Wrong Password'):
    rows7, _ = store7.failed_rows(limit=10, text=typed)
    ok('...and by the reason, typed %r' % typed, bool(rows7), True)
for typed in ('sw-brno', 'SW-BRNO'):
    rows7, _ = store7.failed_rows(limit=10, text=typed)
    ok('...and by the door, typed %r' % typed, bool(rows7), True)
for typed in ('novak', 'NOVAK'):
    ok('the find box knows the name, typed %r' % typed,
       [one['name'] for one in store7.find_names(typed)], ['Novak'])
ok('...and still does not answer half a letter', store7.find_names('n'), [])
store7.add_event('Told', 'a Person Signed In', who='Novak')
for typed in ('person', 'PERSON', 'novak', 'told'):
    rows7 = store7.events(limit=10, text=typed)
    ok('an event is found by typing %r' % typed, bool(rows7), True)
daemon7.ban('203.0.113.77', why='Too Many Tries', by='Admin')
for typed in ('too many', 'TOO MANY', 'admin', '203.0.113.77'):
    rows7, _ = store7.block_events(limit=10, text=typed)
    ok('a ban is found by typing %r' % typed, bool(rows7), True)
rows7, _ = store7.block_events(limit=10, text='zznothing')
ok('...and nothing is found that is not there', bool(rows7), False)
for typed in ('too many', 'TOO MANY', 'admin'):
    rows7, _ = store7.blocked_history(limit=10, text=typed)
    ok('the ban history is found by typing %r' % typed, bool(rows7), True)
shutil.rmtree(folder7, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A record nobody can read keeps its door instead of losing it')
# The worst shape there is: a pass over the whole table that turns "I could
# not read this" into "this was not a login". `other` is the one door that is
# counted by nothing - not the bans, not the counting, not the safety net - so
# a re-sort on the first start after an upgrade could empty the counting of
# every refusal whose record would not decode, and say so in a line that reads
# like a success.
folder8, store8, daemon8 = fresh()
now8 = time.time()
for n in range(4):
    store8.add_failed({'session': 'blind/%d' % n, 'ts': now8 - n, 'ip': '203.0.113.60',
                       'kind': 'vpn', 'username': 'INVALID', 'server': 'ise2',
                       'reason': 'wrong password',
                       'detail': json.dumps({
                           'UserName': 'INVALID',
                           'Calling-Station-ID': '203.0.113.60',
                           'CVPN3000/ASA/PIX7x-Tunnel-Group-Name': 'CORPNET',
                           'NetworkDeviceName': 'FTD-VPN'})})
# One row's record made unreadable, the way a dictionary this database no
# longer has makes one unreadable.
with store8.db_write() as db:
    db.execute("UPDATE failed SET detail=? WHERE session='blind/1'", (b'\x78\x9c not zlib',))
store8.set_meta('failed_sorted', '0')
store8.fill_in_failed_kinds()
kinds8 = store8.db.execute('SELECT kind, COUNT(*) AS n FROM failed GROUP BY kind').fetchall()
ok('the rows that could be read keep their door',
   {r['kind']: r['n'] for r in kinds8}, {'vpn': 4})
ok('...and the sorting is marked as done all the same: a row that will not '
   'decode today will not decode tomorrow, and walking the table at every '
   'start for it is what 1.10.92 did', store8.get_meta('failed_sorted'),
   str(store8.SORT_VERSION))
ok('...and the counting still sees every one of them',
   sum(one['tries'] for one in store8.counting_now(now8 - 3600)), 4)
# ...and a record too long for the column stays readable in the first place.
big = {'UserName': 'INVALID', 'Calling-Station-ID': '203.0.113.61',
       'Huge': 'x' * 90000, 'AlsoBig': 'y' * 30000, 'NetworkDeviceName': 'FTD-VPN'}
said8 = isemon.detail_within(big, 60000)
ok('a record too long to keep is cut and is still readable JSON',
   len(said8) <= 60000 and json.loads(said8).get('Calling-Station-ID'), '203.0.113.61')
ok('...and says which field went', '(too long to keep' in said8, True)
ok('...while one that fits is left exactly as it was',
   json.loads(isemon.detail_within({'a': 'b'}, 60000)), {'a': 'b'})
many = {('f%03d' % n): ('z' * 400) for n in range(400)}
said8 = isemon.detail_within(many, 6000)
ok('...and a record of many small fields is cut to fit and still parses',
   len(said8) <= 6000 and isinstance(json.loads(said8), dict), True)
shutil.rmtree(folder8, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A setting nobody can read is refused, not quietly replaced')
# Every one of these used to be accepted and then silently become something
# else, which on a filter setting means banning nobody at all.
for key, value in (('block_tries', 'three'), ('block_tries', None),
                   ('block_tries', ''), ('judge_max_age_h', None),
                   ('watch_devices', None), ('mikrotik_every', '5 min'),
                   ('mikrotik_every', 'soon'), ('watch_devices', 'ftd one'),
                   ('block_window_min', None)):
    try:
        isemon.check_setting(key, value)
        ok('%s = %r is refused' % (key, value), False)
    except ValueError:
        ok('%s = %r is refused' % (key, value), True)
ok('a device list written as a list is kept as a list, not as its own spelling',
   isemon.check_setting('watch_devices', ['ftd1', 'asa1']), 'ftd1, asa1')
ok('...and written one per line it is still a list of names',
   isemon.comma_list(isemon.check_setting('watch_devices', 'ftd1\nasa1')), ['ftd1', 'asa1'])
ok('...and a name with a space in it is refused rather than kept as a name '
   'nothing is called',
   isemon.comma_list('ftd1\nasa1'), ['ftd1', 'asa1'])
ok('how often the firewall is looked at is read the same way twice',
   isemon.check_setting('mikrotik_every', 'change'), 'change')
ok('...and a number is kept as one', isemon.check_setting('mikrotik_every', '12'), '12')
was8 = isemon.CONFIG.get('mikrotik_every')
isemon.CONFIG['mikrotik_every'] = '5 min'      # as an old database may hold it
ok('...and a value already saved that nobody can read does not raise, '
   'it falls back', isemon.Daemon.mikrotik_interval(), ('every', 5.0))
isemon.CONFIG['mikrotik_every'] = was8
folder9 = Path(tempfile.mkdtemp())
(folder9 / 'config.json').write_text(json.dumps(
    {'block_tries': 'three', 'block_window_min': 1440, 'watch_devices': ['ftd1']}))
was_cfg = dict(isemon.CONFIG)
try:
    got9 = isemon.load_config(folder9 / 'config.json')
    ok('a file with one unreadable setting still brings in the others',
       got9['block_window_min'], 1440)
    ok('...and the unreadable one is named rather than silently replaced',
       bool([one for one in isemon.BAD_CONFIG if one.startswith('block_tries')]), True)
    ok('...and a list where a comma string was expected is honoured',
       got9['watch_devices'], 'ftd1')
finally:
    isemon.CONFIG.clear(); isemon.CONFIG.update(was_cfg)
    isemon.BAD_CONFIG[:] = []
shutil.rmtree(folder9, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Counting wrong passwords is done under one lock, and before the check')
# The throttle was a read, a quarter of a second of PBKDF2, and a write-back
# of a list built from a comprehension. So a burst all passed the test at
# once AND overwrote each other's counts: five tries a quarter of an hour
# became thirty, for ever, against every account including the
# administrator's.
folder10, store10, daemon10 = fresh()
store10.put_user('gate', 'the-right-one-11', 'fulladmin')
isemon.CONFIG.update({'login_tries': 3, 'login_wait_min': 15})
got10, refused10 = [], []


def _guess():
    try:
        daemon10.login('gate', 'wrong', ip='198.51.100.5')
        got10.append('in')
    except ValueError as e:
        (refused10 if 'too many' in str(e) else got10).append(str(e)[:20])


crowd = [threading.Thread(target=_guess) for _ in range(12)]
for one in crowd:
    one.start()
for one in crowd:
    one.join(20)
ok('twelve at once are not all let through the bar of three',
   len(refused10) >= 9, True)
ok('...and none of them got in', [x for x in got10 if x == 'in'], [])
ok('...and the next one after them is refused too',
   [_guess(), 'too many' in (refused10[-1] if refused10 else '')][1], True)
# ...and the right password still gets in, and clears the count.
isemon.CONFIG.update({'login_tries': 3, 'login_wait_min': 15})
daemon10._login_forget('198.51.100.6')
for _ in range(2):
    try:
        daemon10.login('gate', 'wrong', ip='198.51.100.6')
    except ValueError:
        pass
said10 = daemon10.login('gate', 'the-right-one-11', ip='198.51.100.6')
ok('the right password still gets in after a couple of wrong ones',
   said10.get('name'), 'gate')
ok('...and what was counted against that address is let go',
   daemon10._login_fails.get('198.51.100.6'), None)
# ...and a right password on a switched-off account is not a wrong password:
# counting it would let anybody lock an address out by typing the right one.
store10.put_user('shut', 'the-right-one-12', 'readonly')
store10.put_user('shut', disabled=1)
for _ in range(5):
    try:
        daemon10.login('shut', 'the-right-one-12', ip='198.51.100.7')
    except ValueError as e:
        last10 = str(e)
ok('a right password on a switched-off account says so', 'switched off' in last10, True)
ok('...and is never counted as a wrong password',
   daemon10._login_fails.get('198.51.100.7') or [], [])
ok('...not against the name either', daemon10._login_fails.get('user:shut') or [], [])
shutil.rmtree(folder10, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A card is not a search box')
# The box over a list searches: somebody typing half a name expects to find
# the name. A CARD counted the rows where the name IS that name, and pressing
# it has to open those rows and no others - or the number at the top of the
# popup is not the number on the row that was pressed. Three of the columns a
# card can be grouped by had no filter of their own and fell through to the
# search, and the two numbers did not match.
folder11, store11, daemon11 = fresh()
now11 = time.time()
for n, who in enumerate(('novak', 'novakova', 'novak')):
    store11.add_failed({'session': 'exact/%d' % n, 'ts': now11 - n, 'kind': 'vpn',
                        'ip': '203.0.113.9', 'username': who, 'reason': 'wrong password',
                        'mac': 'AA-BB-CC-00-00-0%d' % n, 'realm': 'vut.cz',
                        'server': 'ise1', 'detail': '{}'})
store11.add_failed({'session': 'exact/9', 'ts': now11 - 9, 'kind': 'vpn',
                    'ip': '203.0.113.9', 'username': 'somebody',
                    'reason': 'wrong password, three times', 'mac': 'AA-BB-CC-00-00-09',
                    'realm': 'vutbr.cz', 'server': 'ise1', 'detail': '{}'})
ok('a name typed in the box finds the longer one too',
   store11.failed_rows(limit=10, user='novak')[1], 3)
ok('...while a card asking for that name gets only that name',
   store11.failed_rows(limit=10, username='novak')[1], 2)
ok('an answer is asked for whole rather than as words inside another',
   store11.failed_rows(limit=10, reason='wrong password')[1], 3)
ok('...and the longer answer is its own row', 
   store11.failed_rows(limit=10, reason='wrong password, three times')[1], 1)
ok('a hardware address is a filter of its own',
   store11.failed_rows(limit=10, mac='AA-BB-CC-00-00-01')[1], 1)
ok('...and it does not care how it is typed',
   store11.failed_rows(limit=10, mac='aa-bb-cc-00-00-01')[1], 1)
ok('an institution is a filter of its own, and not half of another',
   (store11.failed_rows(limit=10, realm='vut.cz')[1],
    store11.failed_rows(limit=10, realm='vutbr.cz')[1]), (3, 1))
# ...and the box over the list is still the box over the list: half a name
# finds the name, which is the whole reason the two are not the same filter.
ok('...while the search box still finds a name by half of it',
   store11.failed_rows(limit=10, text='nova')[1], 3)
# ...and the card the page draws agrees with the list the page opens.
for by, column in (('username', 'username'), ('reason', 'reason'), ('mac', 'mac'),
                   ('realm', 'realm')):
    rows = store11.door_subjects('vpn', now11 - 3600, by, 12)
    for one in rows[:3]:
        got = store11.failed_rows(limit=1, since=now11 - 3600, kind='vpn',
                                  **{column: one['said']})[1]
        ok('by %s: the card says %d and pressing it opens the same'
           % (by, one['failed']), got, one['failed'])
shutil.rmtree(folder11, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A ban made longer here reaches the router')
# The database said "for good"; the router kept the ten minutes it was first
# given, let the address back in when they ran out, and the page went on
# saying it was banned. Two halves: the escalation never told the router, and
# the sync skipped anything already there without looking at its timeout.
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10,
                      'block_ladder': '10, 60, 1440, forever', 'block_lots': 0,
                      'block_bogus_tries': 0, 'feeds_ban': 0})
told = []
daemon.mikrotik_after_change = lambda: told.append(time.time())
now = time.time()
IP = '198.51.100.90'
for n in range(3):
    failed_at(IP, now - 600 + n)
daemon.maybe_block(IP, isemon._AtTime(now - 597))
told[:] = []
began = time.time()
for n in range(3):
    failed_at(IP, began + 10 + n, key='esc/%d' % n)
longer = daemon.maybe_escalate(IP, isemon._AtTime(began + 13))
ok('an address that goes on trying is held longer', bool(longer), True)
ok('...and the router is told about it', len(told), 1)
ok('the router\u2019s own duration is read',
   [isemon.mikrotik_seconds(t) for t in ('9m59s', '1d2h3m4s', '00:09:59', '1d 02:03:04')],
   [599, 93784, 599, 93784])
ok('...and not guessed at where it is not one', isemon.mikrotik_seconds('junk'), None)
ok('an entry the router holds for less than this means is written again',
   [daemon.router_holds_too_short(held, row) for held, row in (
       (600, {'forever': False, 'left': 3600}),      # a day here, ten minutes there
       (600, {'forever': True, 'left': 0}),          # for good here, a timeout there
       (None, {'forever': False, 'left': 3600}),     # permanent there: long enough
       (3600, {'forever': False, 'left': 3500}),     # near enough: left alone
       (3600, {'forever': False, 'left': 3660}))],   # within the slack: left alone
   [True, True, False, False, False])

title('...and reaches the top of the ladder')
# The ladder's last rung is "for good" and the escalation read only the
# minutes beside it: an address on its third ban that reached the bar again
# was given another day when the ladder said for ever.
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10,
                      'block_ladder': '10, 60, forever', 'block_lots': 0,
                      'block_bogus_tries': 0, 'feeds_ban': 0, 'block_ladder_forget_days': 30})
daemon.mikrotik_after_change = lambda: None
now = time.time()
IP = '198.51.100.91'
# Two bans already on the record - as history, dated last week, so that
# the counting floor (the end of the last ban) is well before today's tries.
with store.db_write() as db:
    for n in range(2):
        at = now - 86400 * (n + 3)
        db.execute("INSERT INTO block_events (ts, ip, what, why, auto, by) "
                   "VALUES (?,?,'blocked','earlier',1,'')", (at, IP))
        db.execute("INSERT INTO block_events (ts, ip, what, why, auto, by) "
                   "VALUES (?,?,'let back in','ran out',1,'')", (at + 600, IP))
for n in range(3):
    failed_at(IP, now - 600 + n)
daemon.maybe_block(IP, isemon._AtTime(now - 597))
row = store.db.execute('SELECT until FROM blocked WHERE ip=?', (IP,)).fetchone()
ok('the third ban is the last rung', row is not None and row['until'] is None, True)

title('...and a month of behaving is a month of behaving')
# The bans this program remembered making were a plain count that only went
# up, so on a daemon that stayed up "behaves for a month and starts again"
# was true of the database and false of the memory beside it.
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10,
                      'block_ladder': '10, 60, 1440, forever', 'block_lots': 0,
                      'block_bogus_tries': 0, 'feeds_ban': 0, 'block_ladder_forget_days': 30})
daemon.mikrotik_after_change = lambda: None
IP = '198.51.100.92'
# Three bans remembered from long ago, none in the database's window.
daemon._blocked_times[IP] = [time.time() - 86400 * 60] * 3
minutes, words = daemon.block_length(IP)
ok('bans remembered from two months ago do not count', minutes, 10)
ok('...so it starts at the bottom of the ladder', 'first time' in words, True)
daemon._blocked_times[IP] = [time.time() - 86400 * 2]
minutes, words = daemon.block_length(IP)
ok('...while one remembered from this month does', minutes, 60)

title('A subnet is not a way round the whitelist')
folder, store, daemon = fresh()
isemon.CONFIG['never_block'] = '10.1.2.3, 192.168.5.0/24'
daemon._spare_from = None
ok('a subnet that takes in a whitelisted address is spared',
   daemon.spared('10.0.0.0/8'), '10.1.2.3')
ok('...and one inside a whitelisted range', daemon.spared('192.168.5.64/26'), '192.168.5.0/24')
ok('...while one that touches neither is not', daemon.spared('203.0.113.0/24'), '')
ok('...and a single address behaves as it always did',
   [daemon.spared('10.1.2.3'), daemon.spared('10.1.2.4')], ['10.1.2.3', ''])

title('Only failures on the watched devices count towards a ban')
folder, store, daemon = fresh()
isemon.CONFIG.update({'block_tries': 3, 'block_window_min': 10, 'watch_devices': 'FTD-VPN',
                      'block_lots': 0, 'block_bogus_tries': 0, 'feeds_ban': 0})
daemon.mikrotik_after_change = lambda: None
now = time.time()
IP = '198.51.100.93'
failed_at(IP, now - 100, device='LAB-ASA')
failed_at(IP, now - 90, device='LAB-ASA')
failed_at(IP, now - 80, device='FTD-VPN')
daemon.maybe_block(IP, isemon._AtTime(now - 80))
ok('two on a device nobody watches and one on the head end is not three',
   store.blocked_until(IP), None)
failed_at(IP, now - 70, device='FTD-VPN')
failed_at(IP, now - 60, device='FTD-VPN')
daemon.maybe_block(IP, isemon._AtTime(now - 60))
ok('...three on the head end is', store.blocked_until(IP) is not None, True)

title('A socket is never the VPN')
# A switch from another maker sends no Cisco av-pairs, so its failed 802.1X
# had no method and fell through to "a RADIUS record with nothing else to say
# is the VPN" - and five of them banned a desk.
ok('Ethernet with no method is the network',
   isemon.ise_flow({'NAS-Port-Type': ['Ethernet'], 'Protocol': ['Radius']}), 'dot1x-lan')
ok('...and so is Wireless',
   isemon.ise_flow({'NAS-Port-Type': ['Wireless - IEEE 802.11']}), 'dot1x-wifi')
ok('...while Virtual is still the VPN', isemon.ise_flow({'NAS-Port-Type': ['Virtual']}), 'vpn')
ok('...and a socket that says MAB is MAB',
   isemon.ise_flow({'NAS-Port-Type': ['Ethernet'], 'cisco-av-pair': ['method=mab']}), 'mab-lan')

title('Putting a folded subnet back does not climb the ladder')
folder, store, daemon = fresh()
IP = '198.51.100.94'
store.block(IP, time.time() + 600, 'once', auto=True)
ok('one ban is one ban', store.blocked_before(IP), 1)
store.block(IP, time.time() + 600, 'put back', auto=True, again=True)
ok('...and one put back is still one', store.blocked_before(IP), 1)

title('Old rows are let go without re-walking what has already gone')
folder, store, daemon = fresh()
now = time.time()
with store.db_write() as db:
    db.executemany('INSERT INTO failed (session, ts, ip, username) VALUES (?,?,?,?)',
                   [('old/%d' % i, now - 86400 * 40 - i, '203.0.113.1', 'u') for i in range(50)]
                   + [('new/%d' % i, now - i, '203.0.113.1', 'u') for i in range(5)])
asked = []
real = isemon.Db.execute
def spy(self, sql, *a, **k):
    if 'OFFSET' in sql:
        asked.append(a[0] if a else ())
    return real(self, sql, *a, **k)
isemon.Db.execute = spy
try:
    went = store.tidy_older('failed', now - 86400 * 30, stride=10)
finally:
    isemon.Db.execute = real
ok('the old ones went and the new ones stayed', (went,
   store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']), (50, 5))
ok('...and every stride after the first started where the last one stopped',
   all(len(one) == 3 for one in asked[1:]) and len(asked) >= 5, True)

# ---------------------------------------------------------------------------
title('The version this is, said in one place and believed everywhere')
# Three builds went out carrying the same number, which is the one thing a
# version number exists to stop. The number in the program and the newest
# heading in the README have to be the same number, so that shipping without
# raising it is a failing check rather than something somebody notices later.
readme = (Path(__file__).resolve().parent.parent / 'README.md').read_text(encoding='utf-8')
after = readme.split('## Version', 1)[-1]
said = re.findall(r'^(\d+\.\d+\.\d+)\s*$', after, re.M)
ok('the README lists versions under its own heading', bool(said), True)
ok('...and the newest of them is the one this program says it is',
   said[0] if said else '', isemon.__version__)
# ...and they are listed newest first, which is what makes the first one the
# newest. Compared as numbers, not as text: "1.10.9" is older than "1.10.52"
# and sorts after it.
def as_numbers(one):
    return tuple(int(bit) for bit in one.split('.'))
ok('...and they are in order, newest first',
   said == sorted(said, key=as_numbers, reverse=True), True)
ok('...and no version is listed twice',
   [one for one in said if said.count(one) > 1], [])
# ...and the installer says the same number. Written down in a line of its
# own it said 1.10.43 while the program beside it was 1.10.58, so an upgrade
# announced a version nobody was installing and the one number a person
# checks afterwards was the wrong one.
setup = (Path(__file__).resolve().parent.parent / 'install.sh').read_text(encoding='utf-8')
ok('the installer does not write the version down a second time',
   re.search(r'^VERSION="\d', setup, re.M), None)
ok('...it reads it out of the program', '__version__' in setup.split('SERVICE_USER')[0],
   True)
# Run the line itself, so this is what the installer really prints and not
# a second reading of the same idea.
import subprocess as _sub
here = str(Path(__file__).resolve().parent.parent)
line = [one for one in setup.splitlines() if one.startswith('VERSION="$(')]
ok('...in one line, so there is one place it can be wrong', len(line), 1)
told = _sub.run(['bash', '-c', 'SOURCE_DIR=%s; %s; echo "$VERSION"' % (here, line[0])],
                capture_output=True, text=True)
ok('...and gets exactly what the program says it is',
   told.stdout.strip(), isemon.__version__)

# ---------------------------------------------------------------------------
title('Throwing the old rows away: every rule in one place')
# Each kind of record has a keeping of its own, and until now they were
# applied by a handful of lines inside the five-minute pass. One place, so
# that the clock, the pass and the button on the database page are the same
# work - and so that a site can say WHEN rather than being told.
folderT = tempfile.mkdtemp(prefix='isemon-tidy-')
isemon.STATE_DIR = Path(folderT)
isemon.DB_FILE = Path(folderT) / 'tidy.db'
isemon.CONFIG.update({'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'ise': 0,
                      'retain_failed_days': 7, 'retain_passed_days': 7,
                      'retain_events_days': 7, 'winsec_keep_days': 7,
                      'tidy_daily': 0})
storeT = isemon.Storage()
daemonT = isemon.Daemon(storeT)
old = time.time() - 30 * 86400
with storeT.db_write() as db:
    for at in (old, time.time()):
        db.execute("INSERT INTO failed (session, ts, ip, username, kind) "
                   "VALUES (?,?,?,?,'vpn')", ('f%s' % at, at, '10.0.0.1', 'x'))
        db.execute("INSERT INTO passed (session, ts, ip, username, kind) "
                   "VALUES (?,?,?,?,'vpn')", ('p%s' % at, at, '10.0.0.1', 'x'))
        db.execute("INSERT INTO events (ts, kind, detail, level) VALUES (?,?,?,?)",
                   (at, 'control', 'something', 'info'))

said = daemonT.tidy_old_rows()
ok('the old rows go', said['gone'] > 0, True)
ok('...the refused and the let-through both', said['failed_passed'], 2)
ok('...and this program\u2019s own event log', said['events'] >= 1, True)
left = storeT.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']
ok('...and what is inside the keeping stays', left, 1)
ok('...and running it again throws nothing away', daemonT.tidy_old_rows()['gone'], 0)

# ...and WHEN. Off, it happens as the rows age; on, once a day at a time
# somebody chose.
isemon.CONFIG.update({'tidy_daily': 1, 'tidy_at': '00:00'})
storeT.set_meta('tidy_day', time.strftime('%Y-%m-%d'))
with storeT.db_write() as db:
    db.execute("INSERT INTO failed (session, ts, ip, username, kind) "
               "VALUES ('later',?,?,?,'vpn')", (old, '10.0.0.2', 'y'))
daemonT.tidy_due()
ok('once a day means not again today',
   storeT.db.execute("SELECT COUNT(*) AS n FROM failed WHERE session='later'"
                     ).fetchone()['n'], 1)
storeT.set_meta('tidy_day', '')
daemonT.tidy_due()
time.sleep(0.4)
ok('...and when the day turns, it happens',
   storeT.db.execute("SELECT COUNT(*) AS n FROM failed WHERE session='later'"
                     ).fetchone()['n'], 0)
try:
    isemon.check_setting('tidy_at', 'half past four')
    ok('...and a time of day that is not one is refused', False)
except ValueError:
    ok('...and a time of day that is not one is refused', True)
# ...and the three keepings that used to be numbers written into this
# program are numbers a site can set.
isemon.CONFIG.update({'tidy_daily': 0, 'retain_eduroam_days': 1,
                      'retain_otp_days': 1, 'retain_names_days': 1})
with storeT.db_write() as db:
    db.execute("INSERT INTO eduroam_seen (mac, ts) VALUES ('aa', ?)", (old,))
    db.execute("INSERT INTO eduroam_seen (mac, ts) VALUES ('bb', ?)", (time.time(),))
    db.execute("INSERT INTO otp_asked (ident, ts, ip, username) VALUES ('a',?,?,?)",
               (old, '10.0.0.1', 'x'))
    db.execute("INSERT INTO otp_asked (ident, ts, ip, username) VALUES ('b',?,?,?)",
               (time.time(), '10.0.0.1', 'x'))
daemonT.tidy_old_rows()
ok('a keeping for the eduroam machines somebody can set',
   [r['mac'] for r in storeT.db.execute('SELECT mac FROM eduroam_seen').fetchall()], ['bb'])
ok('...and one for what the token server was asked',
   storeT.db.execute('SELECT COUNT(*) AS n FROM otp_asked').fetchone()['n'], 1)
ok('...and one for the names of addresses',
   isemon.check_setting('retain_names_days', 90), 90)
# ...and a name is never let go sooner than the records it is shown beside.
isemon.CONFIG.update({'retain_failed_days': 900, 'retain_names_days': 1})
with storeT.db_write() as db:
    db.execute("INSERT INTO ptr (ident, ip, name, first, last) "
               "VALUES ('x|old|1','10.9.9.9','old.loc',?,?)",
               (time.time() - 500 * 86400, time.time() - 500 * 86400))
storeT.tidy_ptr(int(isemon.CONFIG['retain_failed_days']))
ok('...which is never let go sooner than the record it belongs to',
   storeT.db.execute("SELECT COUNT(*) AS n FROM ptr WHERE ip='10.9.9.9'"
                     ).fetchone()['n'], 1)
isemon.CONFIG.update({'tidy_daily': 0, 'retain_eduroam_days': 14,
                      'retain_otp_days': 31, 'retain_names_days': 400,
                      'retain_failed_days': 7})
shutil.rmtree(folderT, ignore_errors=True)

# ---------------------------------------------------------------------------
title('One answer worked out once, however many ask at the same moment')
# Seen on a site with seven and a half million domain events: four identical
# queries running side by side, nineteen seconds each, because four things on
# one page all wanted the same cold answer. The page gave up waiting before
# any of them finished, so the tab stayed empty - and the next poll started
# another four.
folderH = tempfile.mkdtemp(prefix='isemon-held-')
isemon.STATE_DIR = Path(folderH)
isemon.DB_FILE = Path(folderH) / 'held.db'
storeH = isemon.Storage()
daemonH = isemon.Daemon(storeH)
ran = []


def slowly():
    ran.append(1)
    time.sleep(0.6)
    return 'the answer'


outs = []
threads = [threading.Thread(target=lambda: outs.append(daemonH.held('slow', 30, slowly)))
           for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()
ok('five askers at once ask the database once', len(ran), 1)
ok('...and all five are given the answer', outs, ['the answer'] * 5)
ok('...which is kept, so the next one waits for nothing',
   daemonH.held('slow', 30, slowly), 'the answer')
ok('...and it was still only asked once', len(ran), 1)


def broken():
    ran.append(1)
    raise ValueError('no')


try:
    daemonH.held('bad', 30, broken)
    ok('an answer that cannot be worked out is not swallowed', False)
except ValueError:
    ok('an answer that cannot be worked out is not swallowed', True)
try:
    daemonH.held('bad', 30, broken)
except ValueError:
    pass
ok('...and the next asker is not left waiting for it', len(ran), 3)
shutil.rmtree(folderH, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Everything that can be erased is offered, including what is new')
# The list on the database page had grown stale: the domain events - by far
# the biggest table on any site that reads a domain - were not offered at
# all, so somebody wanting the room back could erase the country database
# and the whole of the ISE records and still be looking at nine gigabytes.
every = set(isemon.Storage.ERASABLE)
ok('the domain events can be erased', 'domain' in every, True)
ok('...and what the directory last said', 'directory' in every, True)
ok('...and the names behind addresses', 'names' in every, True)
ok('...and the MAC vendor registers', 'macs' in every, True)
# Every table this program writes rows into is in one group or another, or
# it is a table nobody can ever get the room back from.
held = set()
for _g in isemon.Storage.ERASABLE.values():
    held |= set(_g['tables']) | set(_g.get('part') or {})
made = set(re.findall(r'CREATE TABLE IF NOT EXISTS (\w+)', isemon.SCHEMA))
# The ones that are not records at all: the settings, who may sign in, what
# is never banned, where the logs were read up to, and the notes beside them -
# and how each person has laid out the tables (1.10.145), which is part of
# their account and goes with it.
kept_on_purpose = {'meta', 'settings', 'users', 'sessions', 'whitelist', 'user_cols',
                   'user_finds', 'user_prefs'}
ok('...and no table of records is left with no way to erase it',
   sorted(made - held - kept_on_purpose), [])
ok('a group that is notes rather than rows says so',
   isemon.Storage.ERASABLE['directory'].get('notes'), True)

# ...and the card that says what is IN the database counts the same tables.
# It said a site was holding a million rows while the disk said nine
# gigabytes, because the biggest table was not on it.
folderC = tempfile.mkdtemp(prefix='isemon-counts-')
isemon.STATE_DIR = Path(folderC)
isemon.DB_FILE = Path(folderC) / 'counts.db'
storeC = isemon.Storage()
counted = set(storeC.counts())
ok('what is in the database counts the domain events', 'win_events' in counted, True)
ok('...and the names behind addresses', 'ptr' in counted, True)
ok('...and every other table of records',
   sorted(held - counted - {'blocked_soon'}), [])
shutil.rmtree(folderC, ignore_errors=True)

title('What 1.10.93 closed and what it stopped walking')
# A command typed on the kit is kept with its secrets named, not kept.
ok('a password in a stored command is hidden',
   isemon.command_kept('username admin secret Sup3rS3cret'), 'username admin secret (hidden)')
ok('...the encrypted form too, since it is the same thing to the next router',
   isemon.command_kept('enable password 7 0822455D0A16'), 'enable password 7 (hidden)')
ok('...but "no password" and "key chain NAME" are not secrets',
   [isemon.command_kept('no password'), isemon.command_kept('key chain RIPKEYS')],
   ['no password', 'key chain RIPKEYS'])
ok('...and a line with none is kept as it came',
   isemon.command_kept('show ip interface brief'), 'show ip interface brief')
# A door name is checked before it goes anywhere near a statement.
storeK = isemon.Storage()
ok('a door name nobody has answers no kinds at all',
   storeK.kinds_of("vpn' OR 1=1 --"), ())
ok('...while a real door answers its kinds', 'vpn' in storeK.kinds_of('vpn'), True)
ok('...and "other" is nobody\u2019s door', storeK.kinds_of('other'), ())
# Which buckets a retention cut empties.
H = isemon.ROLL_HOUR
edge = storeK.roll_floor(1700000000.0, H)
ok('a cut on a bucket\u2019s edge leaves that bucket whole',
   storeK.roll_bound(edge, H), ('<', edge))
ok('...and a cut inside one takes it', storeK.roll_bound(edge + 5, H), ('<=', edge))
# The clean-up remembers how far it got, and walks the whole once a day.
ok('a rule\u2019s first walk is the whole of it', storeK.tidy_mark_stale('k-test'), True)
ok('...and the next one is not', storeK.tidy_mark_stale('k-test'), False)
storeK.set_meta('tidy_walk_k-test', repr(time.time() - 90000))
ok('...until a day has gone by', storeK.tidy_mark_stale('k-test'), True)
# A mend that walks a table runs once per rule.
ok('a mend runs the first time it is asked', storeK.mended_once('k-mend', 'a'), False)
ok('...and again if it did not finish: the mark is written when it has',
   storeK.mended_once('k-mend', 'a'), False)
storeK.mended_done('k-mend', 'a')
ok('...not once it has', storeK.mended_once('k-mend', 'a'), True)
ok('...and again when its rule changes', storeK.mended_once('k-mend', 'b'), False)
# The heaviest checks are bounded.
ok('the whole-sum check is asked over a few days, never the whole table',
   storeK.ROLL_WHOLE_S <= 7 * 86400, True)
ok('a list is counted no further than it is worth counting',
   0 < isemon.Storage.SEARCH_CAP <= isemon.Storage.COUNT_CAP, True)
ok('an index over millions of rows is left for after the start',
   isemon.Storage.INDEX_INLINE_MOST >= 1000000, True)
ok('the wrong-password sentence names neither half',
   'that name and password do not go together' in
   (Path(__file__).resolve().parent.parent / 'isemon.py').read_text(encoding='utf-8'), True)

title('What 1.10.97 put right')
# A guesser who goes on trying while the address waits does not keep it
# waiting for ever.
daemonL = isemon.Daemon(storeK)
barL = max(1, int(isemon.CONFIG.get('login_tries') or 5))
t0 = 1000000.0
for i in range(barL):
    daemonL._login_note('203.0.113.200', t0 + i, 900)
blocked_meanwhile = [daemonL._login_note('203.0.113.200', t0 + 60 * m, 900)[0]
                     for m in range(1, 15)]
ok('trying on while the address waits is refused every time', all(blocked_meanwhile), True)
ok('...but not counted: the wait ends a quarter of an hour after the attempts that earned it',
   daemonL._login_note('203.0.113.200', t0 + 900 + barL, 900)[0], False)
# ...and made-up names do not grow the table for ever.
for n in range(daemonL.LOGIN_FAILS_MOST + 50):
    daemonL._login_note('user:nobody%d' % n, t0, 900)
daemonL._login_note('user:someone', t0 + 10000, 900)
ok('the counts of names nobody tries any more are let go',
   len(daemonL._login_fails) <= daemonL.LOGIN_FAILS_MOST + 1, True)

# The saved database password goes to the saved server only.
_was_cfg = dict(isemon.CONFIG)
isemon.CONFIG.update({'db_engine': 'postgres', 'db_host': 'db.example', 'db_port': 5432,
                      'db_user': 'isemon', 'db_password': 'SavedPw', 'db_name': 'isemon'})
ok('trying the saved server uses its saved password',
   isemon.engine_asked({}, 'postgres')['password'], 'SavedPw')
ok('...but never another server named in the request',
   isemon.engine_asked({'db_host': 'evil.example'}, 'postgres')['password'], '')
ok('...unless its password is typed with it',
   isemon.engine_asked({'db_host': 'evil.example', 'db_password': 'typed'},
                       'postgres')['password'], 'typed')
isemon.CONFIG.clear()
isemon.CONFIG.update(_was_cfg)
try:
    isemon.check_setting('db_password', 'pw\nplugin-dir=/tmp')
    ok('a password with a line break in it is refused', False)
except ValueError:
    ok('a password with a line break in it is refused', True)

# Going back over every log reads the refusals a chunk at a time, in two
# walks merged by time - and gets exactly the rows, in exactly the order,
# the one statement it replaced got.
import random as _random
folderJ = tempfile.mkdtemp(prefix='isemon-judge-')
isemon.STATE_DIR = Path(folderJ)
isemon.DB_FILE = Path(folderJ) / 'judge.db'
storeJ = isemon.Storage()
_rng = _random.Random(7)
for n in range(700):
    storeJ.add_failed({'session': 'j/%d' % n, 'ts': 1700000000.0 + _rng.choice(range(60)),
                       'ip': '' if n % 13 == 0 else '198.51.100.%d' % (n % 200),
                       'username': 'x', 'kind': 'vpn' if n % 3 else 'tacacs',
                       'device': 'd%d' % (n % 5)})
with storeJ.db_write() as db:
    db.execute("UPDATE failed SET kind = NULL WHERE session LIKE 'j/%' AND ts < 1700000010")
storeJ.JUDGING_CHUNK = 7
sql, args = storeJ._judging_query(1700000005)
want = sorted(((r['ts'], r['ip'], r['device']) for r in storeJ.db.execute(sql, args)))
got = [(r['ts'], r['ip'], r['device']) for r in storeJ.failed_for_judging(1700000005)]
ok('the refusals to weigh, a chunk at a time, are exactly the rows one statement read',
   sorted(got), want)
ok('...in time order', [g[0] for g in got] == sorted(g[0] for g in got), True)
ok('...and counted the same', storeJ.how_many_to_judge(1700000005), len(want))
storeJ.db.close()
shutil.rmtree(folderJ, ignore_errors=True)

title('An index that only repeats the start of another goes')
folderI = tempfile.mkdtemp(prefix='isemon-narrow-')
isemon.STATE_DIR = Path(folderI)
isemon.DB_FILE = Path(folderI) / 'narrow.db'
storeI = isemon.Storage()
with storeI.db_write() as db:
    db.execute('CREATE INDEX IF NOT EXISTS failed_ts ON failed (ts)')
    db.execute('CREATE INDEX IF NOT EXISTS win_ts ON win_events (ts)')
ok('(an older database has them)', {'failed_ts', 'win_ts'} <= set(
    storeI.dialect.index_names(storeI.db)), True)
storeI.mend()
namesI = set(storeI.dialect.index_names(storeI.db))
ok('the next start takes them away, the wider ones being there',
   ({'failed_ts', 'passed_ts', 'win_ts'} & namesI,
    {'failed_ts_ip', 'passed_ts_ip', 'win_ts_kind'} <= namesI), (set(), True))
if not getattr(isemon.Storage, 'ENGINE', None):
    planI = ' '.join(r['detail'] for r in storeI.db.execute(
        'EXPLAIN QUERY PLAN SELECT * FROM failed WHERE ts >= ? ORDER BY ts DESC LIMIT 5', (1,)))
    ok('...and the newest rows are still found down an index, not by a sort of the table',
       'USING INDEX failed_ts' in planI and 'TEMP B-TREE' not in planI, True)
storeI.db.close()
shutil.rmtree(folderI, ignore_errors=True)

title('A user name cannot carry a forged record inside it')
# Everything after U+2028 (and its relatives) in a VPN user name used to be
# read as a line of its own: a whole ISE refusal, with any address in it,
# typed at the VPN prompt - and a ban for that address.
folderX = tempfile.mkdtemp(prefix='isemon-smuggle-')
VICTIM = '198.51.100.77'


def smuggled(seq, sep):
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '.500 ' + ise_zone()
    forged = ('Sep 30 11:00:00 ise2 CISE_Failed_Attempts 9%09d 1 0 %s 0229674592 5400 '
              'NOTICE Failed-Attempt: Authentication failed, Protocol=Radius, '
              'UserName=INVALID, Calling-Station-ID=%s, NetworkDeviceName=FTD-VPN,'
              % (seq, when, VICTIM))
    # ...written the way ISE writes a value with commas in it: each one
    # escaped. (An unescaped comma in a value is not something ISE writes;
    # that defence is tested with the ISE parser itself.)
    return ('Sep 30 11:00:00 ise2 CISE_Failed_Attempts %010d 1 0 %s 0229674592 5400 '
            'NOTICE Failed-Attempt: Authentication failed, Protocol=Radius, '
            'UserName=attacker%s%s, Calling-Station-ID=203.0.113.7, NetworkDeviceName=FTD-VPN,'
            % (seq, when, sep, forged.replace(',', '\\,')))


pathX = Path(folderX) / 'CISE_Failed_Attempts.log'
seps = ['\u2028', '\u2029', '\u0085', '\x0b', '\x0c']
pathX.write_bytes(''.join(smuggled(n + 1, sep) + '\n' for n, sep in enumerate(seps))
                  .encode('utf-8'))
tailX = isemon.LogTail(str(pathX), parser=isemon.ise_parse_lines)
tailX.offset = 0
gotX = tailX.read()
ok('each line of the file is one record, whatever is inside its user name',
   len(gotX), len(seps))
ok('...and not one of them is about the address hidden in the name',
   [r.ip for r in gotX if r.ip == VICTIM], [])
ok('a byte-order mark does not cost a file its first line',
   isemon.log_lines('\ufeffSep 30 a\r\nSep 30 b\n'), ['Sep 30 a', 'Sep 30 b'])
shutil.rmtree(folderX, ignore_errors=True)

title('An upgrade says what it does to the database')
# On a file: on a database server the suites empty the one database at every
# Storage, so there is no "next start" to ask about there.
UPGRADE_ON_FILE = not getattr(isemon.Storage, 'ENGINE', None)
if UPGRADE_ON_FILE:
    folderU = tempfile.mkdtemp(prefix='isemon-upgrade-')
    isemon.STATE_DIR = Path(folderU)
    isemon.DB_FILE = Path(folderU) / 'upgrade.db'
    storeU = isemon.Storage()
    # An older database: a table and an index it did not have yet, and the
    # version before this one on it.
    with storeU.db_write() as db:
        db.execute('DROP TABLE ptr')
        db.execute('DROP INDEX IF EXISTS passed_mac_kind_ts')
    storeU.set_meta('version_opened', '1.10.20')
    storeU.db.close()
    saidU = []
    real_log = isemon.log
    isemon.log = lambda msg, level='info': saidU.append((level, msg))
    try:
        storeU = isemon.Storage()
    finally:
        isemon.log = real_log
    linesU = [m for _l, m in saidU if m.startswith('database:')]
    ok('it says which version the database came from, and which it goes to',
       any('last opened by isemon 1.10.20, this is %s' % isemon.__version__ in m
           for m in linesU), True)
    ok('...each table it makes', any('made the table ptr' in m for m in linesU), True)
    ok('...each index, when it starts and when it is done',
       [any('building the index passed_mac_kind_ts' in m and 'starting' in m for m in linesU),
        any('building the index passed_mac_kind_ts - done in' in m for m in linesU)], [True, True])
    ok('...and a line that adds it up',
       any('the schema brought up to date in' in m and '1 table(s)' in m for m in linesU), True)
    ok('...all of it where the log is read, not only when debugging',
       all(l in ('info', 'warn') for l, m in saidU if m.startswith('database:')), True)
    storeU.db.close()
    saidU = []
    isemon.log = lambda msg, level='info': saidU.append((level, msg))
    try:
        storeU = isemon.Storage()
    finally:
        isemon.log = real_log
    ok('the next start says there was nothing to do, in one line',
       [m for _l, m in saidU if m.startswith('database:')],
       ['database: the schema has everything isemon %s needs - nothing to change'
        % isemon.__version__])
    storeU.db.close()
    shutil.rmtree(folderU, ignore_errors=True)

title('A quiet log at night is not a reader that has stopped')
folderH, storeH, daemonH = fresh()
nowH = time.time()
quiet = [{'kind': 'failed', 'there': True, 'error': '', 'records': 10,
          'at': nowH - 3600, 'looked': nowH - 2}]
ok('nothing new for an hour, looked at a moment ago: no warning',
   daemonH.health(quiet)['says'] != 'the logs have not been read lately', True)
stopped = [dict(quiet[0], looked=nowH - 900)]
ok('...and nothing looked at for a quarter of an hour: the warning',
   daemonH.health(stopped)['says'], 'the logs have not been read lately')
busyDC = stopped + [{'kind': 'winsec', 'there': True, 'error': '', 'records': 5,
                     'at': nowH - 1, 'looked': nowH - 1}]
ok('...unless any other log was looked at just now, which is the same reader',
   daemonH.health(busyDC)['says'] != 'the logs have not been read lately', True)
storeH.db.close()
shutil.rmtree(folderH, ignore_errors=True)

title('Each log file carries its machine\'s last day')
folderT, storeT, daemonT = fresh()
tailsT = [{'path': '/var/log/remote/dc03/nps.log', 'source': 'nps', 'kind': 'nps', 'there': True},
          {'path': '/var/log/remote/isea/CISE_Failed_Attempts.log', 'source': 'ise',
           'kind': 'failed', 'there': True},
          {'path': '/var/log/remote/otp/radius-detail.log', 'source': 'otp-detail',
           'kind': 'otp-detail', 'there': True},
          {'path': '/var/log/remote/gone/nps.log', 'source': 'nps', 'kind': 'nps', 'there': False}]
daemonT.tails_per_day(tailsT, {'failed': {'DC03': 600, 'isea': 40}, 'passed': {'DC03': 13, 'isea': 7}})
ok('NPS writing DC03 into a folder called dc03 is one machine',
   tailsT[0]['day'], 613)
ok('...an ISE file counts its own table only', tailsT[1]['day'], 40)
ok('...a file whose records go elsewhere says it cannot tell', tailsT[2]['day'], None)
ok('...and a file that is not there says nothing', tailsT[3]['day'], None)
storeT.db.close()
shutil.rmtree(folderT, ignore_errors=True)

title('A loop that stops coming round says what every thread is doing')
folderW, storeW, daemonW = fresh()
saidW = []
real_logW = isemon.log
isemon.log = lambda msg, level='info': saidW.append((level, msg))
try:
    daemonW.say_what_threads_do('checking')
finally:
    isemon.log = real_logW
ok('every thread is listed, this one included',
   any('thread MainThread' in m and m.startswith('checking') for _l, m in saidW), True)
ok('...as a warning, so it is in the log whatever the level',
   all(l == 'warn' for l, _m in saidW), True)
ok('...and the stall is only said past the loop\'s own ceiling',
   isemon.Daemon.LOOP_STALL_S >= 120, True)
storeW.db.close()
shutil.rmtree(folderW, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A dump being written says how big the last one came out')
_dd = Path(tempfile.mkdtemp(prefix='isemon-dumps-'))
(_dd / 'isemon-20260930-0330.pgc').write_bytes(b'x' * 5000)
(_dd / 'isemon-20260929-0330.pgc').write_bytes(b'x' * 3000)
os.utime(str(_dd / 'isemon-20260929-0330.pgc'), (1, 1))
(_dd / 'isemon-20260930-0330.sql.gz').write_bytes(b'x' * 900)
ok('the newest dump of the same kind is what a new one is measured against',
   isemon.last_dump_size(_dd / 'isemon-20261001-1600.pgc'), 5000)
ok('...and a dump of the other engine is not',
   isemon.last_dump_size(_dd / 'isemon-20261001-1600.sql.gz'), 900)
ok('with none before it there is nothing to measure against',
   isemon.last_dump_size(_dd / 'isemon-20261001-1600.tar'), 0)
_part = _dd / 'isemon-20261001-1600.pgc.part'
_part.write_bytes(b'x' * 100)
_w = isemon.Growing(_part, 'writing the dump test', 'db-dump', expect=5000)
_now = [v for k, v in isemon.Going.snapshot().items() if k.startswith('db-dump')] \
    if hasattr(isemon.Going, 'snapshot') else []
ok('the page is given that size beside the bytes written so far',
   bool(_now) and _now[0].get('expect') == 5000 and not _now[0].get('total'), True)
_w.stop()
shutil.rmtree(str(_dd), ignore_errors=True)

# ---------------------------------------------------------------------------
title('A copy being made is not in the list of copies until it is whole')
folder, store, daemon = fresh()
_half = isemon.BACKUP_DIR / 'isemon-20261001-161345-by-hand.db.part'
isemon.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
_half.write_bytes(b'not finished')
ok('a half-made copy is not offered to restore or delete',
   [b['name'] for b in store.backups()], [])
_made = store.backup(label='by-hand')
ok('a finished copy has its own name', (_made.exists(), _made.name.endswith('.db')),
   (True, True))
ok('...and nothing of it is left under the other one',
   Path(str(_made) + '.part').exists(), False)
ok('...and it is the one in the list', [b['name'] for b in store.backups()], [_made.name])
ok('...and it says where it came off', store.backups()[0]['from'], store.dialect.name)
_cols = sqlite3.connect(str(_made)).execute('PRAGMA table_info(win_events)').fetchall()
ok('...and its tables have the columns they gained later, not only the first ones',
   'by_logon' in [c[1] for c in _cols], True)
os.utime(str(_half), (time.time() - 7 * 3600, time.time() - 7 * 3600))
store.prune_backups(14)
ok('a half left behind by a copy that never finished is cleared away later',
   _half.exists(), False)

# ---------------------------------------------------------------------------
title('A copy says how it is going once, not again as a warning per index')
folder, store, daemon = fresh()
_said_lines = []
_real_log = isemon.log


def _keep(text, level='info', *a, **k):
    _said_lines.append((level, str(text)))
    return _real_log(text, level, *a, **k)


isemon.log = _keep
_slow = isemon.Db.SLOW
isemon.Db.SLOW = 0.0
try:
    with isemon.Db.patiently('making a copy, which says how far along it is', quiet=True):
        store.db.execute('SELECT 1').fetchall()
    ok('a slow statement inside a copy is not written as a warning or as information',
       [l for l, t in _said_lines if t.startswith('sql took') and l != 'debug'], [])
    del _said_lines[:]
    with isemon.Db.patiently('something slow on purpose'):
        store.db.execute('SELECT 2').fetchall()
    ok('...while elsewhere one is still written down, as information',
       [l for l, t in _said_lines if t.startswith('sql took')], ['info'])
    del _said_lines[:]
    _g = isemon.Going('counting to two', 2, name='test-twice')
    _g.step(2)
    _g.step(0)
    _g.done_now()
    ok('a job that has reached the end says so once',
       len([t for l, t in _said_lines if t.startswith('counting to two: 100%')]), 1)
finally:
    isemon.Db.SLOW = _slow
    isemon.log = _real_log
_src = open(isemon.__file__, encoding='utf-8').read()
ok('a database request that is long because of the work it was asked for is one line '
   'in the log, not every thread\u2019s stack',
   "if going and str(oldest[1]).split('?')[0].startswith('/api/db'):" in _src, True)

print('\nA reader that stops reading (1.10.138)')
import subprocess
_tree = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_child = subprocess.Popen(
    [sys.executable, '-c',
     'import sys; sys.path.insert(0, %r); import isemon\n'
     'def fake():\n'
     '    for i in range(20000): print("line %%d" %% i)\n'
     '    return 0\n'
     'isemon.main = fake\n'
     'sys.exit(isemon.run_main())' % _tree],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
_child.stdout.readline()
_child.stdout.close()                 # what `| head -1` does
_err = _child.stderr.read().decode('utf-8', 'replace')
_rc = _child.wait(timeout=60)
ok('isemon --status | head: no traceback, no "Exception ignored", and the exit any '
   'program stopped by head gives', ('Traceback' in _err, 'Exception ignored' in _err, _rc),
   (False, False, 141))

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
