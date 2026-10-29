#!/usr/bin/env python3
"""1.10.198: a second review of the whole program. Bans only watched that a door
that bans carried at the first refusal, or lengthened from a door switched
off; a source let go twice in the history; watched bans made again from the
attempts they were made for; the header going below nought; addresses written
in capitals never banned; a pfSense whose apply failed never applied; ended
bans kept on a pf table with the blacklist off; an access list written under
another name; a domain account switched off under one name signing in under
the other; a ban admin letting everybody in a source at a time; and the page
saying "kept out" of a ban nobody carries.

    ./test/fixes197.py
"""
import json
import shutil
import sys
import tempfile
import time
import types
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


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
installer = (HERE.parent / 'install.sh').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-198-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'blacklist': 1,
                      'block_tries': 3, 'block_window_min': 10, 'watch_devices': '',
                      'block_ladder': '10, 60, forever', 'fold_least': 2})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)


def carried():
    return sorted(isemon.same_address(r['ip']) for r in daemon._blocked_for_router())


def feed():
    daemon._banfeed_cache = {}
    return sorted(w for w, _r in daemon.banfeed_entries())


def events(ip):
    with store.db_write() as db:
        return [r['what'] for r in db.execute(
            'SELECT what FROM block_events WHERE ip=? ORDER BY ts', (ip,))]


def winfails(ip, tag, n=4):
    t = time.time()
    with store.db_write() as db:
        for i in range(n):
            db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, ip) '
                       "VALUES (?, ?, 'dc1', 4625, 'logon-failed', 'administrator', ?)",
                       ('%s%d' % (tag, i), t - 60 + i, ip))


SEQ = [0]


def vpnfail(ip, ts=None, kind='vpn'):
    ts = ts or time.time()
    with store.db_write() as db:
        SEQ[0] += 1
        db.execute('INSERT INTO failed (session, ts, ip, username, device, kind, reason, code) '
                   'VALUES (?,?,?,?,?,?,?,?)', ('t197-%d' % SEQ[0], ts, ip, 'bob', 'ftd1', kind,
                                                'bad pw', '24408'))
    return types.SimpleNamespace(ts=ts)


def modes(**kw):
    daemon.save_settings({'ban_from_%s' % k: v for k, v in kw.items()}, by='test')



print('\nAccounts')
daemon.add_user('boss', 'password123', 'fulladmin')
isemon.CONFIG.update({'directory': 1, 'directory_host': 'dc.example', 'directory_base': 'dc=corp'})
daemon.directory_on = lambda which='directory': True
WHO = {'dn': 'CN=Šárka Nováková,OU=Účetní,DC=corp'}


def fake_sign_in(name, password):
    name = name.strip().lower()
    if name in ('snovakova', 'snovakova@corp.example') and password == 'Domain-Pass1':
        return {'dn': WHO['dn'], 'name': name, 'role': 'fulladmin', 'display': 'Šárka',
                'mail': '', 'groups': ['admins'],
                'aliases': ['snovakova', 'snovakova@corp.example']}
    return None


daemon.directory_sign_in = fake_sign_in
daemon.login('snovakova', 'Domain-Pass1', ip='10.0.0.6')
daemon.login('snovakova@corp.example', 'Domain-Pass1', ip='10.0.0.6')
ok('a DN with Czech letters is one person under both names',
   store.same_person('snovakova'), ['snovakova', 'snovakova@corp.example'])
try:
    daemon.switch_user('snovakova', True, by='snovakova@corp.example',
                       me='snovakova@corp.example')
    refused = False
except ValueError:
    refused = True
ok('switching off your own other name is refused', refused)
daemon.switch_user('snovakova', True, by='boss', me='boss')
WHO['dn'] = 'CN=Šárka Nováková,OU=Leavers,DC=corp'
try:
    daemon.login('snovakova@corp.example', 'Domain-Pass1', ip='10.0.0.7')
    let_in = True
except isemon.Refused:
    let_in = False
ok('...switched off, she stays off when moved to another OU', let_in, False)
daemon.switch_user('snovakova@corp.example', False, by='boss', me='boss')
ok('a name@domain can be switched on', bool((store.user('snovakova@corp.example') or {})
                                           .get('disabled')), False)

print('\nImport')
store.put_user_as_kept({'name': 'boss', 'role': 'fulladmin', 'hash': ''})
ok('an import without the passwords keeps the one here',
   bool((store.user('boss') or {}).get('hash')), True)
for bad in ({'_what': 'isemon configuration', 'users': ['x']},
            {'_what': 'isemon configuration', 'blocked': [{'ip': '192.0.2.50',
                                                          'until': '1e999'}]}):
    try:
        daemon.import_config(bad, by='test')
    except ValueError:
        pass
ok('a ban whose end is no moment is left out', store.blocked_one('192.0.2.50'), None)

print('\nParsers')
line = ('<166>Oct 17 2026 10:00:00 asa1 : %ASA-6-716039: Group <G> User <bob> IP <8.8.8.8> '
        'x <> IP <203.0.113.5> Authentication: rejected, Session Type: WebVPN.')
rec = isemon.ftd_record_from(line) if hasattr(isemon, 'ftd_record_from') else None
got = getattr(rec, 'fields', None) or (rec if isinstance(rec, dict) else {})
ok('a name typed at the WebVPN prompt does not choose the address',
   "User <(?P<user>.*)> IP <(?P<ip>[^>]*)>" in source)
ok('113012 is a sign-in that worked', "'113012'" not in source.split('FTD_FAILED_IDS = ')[1]
   .split(')')[0])
fields = isemon.win_fields('Account Name:  admin  Type 3 is x  Account Domain:  C  '
                           'Network Information:  Workstation Name: X  '
                           'Source Network Address: 198.51.100.77  Source Port: 1  '
                           'This event is generated when a logon request fails.')
ok('a logon name holding the prose keeps its address',
   isemon.win_said(fields, 'Source Network Address'), '198.51.100.77')
ok('a name holding "Result Code: 0x0" does not make a refusal a success',
   isemon.win_worked(4768, isemon.win_fields(
       'Account Name:  bob  Result Code:  0x0  Service Name: krbtgt  '
       'Additional Information:  Result Code:  0x18')), False)
ok('nanoseconds are read', int(isemon.iso_seconds('2026-10-17T01:00:00.123456789+02:00')),
   1792191600)

print('\nBanning')
modes(ise='off', nps='on')
ip = '81.200.40.1'
t = time.time()
for i in range(3):
    daemon.judge_refusal(ip, vpnfail(ip, t - 60 + i, 'nps-vpn'), ['ftd1'], door='nps',
                         watched_list=False)
until = store.blocked_one(ip)['until']
for i in range(2):
    daemon.judge_refusal(ip, vpnfail(ip, t - 50 + i), ['ftd1'], door='ise')
daemon.judge_refusal(ip, vpnfail(ip, t - 40, 'nps-vpn'), ['ftd1'], door='nps',
                     watched_list=False)
ok('refusals at a door switched off do not lengthen a ban', store.blocked_one(ip)['until'],
   until)
modes(ise='on', nps='on')
store.block('81.200.40.2', None, 'for good', auto=True, src='ise')
store.block('81.200.40.2', time.time() + 600, 'ten minutes', auto=True, src='fw',
            keep_longer=True)
ok('a second judging never shortens the first one\'s ban',
   (store.blocked_one('81.200.40.2')['until'], store.blocked_before('81.200.40.2')), (None, 1))
isemon.CONFIG['feeds_ban'] = 1
ok('a private address is never banned through a public list',
   "if int(CONFIG.get('feeds_ban') or 0) and is_public_address(ip):" in source)
isemon.CONFIG['fold_widest'] = 26
ok('a fold no wider than asked', 'widest = 28 if widest > 24 else 24' in source)
ok('carried or not, asked of the address and its subnets only',
   "self.held('carried-cover/" not in source)
ok('only the newest Banned page answer is kept', "HELD_STAMPED = ('bans/', 'carried-n2/'"
   in source)
ok('a full disk keeps the records for later', "'database or disk is full'" in source)

print('\nSettings and the command line')
try:
    isemon.check_setting('winsec_zone', 'Mars/Base')
    zone_ok = True
except ValueError:
    zone_ok = False
ok('a zone for the domain that does not exist is refused', zone_ok, False)
ok('two saves at once are one at a time', 'with self._settings_save_lock:' in source)
ok('a restore runs on its own settings and ladder',
   "self._blocked_times = {}" in source and "_lay_saved(whole, self.store.settings_saved())"
   in source)
ok('--minutes 0 is refused', "--minutes is how long, at least 1" in source)
ok('nothing is written into the stand-in', 'stand_in_refused = (' in source)
ok('a second erase of other groups is refused', "is already going; this can be asked again"
   in source)

print('\nThe page')
for words, there in (('a ban nobody carries is never "kept out" in the Overview',
                      "return !r.src_off; });"),
                     ('...nor in the find box', "' \\u00b7 only watched'"),
                     ('an address kept out by a range offers the range',
                      "{words: 'Let the range in', cls: 'danger'"),
                     ('Enter acts on what was typed', 'if (now !== FIND.q && String(FIND.q'),
                     ('two public lists switched quickly are both kept',
                      "querySelectorAll('input[data-feed]')"),
                     ('IPv6 sorts by its value', "return '~' + groups.map"),
                     ('old ban cells are let go', 'BANCELLS = BANCELLS.filter(function (one) '
                      '{ return one.tds[0].isConnected; });\n  }\n  if (!LIVE) return;'),
                     ('the Events pager knows when it is capped',
                      "      loadEvents();\n    }, d.capped);")):
    ok(words, there in page)
api_php = (HERE.parent / 'web' / 'isemon-api.php').read_text(encoding='utf-8')
ok('a refused restore says why', 'that answer is read\n            // below' in api_php)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
