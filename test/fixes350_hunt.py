#!/usr/bin/env python3
"""1.10.350: three rounds of looking for bugs.

Round 2 - logs, certificates, upgrades: a Windows address never from an
account name; FreeRADIUS's station the last one; no square-time regexes; an
authority's address never this machine, every redirect checked; a pushed
certificate not put over; root puts back nothing older than 1.10.345.

Round 1 - bans, backups, settings:
- a RouterOS login failure is the address at the end of the line, whatever
  name somebody typed;
- an IPv6 zone is no address; an IPv4 network written the IPv6 way is that
  IPv4 network;
- a "folder" backup never writes through a link; a database put back holds no
  trigger or view; one put back at a time, its sign-ins ended;
- a leading dot no longer skips the checks of Automatic certificates; a file
  imported switches on neither Face ID nor "no password", nor an odd port.

    ./test/fixes350_hunt.py
"""
import os
import sqlite3
import sys
import tempfile
import threading
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


folder = Path(tempfile.mkdtemp(prefix='isemon-350-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)

print('round 1: RouterOS sign-in lines')
m = isemon.ROS_LOGIN_FAIL.match('login failure for user x from 198.51.100.7 via y from '
                                '203.0.113.9 via ssh')
ok('the address is the one at the end', (m.group('ip'), m.group('via')), ('203.0.113.9', 'ssh'))
ok('...the rest is the name', m.group('user'), 'x from 198.51.100.7 via y')
r = isemon.ros_record_from('login failure for user x from 198.51.100.7 via y from 203.0.113.9 '
                           'via ssh') if hasattr(isemon, 'ros_record_from') else None
if r is not None:
    ok('...the record\'s address', (r or {}).get('srcip'), '203.0.113.9')
ok('a plain line as before', isemon.ROS_LOGIN_FAIL.match(
    'login failure for user admin from 203.0.113.9 via winbox').group('ip'), '203.0.113.9')
ok('logged in, the same', isemon.ROS_LOGIN.match(
    'user a from 10.9.9.9 via x logged in from 10.0.0.2 via winbox').group('ip'), '10.0.0.2')

print('round 1: addresses')
ok('an IPv6 zone is no public address', isemon.is_public_address('2a00::1%x\n0.0.0.0'), False)
ok('...nor a pf entry', isemon.pf_entry('2a00::1%eth0'), '')
ok('an IPv4 network written the IPv6 way', isemon.same_address('::ffff:10.0.0.0/120'),
   '10.0.0.0/24')
ok('...a plain IPv6 network as before', isemon.same_address('2a00:1:2::/48'), '2a00:1:2::/48')

print('round 1: settings')
for k, v in (('acme_dns_zone', '•x\nupdate add evil 60 A 1.2.3.4'),
             ('acme_name', '•@169.254.169.254/x#')):
    try:
        isemon.check_setting(k, v)
        ok('a leading dot checked like anything else: %s' % k, False)
    except ValueError:
        ok('a leading dot checked like anything else: %s' % k, True)
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin')
said = daemon.import_config({'_what': 'isemon configuration', 'settings': {'password_off': 1, 'passkeys': 1,
                                          'certlogin_port': 3306, 'session_hours': 9}}, by='boss')
ok('an import switches on neither "no password" nor Face ID, nor port 3306',
   (int(isemon.CONFIG.get('password_off') or 0), int(isemon.CONFIG.get('passkeys') or 0),
    int(isemon.CONFIG.get('certlogin_port'))), (0, 0, 8443))
ok('...and says so, the rest taken', ('page itself' in str(said),
                                      int(isemon.CONFIG.get('session_hours'))), (True, 9))

print('round 1: backups')
dest = folder / 'dest'
dest.mkdir()
victim = folder / 'victim'
victim.write_text('precious')
src = folder / 'src.bin'
src.write_bytes(b'backup bytes')
name = 'isemon-backup-x-y-20260101-000000.tar.gz.enc'
os.symlink(str(victim), str(dest / ('.%s.part' % name)))
rb = isemon.RbFolder.__new__(isemon.RbFolder)
rb.dir = str(dest)
try:
    rb.put(str(src), name)
except Exception as e:                                  # noqa: BLE001
    print('    (%s)' % e)
ok('a link named as the next copy is not written through', victim.read_text(), 'precious')
ok('...the copy is there', (dest / name).read_bytes(), b'backup bytes')
bad = folder / 'trig.db'
other = isemon.Storage(bad)
other.db.raw.execute('CREATE TRIGGER t AFTER INSERT ON failed BEGIN SELECT 1; END')
other.db.raw.commit()
try:
    other.db.raw.close()
except Exception:                                       # noqa: BLE001
    pass
got, why = store.looks_like_ours(bad)
ok('a copy with a trigger is not put back', (got, 'trigger' in str(why)), (None, True))
held = isemon.Storage._RESTORE_LOCK.acquire()
try:
    try:
        store.restore_dump(bad)
        ok('one restore at a time', False)
    except ValueError as e:
        ok('one restore at a time', 'already' in str(e))
    try:
        isemon.rb_not_while(daemon, 'rbackup-restore', 'x')
        ok('...and no backup to another machine meanwhile', False)
    except ValueError as e:
        ok('...and no backup to another machine meanwhile', 'from the page' in str(e))
finally:
    isemon.Storage._RESTORE_LOCK.release()
src_txt = (ROOT / 'isemon.py').read_text()
ok('the pf alias said to be isemon\'s own', "It has to be an alias of isemon\\'s own" in src_txt)

print('round 2: logs - the address is never one somebody typed')
r = isemon.win_record_from(
    'Nov 14 10:00:00 DC01 Microsoft-Windows-Security-Auditing: EventID=4776 | The computer '
    'attempted to validate the credentials for an account.  Authentication Package: '
    'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account: bob Source Network Address: '
    '203.0.113.66  Source Workstation: WS1  Error Code: 0xC000006A')
ok('Windows 4776: no address taken from the account name', getattr(r, 'ip', None), '')
m = isemon.EDU_SAID.match('Login incorrect (mschap: x): [bob] (from client vpn port 0 cli '
                          '203.0.113.66 x] (from client vpngw port 0 cli 198.51.100.9)')
ok('FreeRADIUS: the station of the last "(from client ...)"', (m.group('cli'), m.group('client')),
   ('198.51.100.9', 'vpngw'))
m = isemon.EDU_SAID.match('Login OK: [user/pass] (from client wlc9800 port 2915 cli '
                          '36-C3-21-CD-1A-94)')
ok('...a plain line as before', (m.group('who'), m.group('cli')), ('user/pass', '36-C3-21-CD-1A-94'))
import time as _t
t0 = _t.time()
isemon.ROS_LINE.match('Nov 14 10:00:00 MikroTik system,error,critical login failure for user a'
                      + ' ' * 65000 + 'b from 1.2.3.4 via ssh')
ok('a RouterOS line of 64 KB of blanks read in under a second', _t.time() - t0 < 1.0)

print('round 2: certificates')
os.environ.pop('ISEMON_CDP_LOOPBACK_OK', None)
try:
    isemon.tls_fetch('http://127.0.0.1:9/ca.crt')
    ok('an authority is not fetched from this machine itself', False)
except isemon.WebRootError as e:
    ok('an authority is not fetched from this machine itself', 'not an address' in str(e))
try:
    isemon.tls_fetch('http://no-such-name.invalid/ca.crt')
    ok('...nor from a name that does not resolve (refused before asking)', False)
except isemon.WebRootError as e:
    ok('...nor from a name that does not resolve (refused before asking)', 'resolve' in str(e))
ok('every step of a redirect checked', 'class Guarded(urllib.request.HTTPRedirectHandler)'
   in src_txt if 'src_txt' in dir() else 'class Guarded(' in (ROOT / 'isemon.py').read_text())
src2 = (ROOT / 'isemon.py').read_text()
ok('a pushed certificate is not put over by an order that ran meanwhile',
   "if how.startswith('acme push') and not acme_care(wr):" in src2)
ok('a push checks both of a pair, and none against a dashboard with no name',
   "for one in [main] + ([alt] if alt else []):" in src2 and
   'the dashboard has no name yet to check' in src2)
ok('no control character from acme\'s name', "re.sub(r'[\\x00-\\x1f\\x7f]+', ' ', str(body.get('acme_name')" in src2)

print('round 2: upgrades')
import importlib.util
spec = importlib.util.spec_from_file_location('upg350', str(ROOT / 'deploy' / 'isemon_upgrade.py'))
upg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upg)
ok('root puts back nothing older than 1.10.345', upg.SECURITY_FLOOR, '1.10.345')
ok('...nor does the daemon offer it', isemon.DOWNGRADE_SECURITY_FLOOR, (1, 10, 345))
inst = (ROOT / 'install.sh').read_text()
ok('install.sh makes config.json without following a link',
   'os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW' in inst and 'chown root:"$SERVICE_USER" "$CONFIG_FILE"'
   not in inst)
ok('the console checks a package\'s signature through root\'s helper',
   "subprocess.call(['python3', '-I', helper, '--run', path])" in src2)

print('round 3: the pages')
sys.path.insert(0, str(ROOT / 'deploy'))
import isemon_web                                    # noqa: E402
conf = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
ok('nginx hands PHP the body as it comes', 'fastcgi_request_buffering off;' in conf)
old = conf.replace('        fastcgi_request_buffering off;\n', '')
m = __import__('re').search(r'(?m)^(\s*)location\s*=\s*/index\.php\s*\{[^\n]*\n', old)
ok('...the root helper finds where an older file needs it', bool(m))
page = (ROOT / 'web' / 'index.php').read_text()
ok('before signing in, 64 KB at most', "if ($told > 65536 && (isemon_session() === '' || in_array($what, ['login', 'password'," in page)
ok('JSON nested 64 deep at most', 'json_decode($raw, true, 64)' in page)
ok('data in help panels is text', "richText(wordsIn(String(one[1])))" in page and
   "if (one.closest && one.closest('[data-no-i18n], .mono')) t = wordsIn(t);" in page)
ok('a link\'s tab is a name, nothing else', "if (!/^[a-z0-9-]{1,40}$/.test(want))" in page)

print('round 3: searches that took the daemon')
import time as _t2
t0 = _t2.time()
ok('a run of stars says no at once', isemon.fw_glob('*' * 14 + 'q').match(
    '#acsacl#-ip-permit_all_ipv4_traffic-57f6b0d3'), False)
ok('...in a moment', _t2.time() - t0 < 0.1)
for pat, text, want in (('a*b*c', 'axxbyyc', True), ('a*b*c', 'acb', False), ('*x*', 'x', True),
                        ('ab*ba', 'aba', False), ('#acsacl#-ip-*-57f6b0d3',
                                                  '#acsacl#-ip-permit_all-57f6b0d3', True)):
    ok('glob %s on %s' % (pat, text), isemon.fw_glob(pat).match(text), want)
ok('the kinds of Windows events: each once, few', 'list(dict.fromkeys(k.strip()[:40]' in (
    ROOT / 'isemon.py').read_text())

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
