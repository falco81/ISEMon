#!/usr/bin/env python3
"""1.10.227: what a search for faults found.

The token server's packets read twice are not written twice, an id is not
somebody else's packet, a code typed is not a code never typed; root's two
helpers - an upgrade that hangs is stopped, one that was killed does not
block every one after it, a package that says it is huge is refused before
it is unpacked, a new DH group reaches nginx, a firewall that cannot be done
is refused before nginx is touched; a ban-list key that is not UTF-8; the
php2shell notice reading PHP as a whole; and the suite no longer depends on
the day it is run.

    ./test/fixes227.py
"""
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
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


def title(text):
    print('\n' + text)


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


def load(name):
    spec = importlib.util.spec_from_file_location(name, str(ROOT / 'deploy' / (name + '.py')))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


work = Path(tempfile.mkdtemp(prefix='isemon-227-'))
NOW = datetime(2026, 10, 24, 14, 0, 0).timestamp()


def fresh():
    folder = Path(tempfile.mkdtemp(prefix='db-', dir=str(work)))
    isemon.STATE_DIR = folder
    isemon.DB_FILE = folder / 'd.db'
    isemon.BACKUP_DIR = folder / 'b'
    isemon._LOG_PATH = folder / 'd.log'
    isemon.CONFIG_FILE = folder / 'config.json'
    (folder / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'otp': 1, 'otp_detail': 1, 'geo': 0, 'api_port': 0})
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    db = sqlite3.connect(str(isemon.DB_FILE))
    db.row_factory = sqlite3.Row
    return store, daemon, db


def det(lines, daemon):
    for rec in isemon.otp_detail_lines(lines, now=NOW):
        daemon.take_record('otp-detail', rec)


def tok(lines, daemon):
    for rec in isemon.otp_parse_lines(lines, now=NOW):
        daemon.take_record('otp', rec)


def asked(db):
    return [tuple(r) for r in db.execute(
        'SELECT ident, username, verdict FROM otp_asked ORDER BY ts, ident')]


def ask(t, port, user, ip, srv='otp1', ident=''):
    return ('Oct 24 %s %s radius-detail[1]: nas=192.0.2.32 %sfile=auth-detail-x '
            'ts=[Sat Oct 24 %s 2026] Packet-Type = Access-Request, '
            'Packet-Src-IP-Address = 192.0.2.32, Packet-Src-IP-Port = %d, User-Name = "%s", '
            'Calling-Station-Id = "%s", Totp-Request-Id = "192.0.2.32:%d"'
            % (t, srv, ('id=%s ' % ident) if ident else '', t, port, user, ip, port))


def ans(t, port, verdict, srv='otp1', ident='', more=''):
    return ('Oct 24 %s %s radius-detail[1]: nas=192.0.2.32 %sfile=reply-detail-x '
            'ts=[Sat Oct 24 %s 2026] Packet-Type = %s, Packet-Dst-IP-Address = 192.0.2.32, '
            'Packet-Dst-IP-Port = %d, %sTotp-Request-Id = "192.0.2.32:%d"'
            % (t, srv, ('id=%s ' % ident) if ident else '', t, verdict, port, more, port))


# ---------------------------------------------------------------------------
title('The token server’s packets, read a second time')
REAL = (HERE / 'otp-1.0.92' / 'otp2-radius-detail.log').read_text(
    encoding='utf-8').splitlines()[:2]
store, daemon, db = fresh()
det(REAL, daemon)
once = asked(db)
det(REAL, daemon)
ok('a request and its reply a second apart, read twice, are still one row',
   (len(once), asked(db)), (1, once))
store, daemon, db = fresh()
det(REAL[::-1], daemon)
first = asked(db)
det(REAL[::-1], daemon)
ok('...and the same when the reply came in first', (len(first), asked(db)), (1, first))

store, daemon, db = fresh()
PAIR = [ask('10:00:00', 41000, 'carol@ex.int', '198.51.100.7', ident='aaaa'),
        ans('10:00:01', 41000, 'Access-Reject', ident='bbbb')]
det(PAIR, daemon)
det(PAIR, daemon)
ok('a refusal before any code, its file read again: one packet',
   [r[1:] for r in asked(db)], [('carol@ex.int', 'reject')])
daemon.apply_radius_refusals(since=0)
ok('...and one refusal, not a second one with nobody’s name on it',
   [tuple(r) for r in db.execute("SELECT username, code FROM failed")],
   [('carol', 'before-code')])

# ---------------------------------------------------------------------------
title('An id is a conversation only on the same machine, for the same person')
store, daemon, db = fresh()
det([ask('10:00:00', 40000, 'alice@ex.int', '198.51.100.1', 'otp2'),
     ans('10:00:00', 40000, 'Access-Accept', 'otp2')], daemon)
tok(['Oct 24 10:00:00 otp1 totp.cgi[5]: Success: user=bob@ex.int, mode=PAM_SM_AUTH, '
     'host=127.0.0.1, rid=192.0.2.32:40000, message=Valid token used'], daemon)
rows = [dict(r) for r in db.execute("SELECT * FROM passed WHERE kind = 'otp'")]
got = store.otp_asked_near([(r['session'], r['server'], r['username'], r['ts'], True,
                             r['tkey'], r['asked_as']) for r in rows])
ok('bob’s token line, his packet not shipped yet: not alice’s packet on the other '
   'node', [v.get('username') for v in got.values()], [])
det([ask('10:00:20', 40000, 'bob@ex.int', '203.0.113.66'),
     ans('10:00:20', 40000, 'Access-Accept')], daemon)
got = store.otp_asked_near([(r['session'], r['server'], r['username'], r['ts'], True,
                             r['tkey'], r['asked_as']) for r in rows])
ok('...and his own, once it is there, by the id',
   [(v.get('username'), v.get('ip'), v.get('by')) for v in got.values()],
   [('bob@ex.int', '203.0.113.66', 'the id both logs carry')])

# ---------------------------------------------------------------------------
title('A code typed is not a code never typed')
store, daemon, db = fresh()
STATE = '0x6f7470318a'
det([ans('10:00:00', 42000, 'Access-Challenge', more='State = %s, Reply-Message = '
         '"Type the code sent by SMS to +420******123", ' % STATE),
     ask('10:01:00', 42001, 'dana@ex.int', '198.51.100.9') .replace(
         'Totp-Request-Id', 'State = %s, Totp-Request-Id' % STATE)], daemon)
one = [c for c in store.otp_challenges_since(0, NOW * 2)]
ok('a question whose request never came has no name on it',
   [c['username'] for c in one], [''])
ok('...and the answer to it is still found, by its State',
   store.otp_state_answered('', one[0]['state'], one[0]['ts']), True)
ok('...so it is not written down as a code nobody typed',
   daemon.apply_unanswered_codes(one[0]['ts'] + 1800, {}), 0)

# ---------------------------------------------------------------------------
title('FTD: what 722033 is')
ok('722033 is the first connection, not DTLS', isemon.FTD_DESC['722033'],
   'AnyConnect first connection established')
ok('...and 722034 a new TCP connection', isemon.FTD_DESC['722034'],
   'AnyConnect: new TCP connection')

# ---------------------------------------------------------------------------
title('An upgrade root never finished does not block every one after it')
store, daemon, db = fresh()
up = daemon.upgrades
folder = up.folder()
folder.mkdir(parents=True, exist_ok=True)
(folder / 'request.taken').write_text('{}')
(folder / 'status.json').write_text(json.dumps({'state': 'running', 'at': time.time()}))
ok('a request root took a moment ago is an upgrade running', up.running(), True)
old = time.time() - 3 * 3600
(folder / 'status.json').write_text(json.dumps({'state': 'running', 'at': old}))
os.utime(str(folder / 'request.taken'), (old, old))
ok('...one left behind hours ago, by a helper that was killed, is not', up.running(), False)
(folder / 'request.json').write_text('{}')
ok('...while a request just laid down is', up.running(), True)

# ---------------------------------------------------------------------------
title('A package that says it is huge is refused before it is unpacked')
os.environ['ISEMON_LIB'] = str(work / 'lib')
(work / 'lib').mkdir()
(work / 'lib' / 'isemon.py').write_text("__version__ = '%s'\n" % isemon.__version__)
upg = load('isemon_upgrade')


class Zeros(io.RawIOBase):
    def __init__(self, n):
        self.n = n

    def readable(self):
        return True

    def readinto(self, b):
        k = min(len(b), self.n)
        b[:k] = bytes(k)
        self.n -= k
        return k


bomb = work / 'isemon-9.9.9.tar.gz'
with tarfile.open(str(bomb), 'w:gz') as tar:
    for n in range(2):
        info = tarfile.TarInfo('isemon-9.9.9/f%d' % n)
        info.size = 200 * 1024 * 1024
        tar.addfile(info, io.BufferedReader(Zeros(info.size)))
began = time.time()
try:
    upg.inspect(str(bomb))
    ok('refused', False)
except upg.Refused as e:
    ok('refused for its size', 'more than 256 MB' in str(e))
ok('...as soon as the headers say so, not after unpacking it', time.time() - began < 2.0)

if os.geteuid() == 0:
    keys = work / 'keys'
    keys.mkdir()
    sh('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(keys / 'r.key'))
    sh('openssl', 'pkey', '-in', str(keys / 'r.key'), '-pubout', '-out',
       str(keys / 'test-release.pub'))
    upg.KEYS_DIR = str(keys)
    os.environ['ISEMON_RELEASE_KEYS'] = str(keys)
    nxt = isemon.__version__.rsplit('.', 1)
    nxt = '%s.%d' % (nxt[0], int(nxt[1]) + 1)
    top = work / 'pk' / ('isemon-%s' % nxt)
    (top / 'deploy' / 'release-keys').mkdir(parents=True)
    shutil.copy(str(keys / 'test-release.pub'), str(top / 'deploy' / 'release-keys'))
    (top / 'isemon.py').write_text("__version__ = '%s'\n" % nxt)
    (top / 'install.sh').write_text('#!/bin/bash\necho starting\nsleep 30\necho never\n')
    pkg = work / ('isemon-%s.tar.gz' % nxt)
    made = sh(sys.executable, str(ROOT / 'tools' / 'release.py'), str(top),
              str(keys / 'r.key'), str(pkg))
    ok('a package whose install.sh hangs, signed', made.returncode, 0)
    upg = load('isemon_upgrade')
    upg.INSTALL_LIMIT_S = 1
    began = time.time()
    try:
        upg.put_in(str(pkg))
        ok('an install.sh that hangs is stopped', False)
    except upg.Refused as e:
        ok('an install.sh that hangs is stopped, and said so', 'did not finish' in str(e))
    ok('...at its deadline, not when what it started ends by itself', time.time() - began < 10)
else:
    print('  (not root: the deadline on install.sh is not run here)')

# ---------------------------------------------------------------------------
title('release.py refuses a linked folder, which every machine would refuse')
odd = work / 'odd' / 'isemon-9.9.8'
(odd / 'real').mkdir(parents=True)
(odd / 'isemon.py').write_text("__version__ = '9.9.8'\n")
os.symlink('real', str(odd / 'linked'))
got = sh(sys.executable, str(ROOT / 'tools' / 'release.py'), str(odd), '/nonexistent',
         str(work / 'odd.tar.gz'))
ok('not signed', (got.returncode != 0, 'linked is a link' in got.stdout + got.stderr),
   (True, True))

# ---------------------------------------------------------------------------
title('A new DH group reaches nginx')
NGINX = work / 'nginx' / 'isemon.conf'
CERTS = work / 'certs'
NGINX.parent.mkdir()
CERTS.mkdir()
shutil.copy(str(ROOT / 'deploy' / 'nginx-isemon.conf'), str(NGINX))
NGINX.write_text(NGINX.read_text().replace('/etc/nginx/certs', str(CERTS)))
os.environ.update(ISEMON_NGINX_CONF=str(NGINX), ISEMON_CERT_DIR=str(CERTS))
web = load('isemon_web')
ran = []
real_run = web.subprocess.run


def fake_run(cmd, *a, **kw):
    if cmd[0] in ('nginx', 'systemctl', 'restorecon'):
        ran.append(cmd[:2])
        return subprocess.CompletedProcess(cmd, 0, '', '')
    return real_run(cmd, *a, **kw)


web.subprocess.run = fake_run
web.NO_SERVICES = False
web.progress = lambda *a, **kw: None
for dh in ('ffdhe2048', 'ffdhe4096'):
    del ran[:]
    web.nginx_part(web.checked({'tls': {'protocols': ['TLSv1.2', 'TLSv1.3'], 'dh': dh}}), {})
    ok('%s: nginx asked and reloaded' % dh,
       (['nginx', '-t'] in ran, ['systemctl', 'reload'] in ran), (True, True))
del ran[:]
web.nginx_part(web.checked({'tls': {'protocols': ['TLSv1.2', 'TLSv1.3'],
                                    'dh': 'ffdhe4096'}}), {})
ok('...and the same group again reloads nothing', ran, [])

title('A firewall that cannot be done is refused before nginx is touched')
before = NGINX.read_text()
web.fw_backend = lambda: 'firewalld'
try:
    web.fw_can({'on': True})
    ok('refused', False)
except web.Refused as e:
    ok('firewalld, and isemon asked to keep the firewall: refused first', 'firewalld' in str(e))
ok('...and nothing of nginx’s changed', NGINX.read_text(), before)
ok('a firewall left off asks nothing of the machine', web.fw_can({'on': False}), None)

# ---------------------------------------------------------------------------
title('The pages')
api = (ROOT / 'web' / 'isemon-api.php').read_text(encoding='utf-8')
ok('bytes that are not UTF-8 are sent on, not a 500',
   'JSON_INVALID_UTF8_SUBSTITUTE' in api)
php = shutil.which('php')
if php:
    probe = work / 'probe.php'
    probe.write_text('<?php declare(strict_types=1);\n'
                     'echo strlen((string) json_encode(["k" => "\\xe9t\\xe9"], '
                     'JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)) > 0 ? "ok" : "no";\n')
    ok('...which PHP does', sh(php, str(probe)).stdout, 'ok')
    got = sh(php, '-d', 'session.upload_progress.enabled=1', '-r',
             'require "%s"; echo json_encode(isemon_php_safety());'
             % (ROOT / 'web' / 'isemon-api.php'))
    try:
        said = json.loads(got.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        said = {}
    ok('upload progress on for PHP as a whole is not guarded', said.get('guarded'), False)
page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
ok('the notice points at /etc/php.d as well as .user.ini',
   '/etc/php.d/99-php2shell.ini for the whole of PHP' in page)

# ---------------------------------------------------------------------------
title('The suite does not depend on the day it is run')
for name in ('checks.py', 'doors.py'):
    ok('%s writes ISE’s offset as it is that day' % name,
       "'.500 +02:00'" not in (HERE / name).read_text(encoding='utf-8'))
ok('fixes226 asks for the codes never typed at its own moment',
   'apply_unanswered_codes(NOW, {})' in (HERE / 'fixes226.py').read_text(encoding='utf-8'))

shutil.rmtree(str(work), ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
