#!/usr/bin/env python3
"""1.10.228: Settings -> Backups - backups to another machine, as otp has
them. A backup is the full backup (the copy of the database with its keys),
packed with a manifest and RESTORE.md and locked with openssl exactly as otp
locks it; it goes to a folder, FTP, FTPS, SFTP, SCP or SMB, on a schedule or
now, and comes back from a destination, from a file sent from the page, or
with `isemon --restore-bundle` on a machine installed from nothing.

ssh, sftp, scp, ssh-keyscan, ssh-keygen and smbclient are stood in for by
small fakes that keep the "server's" files in a folder of their own, and
check what they are given the way the real ones do: the host key trusted,
the password asked through SSH_ASKPASS and never on the command line, the
password of a share in its authentication file.

    ./test/fixes228_rbackup.py
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19700 + random.randint(0, 90)
PW = 'Backups-Password-1234'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def refused(what, fn, *args):
    try:
        fn(*args)
        ok(what, 'taken', 'refused')
    except (ValueError, isemon.RbError) as e:
        ok(what, bool(str(e)), True)


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


work = Path(tempfile.mkdtemp(prefix='isemon-228rb-'))
state = work / 'state'
state.mkdir()
isemon.STATE_DIR = state
isemon.DB_FILE = state / 'isemon.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'site_name': 'Test site'})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite', 'db_password': 'hush'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

# ---- the fakes ------------------------------------------------------------------
FAKE = work / 'bin'
FAKE.mkdir()
REMOTE = work / 'remote'          # the "server's" files
REMOTE.mkdir()
SMBROOT = work / 'share'
SMBROOT.mkdir()
ARGV_LOG = work / 'argv.log'
FAKES = {
    'ssh-keyscan': r'''
import os, sys
print('%s %s' % (sys.argv[-1], os.environ.get('FAKE_HOSTKEY', 'ssh-ed25519 AAAAC3NzaFAKE1')))
''',
    'ssh-keygen': r'''
import sys
a = sys.argv[1:]
if '-l' in a or '-lf' in a:
    for line in sys.stdin.read().splitlines():
        if line.strip():
            print('256 SHA256:%s %s (ED25519)' % (line.split()[-1][-10:], line.split()[0]))
    sys.exit(0)
path = a[a.index('-f') + 1]
if '-y' in a:
    text = open(path).read()
    if 'PRIVATE KEY' not in text:
        sys.stderr.write('invalid format\n'); sys.exit(1)
    if 'LOCKED' in text and '-P' in a:
        sys.stderr.write('incorrect passphrase supplied to decrypt private key\n'); sys.exit(1)
    print('ssh-ed25519 AAAAC3NzaPUBLIC fake')
    sys.exit(0)
comment = a[a.index('-C') + 1]
open(path, 'w').write('-----BEGIN OPENSSH PRIVATE KEY-----\nmadehere\n-----END OPENSSH PRIVATE KEY-----\n')
open(path + '.pub', 'w').write('ssh-ed25519 AAAAC3NzaMADE %s\n' % comment)
''',
    # ssh, sftp and scp: the server's host key as trusted, then the account
    # let in by its key or by the password SSH_ASKPASS gives.
    '_sshcommon': r'''
import os, subprocess, sys
ROOT = os.environ['FAKE_SSH_ROOT']
open(os.environ['FAKE_ARGV_LOG'], 'a').write(' '.join(sys.argv) + '\n')
a = sys.argv[1:]
opts = {}
i = 0
while i < len(a) and a[i] != '--':
    if a[i] == '-o':
        k, _, v = a[i + 1].partition('='); opts[k] = v; i += 2
    elif a[i] in ('-i', '-F', '-p', '-P', '-b'):
        opts[a[i]] = a[i + 1]; i += 2
    else:
        i += 1
rest = a[i + 1:]
kh = open(opts.get('UserKnownHostsFile', '/dev/null')).read()
if os.environ.get('FAKE_HOSTKEY', 'ssh-ed25519 AAAAC3NzaFAKE1') not in kh:
    sys.stderr.write('Host key verification failed.\n'); sys.exit(255)
inside = False
if '-i' in opts and 'PRIVATE KEY' in open(opts['-i']).read():
    inside = True
elif os.environ.get('SSH_ASKPASS'):
    said = subprocess.run([os.environ['SSH_ASKPASS']], capture_output=True, text=True).stdout.strip()
    inside = said == os.environ.get('FAKE_PASSWORD')
if not inside:
    sys.stderr.write('user@host: Permission denied (publickey,password).\n'); sys.exit(255)
def where(p):
    p = p.strip('"')
    return os.path.join(ROOT, p.lstrip('/'))
''',
}
# The three ssh fakes share their first half.
common = FAKES.pop('_sshcommon')
FAKES['ssh'] = common + r'''
sys.exit(subprocess.run(['sh', '-c', rest[-1]], cwd=ROOT).returncode)
'''
FAKES['sftp'] = common + r'''
import shlex, shutil
cwd = ROOT
for line in open(opts['-b']).read().splitlines():
    quiet = line.startswith('-')
    words = shlex.split(line.lstrip('-'))
    if not words:
        continue
    op, args = words[0], words[1:]
    def at(p):
        return os.path.join(ROOT, p.lstrip('/')) if p.startswith('/') else os.path.join(cwd, p)
    try:
        if op == 'mkdir':
            os.mkdir(at(args[0]))
        elif op == 'cd':
            if not os.path.isdir(at(args[0])):
                raise OSError('no such folder')
            cwd = at(args[0])
        elif op == 'put':
            shutil.copyfile(args[0], at(args[1]))
        elif op == 'get':
            shutil.copyfile(at(args[0]), args[1])
        elif op == 'rm':
            os.unlink(at(args[0]))
        elif op == 'rename':
            os.rename(at(args[0]), at(args[1]))
        elif op == 'ls':
            for n in sorted(os.listdir(cwd)):
                st = os.stat(os.path.join(cwd, n))
                print('-rw-r--r--    1 1000     1000     %8d Oct 28 20:00 %s' % (st.st_size, n))
    except OSError as e:
        if not quiet:
            sys.stderr.write('%s: %s\n' % (op, e)); sys.exit(1)
'''
FAKES['scp'] = common + r'''
import shutil
src, dst = rest[-2], rest[-1]
if '@' in src.split(':')[0] and ':' in src:
    shutil.copyfile(os.path.join(ROOT, src.split(':', 1)[1].lstrip('/')), dst)
else:
    shutil.copyfile(src, os.path.join(ROOT, dst.split(':', 1)[1].lstrip('/')))
'''
FAKES['smbclient'] = r'''
import os, re, shutil, sys, time
ROOT = os.environ['FAKE_SMB_ROOT']
a = sys.argv[1:]
open(os.environ['FAKE_ARGV_LOG'], 'a').write(' '.join(a) + '\n')
auth = open(a[a.index('-A') + 1]).read()
if 'password = %s\n' % os.environ.get('FAKE_PASSWORD') not in auth:
    print('session setup failed: NT_STATUS_LOGON_FAILURE'); sys.exit(1)
share = os.path.join(ROOT, a[0].split('/')[-1])
if not os.path.isdir(share):
    print('tree connect failed: NT_STATUS_BAD_NETWORK_NAME'); sys.exit(1)
cwd = share
for cmd in a[a.index('-c') + 1].split('; '):
    m = re.match(r'^(\w+)\s*(.*)$', cmd)
    op, args = m.group(1), re.findall(r'"([^"]*)"', m.group(2))
    at = lambda p: os.path.join(share, *[x for x in p.split('\\') if x]) if p.startswith('\\') \
        else os.path.join(cwd, *[x for x in p.split('\\') if x])
    if op == 'mkdir':
        if os.path.isdir(at(args[0])):
            print('NT_STATUS_OBJECT_NAME_COLLISION making remote directory')
        else:
            os.mkdir(at(args[0]))
    elif op == 'cd':
        cwd = at(args[0])
    elif op == 'ls':
        for n in sorted(os.listdir(cwd)):
            p = os.path.join(cwd, n)
            print('  %-40s %5s %10d  %s' % (n, 'D' if os.path.isdir(p) else 'A',
                                             os.path.getsize(p),
                                             time.strftime('%a %b %d %H:%M:%S %Y')))
    elif op == 'put':
        shutil.copyfile(args[0], at(args[1]))
    elif op == 'get':
        shutil.copyfile(at(args[0]), args[1])
    elif op == 'del':
        if os.path.exists(at(args[0])):
            os.unlink(at(args[0]))
        else:
            print('NT_STATUS_NO_SUCH_FILE deleting remote file')
    elif op == 'rename':
        os.rename(at(args[0]), at(args[1]))
'''
for name, body in FAKES.items():
    p = FAKE / name
    p.write_text('#!%s\nimport os, sys\n%s' % (sys.executable, body))
    p.chmod(0o755)
os.environ['PATH'] = '%s:%s' % (FAKE, os.environ.get('PATH', ''))
os.environ.update(FAKE_SSH_ROOT=str(REMOTE), FAKE_SMB_ROOT=str(SMBROOT),
                  FAKE_ARGV_LOG=str(ARGV_LOG), FAKE_PASSWORD='server-pass-77')
(SMBROOT / 'backup').mkdir()

try:
    # ------------------------------------------------------------------------
    print('\nNothing happens until somebody sets it up')
    ok('the schedule is off by default', isemon.DEFAULTS['rbackup'], 0)
    ok('no password by default', isemon.DEFAULTS['rbackup_password'], '')
    ok('no destination at first', isemon.rb_targets(store), [])
    ok('so the minute\'s pass does nothing', (isemon.rb_tick(daemon), daemon.jobs()), (None, []))
    ok('the password is a secret setting', 'rbackup_password' in isemon.SECRET_KEYS)
    for k in ('rbackup', 'rbackup_at', 'rbackup_every', 'rbackup_day', 'rbackup_keep',
              'rbackup_keep_days', 'rbackup_password'):
        ok('%s has its words and its shape' % k, (k in daemon.NAMES, bool(daemon.SAYS.get(k)),
                                                  k in daemon.TUNABLE), (True, True, True))

    # ------------------------------------------------------------------------
    print('\nWhat is typed is checked (otp 1.0.136)')
    C = isemon.rb_checked
    refused('a share with ; in it', C, {'kind': 'smb', 'host': 'nas', 'share': 'b;x'})
    refused('a share with " in it', C, {'kind': 'smb', 'host': 'nas', 'share': 'b"x'})
    refused('a share beginning with -', C, {'kind': 'smb', 'host': 'nas', 'share': '-x'})
    refused('a folder with ; in it', C, {'kind': 'sftp', 'host': 'h', 'path': 'a;rm -rf /'})
    refused('a folder with " in it', C, {'kind': 'smb', 'host': 'h', 'share': 's',
                                         'path': 'a"b'})
    refused('a folder beginning with -', C, {'kind': 'scp', 'host': 'h', 'path': '-oProxyCommand=x'})
    refused('an account beginning with -', C, {'kind': 'sftp', 'host': 'h', 'user': '-oX=y'})
    refused('a server beginning with -', C, {'kind': 'sftp', 'host': '-oProxyCommand=x'})
    refused('.. in a folder', C, {'kind': 'ftp', 'host': 'h', 'path': 'a/../../etc'})
    refused('a folder destination that is not a whole path', C, {'kind': 'folder', 'path': 'x'})
    refused('a port out of range', C, {'kind': 'ftp', 'host': 'h', 'port': 70000})
    refused('a kind there is not', C, {'kind': 'gopher', 'host': 'h'})
    refused('a line break in a password', C, {'kind': 'ftp', 'host': 'h', 'password': 'a\nb'})
    refused('an SSH certificate that is not one', C, {'kind': 'sftp', 'host': 'h',
                                                     'ssh_cert': 'rm -rf /'})
    refused('a pin that is not SHA-256', C, {'kind': 'ftps', 'host': 'h', 'tls_check': 'pin',
                                            'pin': 'abc'})
    ok('FTPS implicit takes port 990 by itself',
       C({'kind': 'ftps', 'host': 'h', 'implicit': 1})['port'], 990)
    ok('SMB3 encryption is on by default', C({'kind': 'smb', 'host': 'h', 'share': 's'})
       ['smb_encrypt'], 1)

    # ------------------------------------------------------------------------
    print('\nSecrets stay sealed')
    t = isemon.rb_save(store, {'kind': 'ftp', 'host': 'ftp.example.cz', 'user': 'u',
                               'password': 'ftp-secret-99'}, 'boss')
    raw = store.get_meta('rbackup:targets')
    ok('the password is not in the database as it is', 'ftp-secret-99' in raw, False)
    ok('...it is sealed', isemon.rb_target(store, t['id'])['password'].startswith(
        isemon.SEALED))
    ok('...and opens again', isemon.rb_secret(isemon.rb_target(store, t['id']), 'password'),
       'ftp-secret-99')
    view = isemon.rb_view(isemon.rb_target(store, t['id']))
    ok('the page is shown its last letters only', (view['password'].endswith('99'),
                                                   'ftp-secret' in json.dumps(view)), (True, False))
    t2 = isemon.rb_save(store, dict(view, id=t['id'], kind='ftp'), 'boss')
    ok('dots sent back keep the password', isemon.rb_secret(t2, 'password'), 'ftp-secret-99')
    ok('...and nothing said about it in Events',
       any('ftp-secret' in (e['detail'] or '') for e in store.events(50)[0]), False)
    isemon.rb_delete(store, t['id'], 'boss')
    for i in range(isemon.RB_MOST):
        isemon.rb_save(store, {'kind': 'folder', 'path': '/mnt/x%d' % i}, 'boss')
    refused('a destination more than 20 is refused', isemon.rb_save, store,
            {'kind': 'folder', 'path': '/mnt/y'}, 'boss')
    isemon.rb_put_targets(store, [])
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    said = daemon.save_settings({'rbackup_password': PW, 'mikrotik_password': 'router-pw-1'},
                                by='boss')
    row = store.db.execute("SELECT value FROM settings WHERE key='rbackup_password'").fetchone()
    ok('the password of the backups is kept sealed', (PW in row['value'],
                                                     isemon.SEALED in row['value']), (False, True))
    ok('...and is the one in use', isemon.CONFIG.get('rbackup_password'), PW)
    shown = [s for s in daemon.settings_state() if s['key'] == 'rbackup_password'][0]
    ok('...and the page is shown dots', (shown['secret'], PW in str(shown['value'])), (True, False))

    # ------------------------------------------------------------------------
    print('\nWhen the schedule says')
    D = isemon.rb_due
    at = datetime(2026, 10, 28, 4, 30)          # a Wednesday
    ok('off: never due', D('', at), None)
    isemon.CONFIG.update({'rbackup': 1, 'rbackup_at': '04:15', 'rbackup_every': 'daily'})
    ok('daily, after the time: due today', D('', at), '2026-10-28')
    ok('...but not twice a day', D('2026-10-28', at), None)
    ok('...and not before the time', D('', datetime(2026, 10, 28, 4, 14)), None)
    isemon.CONFIG.update({'rbackup_every': 'weekly', 'rbackup_day': 7})
    ok('weekly on Sunday: not on a Wednesday', D('', at), None)
    ok('...on the Sunday', D('', datetime(2026, 11, 1, 5, 0)), '2026-11-01')
    ok('the next one is said', isemon.rb_next_words(at), '2026-11-01T04:15')
    isemon.CONFIG.update({'rbackup': 0, 'rbackup_every': 'daily'})
    ok('...and nothing when it is off', isemon.rb_next_words(at), '')
    try:
        isemon.check_setting('rbackup_at', '25:00') if hasattr(isemon, 'check_setting') else \
            daemon.save_settings({'rbackup_at': '25:00'}, by='boss')
        ok('a time that is not one is refused', False)
    except ValueError:
        ok('a time that is not one is refused', True)

    # ------------------------------------------------------------------------
    print('\nA backup: built, locked, opened')
    (state / 'known_hosts').write_text('10.0.0.1 ssh-ed25519 AAAAC3NzaROUTER\n')
    daemon.banfeed_key(make=True)
    key_before = (state / 'settings.key').read_text()
    b1 = work / 'b1'
    b1.mkdir()
    steps = []
    path, m, md = isemon.rb_build(store, b1, lambda d, w, s='': steps.append((d, s)))
    ok('its name says the site, the machine and when',
       bool(isemon.RB_NAME_RE.match(path.name)) and path.name.startswith(
           'isemon-backup-Test_site-%s-' % isemon.rb_host()) and path.name.endswith('.tar.gz.enc'))
    ok('it says how far it got as it goes', steps[-1][0] == 800 and len(steps) > 3)
    ok('the copy is not left behind unlocked', sorted(p.name for p in b1.iterdir()),
       sorted([path.name, path.name + '.sha256', m['base'] + '-RESTORE.md']))
    ok('the .sha256 beside it is its checksum',
       (b1 / (path.name + '.sha256')).read_text().split()[0], isemon.rb_sha(path))
    ok('RESTORE.md beside it is the one inside', (b1 / (m['base'] + '-RESTORE.md')).read_text(), md)
    ok('...and says how to put it back', '--restore-bundle %s --yes' % path.name in md)
    with open(str(path), 'rb') as f:
        ok('it is locked (openssl\'s salted format)', f.read(8), b'Salted__')
    plain = work / 'plain.tar.gz'
    got = sh('openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', '600000', '-md',
             'sha256', '-in', str(path), '-out', str(plain), '-pass', 'pass:' + PW)
    ok('openssl alone opens it, as RESTORE.md says', got.returncode, 0)
    with tarfile.open(str(plain)) as tf:
        names = [x.name.split('/', 1)[1] for x in tf.getmembers()]
        man = json.loads(tf.extractfile('%s/manifest.json' % m['base']).read())
        inner = tf.extractfile('%s/%s' % (m['base'], isemon.RB_DB)).read()
    ok('inside: about.json, RESTORE.md, the full backup, manifest.json', names,
       ['about.json', 'RESTORE.md', 'isemon-full.db', 'manifest.json'])
    import hashlib
    ok('the manifest has the SHA-256 of the copy', man['files']['isemon-full.db']['sha256'],
       hashlib.sha256(inner).hexdigest())
    fb = work / 'inner.db'
    fb.write_bytes(inner)
    carried = isemon.carried_in(fb)
    ok('the copy is a full backup: the keys are in it', sorted(carried),
       ['banfeed.key', 'config.json', 'known_hosts', 'settings.key'])
    ok('...the database password left out of config.json',
       json.loads(carried['config.json'])['db_password'], '')
    ok('...and the live database keeps no keys table', store.db.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='isemon_carried'").fetchone()[0], 0)
    ok('the right password opens it', isemon.rb_peek(str(path), PW)['host'], isemon.rb_host())
    refused('a wrong password does not', isemon.rb_peek, str(path), 'not-it')
    refused('no password does not', isemon.rb_peek, str(path), '')
    opened = work / 'open1'
    opened.mkdir()
    top, man2 = isemon.rb_open(str(path), PW, opened)
    ok('opened whole: every file checked against the manifest', sorted(p.name for p in
                                                                     top.iterdir()),
       ['RESTORE.md', 'about.json', 'isemon-full.db', 'manifest.json'])
    bad = work / 'bad.tar.gz'
    with tarfile.open(str(plain)) as src, tarfile.open(str(bad), 'w:gz') as dst:
        for mb in src.getmembers():
            data = src.extractfile(mb).read()
            if mb.name.endswith(isemon.RB_DB):
                data = data[:-1] + bytes([data[-1] ^ 1])
            import io
            dst.addfile(mb, io.BytesIO(data))
    opened2 = work / 'open2'
    opened2.mkdir()
    try:
        isemon.rb_open(str(bad), '', opened2)
        ok('a copy changed by one bit is refused', False)
    except isemon.RbError as e:
        ok('a copy changed by one bit is refused', 'damaged' in str(e))
    evil = work / 'evil.tar.gz'
    with tarfile.open(str(evil), 'w:gz') as dst:
        import io
        ti = tarfile.TarInfo('isemon-backup-x-y-20260101-000000/../../etc/passwd')
        ti.size = 3
        dst.addfile(ti, io.BytesIO(b'x\n\n'))
    opened3 = work / 'open3'
    opened3.mkdir()
    refused('a file that would land outside is refused', isemon.rb_open, str(evil), '', opened3)

    # ------------------------------------------------------------------------
    print('\nWithout the password nothing is sent')
    dest = work / 'dest'
    t = isemon.rb_save(store, {'kind': 'folder', 'path': str(dest), 'name': 'NAS'}, 'boss')
    isemon.CONFIG['rbackup_password'] = ''
    refused('a backup is refused', isemon.rb_run, store, 'boss')
    ok('...and nothing went there', dest.exists() and any(dest.iterdir()), False)
    isemon.CONFIG['rbackup_password'] = PW

    # ------------------------------------------------------------------------
    print('\nA folder, from end to end')
    out = isemon.rb_try(isemon.rb_target(store, t['id']))
    ok('tried: signed in, written, listed, taken away', (out['ok'], len(out['steps'])), (True, 4))
    ok('...and nothing left there', sorted(os.listdir(str(dest))), [])
    run = isemon.rb_run(store, 'boss')
    ok('sent', (run['ok'], [x['ok'] for x in run['targets']]), (True, [True]))
    there = sorted(os.listdir(str(dest)))
    ok('the backup, its .sha256 and its RESTORE.md are there', len(there), 3)
    ok('...said in the history', isemon.rb_history(store)[0]['file'], run['file'])
    ok('...and on the destination', isemon.rb_target(store, t['id'])['last']['ok'], True)
    listed = isemon.rb_remote_list(store, t['id'])
    ok('the list there has it, as this machine\'s', [(x['name'], x['mine'], x['sha256'])
                                                    for x in listed], [(run['file'], True, True)])
    # Older ones: this machine's and another's.
    host = isemon.rb_host()
    for stamp_ in ('20250101-010101', '20250102-010101', '20250103-010101'):
        for n in ('isemon-backup-Test_site-%s-%s.tar.gz.enc' % (host, stamp_),
                  'isemon-backup-Test_site-%s-%s.tar.gz.enc.sha256' % (host, stamp_),
                  'isemon-backup-Test_site-%s-%s-RESTORE.md' % (host, stamp_),
                  'isemon-backup-Test_site-other-%s.tar.gz.enc' % stamp_):
            (dest / n).write_text('x')
        # Sent by this installation (1.10.234: retention takes away only those).
        isemon.rb_sent_add(store, 'isemon-backup-Test_site-%s-%s.tar.gz.enc' % (host, stamp_))
    # One of the same name that this installation never sent: another machine
    # of the same short name - left alone.
    twin = dest / ('isemon-backup-Test_site-%s-20250104-010101.tar.gz.enc' % host)
    twin.write_text('x')
    isemon.CONFIG.update({'rbackup_keep': 2, 'rbackup_keep_days': 0})
    time.sleep(1.1)                 # a name a second: not the same name as the first
    run2 = isemon.rb_run(store, 'boss')
    left = sorted(x['name'] for x in isemon.rb_remote_list(store, t['id']) if x['mine'])
    ok('kept: the newest two of this machine (and the twin it never sent)', len(left), 3)
    ok('...the twin of the same name left alone', twin.exists(), True)
    twin.unlink()
    ok('...the older ones taken away with their .sha256 and RESTORE.md',
       [n for n in os.listdir(str(dest)) if '2025010' in n and host in n], [])
    ok('...another machine\'s left alone',
       len([n for n in os.listdir(str(dest)) if '-other-' in n]), 3)
    ok('...and said (the three older ones)', len(run2['targets'][0]['taken_away']), 3)
    isemon.CONFIG.update({'rbackup_keep': 30, 'rbackup_keep_days': 1})
    old = dest / ('isemon-backup-Test_site-%s-20200101-000000.tar.gz.enc' % host)
    old.write_text('x')
    gone = isemon.rb_retain(isemon.RbFolder(isemon.rb_target(store, t['id'])), 30, 1)
    ok('older than the days kept: taken away too', gone, [old.name])
    fetched = work / 'fetched.enc'
    isemon.rb_fetch(store, t['id'], run2['file'], str(fetched))
    ok('fetched back whole', isemon.rb_sha(fetched), isemon.rb_sha(dest / run2['file']))
    refused('a name that is not a backup is not fetched', isemon.rb_fetch, store, t['id'],
            '../../etc/passwd', str(work / 'x'))

    # ------------------------------------------------------------------------
    print('\nSFTP, SCP and SMB (through the fakes)')
    sf = isemon.rb_save(store, {'kind': 'sftp', 'host': 'backup.example.cz', 'user': 'bk',
                                'path': 'backups/sftp', 'password': 'server-pass-77'}, 'boss')
    out = isemon.rb_do(daemon, {'action': 'try', 'id': sf['id']}, 'boss')
    ok('not trusted yet: the host key is shown to compare',
       (out.get('hostkey_needed'), len(out.get('fingerprints') or [])), (True, 1))
    isemon.rb_do(daemon, {'action': 'hostkey_trust', 'id': sf['id'], 'hostkey': out['hostkey']},
                 'boss')
    try:
        isemon.rb_do(daemon, {'action': 'hostkey_trust', 'id': sf['id'],
                              'hostkey': 'backup.example.cz ssh-rsa AAAAtypedin\n'}, 'boss')
        ok('only the key the server shows can be trusted', False)
    except isemon.RbError:
        ok('only the key the server shows can be trusted', True)
    out = isemon.rb_do(daemon, {'action': 'try', 'id': sf['id']}, 'boss')
    ok('SFTP with a password: it works', (out['ok'], out.get('error')), (True, None))
    ok('...and the password was never on a command line',
       'server-pass-77' in ARGV_LOG.read_text(), False)
    sc = isemon.rb_save(store, {'kind': 'scp', 'host': 'backup.example.cz', 'user': 'bk',
                                'path': 'backups/scp'}, 'boss')
    isemon.rb_set_fields(store, sc['id'], 'boss', '', hostkey=isemon.rb_target(
        store, sf['id'])['hostkey'])
    ok('SCP with neither key nor password: said', isemon.rb_try(isemon.rb_target(
        store, sc['id'])).get('error'), 'neither a key nor a password is set')
    got = isemon.rb_do(daemon, {'action': 'keygen', 'id': sc['id']}, 'boss')
    ok('a key made here: the public half shown', got['pub'].startswith('ssh-ed25519'))
    ok('...the private half kept sealed', isemon.rb_target(store, sc['id'])['key'].startswith(
        isemon.SEALED))
    ok('...never shown on the page', 'PRIVATE' in json.dumps(isemon.rb_view(
        isemon.rb_target(store, sc['id']))), False)
    ok('SCP with the key: it works', isemon.rb_try(isemon.rb_target(store, sc['id']))['ok'])
    sm = isemon.rb_save(store, {'kind': 'smb', 'host': 'nas', 'share': 'backup',
                                'path': 'isemon\\nightly', 'user': 'bk',
                                'password': 'server-pass-77', 'domain': 'CORP'}, 'boss')
    ok('SMB: it works', isemon.rb_try(isemon.rb_target(store, sm['id']))['ok'])
    ok('...SMB3 encryption asked for', '--client-protection=encrypt' in ARGV_LOG.read_text())
    ok('...and the password only in the authentication file',
       ARGV_LOG.read_text().count('server-pass-77'), 0)
    run3 = isemon.rb_run(store, 'boss')
    ok('one backup sent to all four', [(x['kind'], x['ok']) for x in run3['targets']],
       [('folder', True), ('sftp', True), ('scp', True), ('smb', True)])
    ok('...each holds it whole', all(
        isemon.rb_sha(p) == isemon.rb_sha(dest / run3['file'])
        for p in (REMOTE / 'backups' / 'sftp' / run3['file'],
                  REMOTE / 'backups' / 'scp' / run3['file'],
                  SMBROOT / 'backup' / 'isemon' / 'nightly' / run3['file'])))
    ok('SFTP lists it', run3['file'] in [x['name'] for x in isemon.rb_remote_list(store, sf['id'])])
    isemon.rb_do(daemon, {'action': 'delete_file', 'id': sm['id'], 'name': run3['file']}, 'boss')
    ok('deleted at the share, with its companions',
       [n for n in os.listdir(str(SMBROOT / 'backup' / 'isemon' / 'nightly'))
        if n.startswith(run3['file'].split('.tar')[0])], [])
    os.environ['FAKE_HOSTKEY'] = 'ssh-ed25519 AAAAC3NzaREINSTALLED'
    out = isemon.rb_try(isemon.rb_target(store, sf['id']))
    ok('a server answering with another host key is refused',
       'another host key' in (out.get('error') or ''))
    os.environ.pop('FAKE_HOSTKEY')
    os.environ['FAKE_PASSWORD'] = 'changed'
    out = isemon.rb_try(isemon.rb_target(store, sm['id']))
    ok('a share that does not take the password says so',
       'did not take the account and password' in (out.get('error') or ''))
    os.environ['FAKE_PASSWORD'] = 'server-pass-77'
    for one in (sf, sc, sm):
        isemon.rb_set_fields(store, one['id'], '', '', enabled=0)

    # ------------------------------------------------------------------------
    print('\nPutting one back, on a machine installed from nothing')
    fresh = work / 'fresh'
    fresh.mkdir()
    (fresh / 'config.json').write_text(json.dumps({'db_engine': 'sqlite',
                                                   'api_port': PORT + 200}))
    env = dict(os.environ, ISEMON_CONFIG=str(fresh / 'config.json'), ISEMON_STATE=str(fresh))
    sh(sys.executable, str(ROOT / 'isemon.py'), '--add-user', 'someone', '--role', 'fulladmin',
       env=dict(env, ISEMON_PASSWORD='another-long-password'), timeout=120)
    (fresh / 'settings.key').write_text('0' * 64 + '\n')
    pf = work / 'pw.txt'
    pf.write_text(PW + '\n')
    bundle = dest / run3['file']
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(pf), env=env, timeout=120)
    ok('without --yes: what is in it, nothing changed',
       (got.returncode, 'again with --yes' in got.stdout,
        (fresh / 'settings.key').read_text().startswith('0' * 64)), (0, True, True))
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(work / 'nope'), '--yes', env=env, timeout=120)
    ok('a password file that is not there: refused', got.returncode != 0)
    (work / 'wrong.txt').write_text('wrong\n')
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(work / 'wrong.txt'), '--yes', env=env, timeout=120)
    ok('a wrong password: refused, and said', (got.returncode, 'password does not open it' in
                                               got.stdout + got.stderr), (1, True))
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(pf), '--yes', env=env, timeout=300)
    ok('with --yes: put back', got.returncode, 0)
    if got.returncode:
        print(got.stdout[-1500:], got.stderr[-1500:])
    ok('...the key that opens the passwords is the one of the machine it came from',
       (fresh / 'settings.key').read_text(), key_before)
    ok('...the one that was there kept beside it', any(
        p.name.startswith('settings.key.before-restore-') for p in fresh.iterdir()))
    ok('...the ban feed\'s key and the host keys too',
       ((fresh / 'banfeed.key').exists(), (fresh / 'known_hosts').read_text()),
       (True, (state / 'known_hosts').read_text()))
    ok('...a copy of what it replaced was made first',
       any('before-restore' in p.name for p in (fresh / 'backups').iterdir()))
    isemon.Storage._unsealable = set()
    other = isemon.Storage(fresh / 'isemon.db')
    saved_there = other.settings_saved()
    ok('...the passwords kept in it open there', (saved_there.get('mikrotik_password'),
                                                 saved_there.get('rbackup_password')),
       ('router-pw-1', PW))
    ok('...the accounts are the backup\'s', sorted(u['name'] for u in other.users()),
       ['boss', 'watcher'])
    ok('...the destinations came back, their secrets opening',
       isemon.rb_secret(isemon.rb_target(other, sm['id']), 'password'), 'server-pass-77')
    ok('...and the machine kept its own config.json',
       json.loads((fresh / 'config.json').read_text())['api_port'], PORT + 200)
    other.close() if hasattr(other, 'close') else None

    # ------------------------------------------------------------------------
    print('\nThrough the API')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None, raw=None, binary=False):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=raw if raw is not None else (
                                         json.dumps(payload).encode() if payload is not None
                                         else None),
                                     method='POST' if (payload is not None or raw is not None)
                                     else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/octet-stream' if raw is not None
                       else 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=300) as answer:
                body = answer.read()
                return answer.status, (body if binary else json.loads(body.decode() or '{}'))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def wait(session, jid=None, most=120):
        for _ in range(most * 4):
            if jid:
                st, d = call('/api/job?id=%s' % jid, session=session)
                if d.get('job', {}).get('done'):
                    return d['job']
            else:
                st, d = call('/api/rbackup', {'action': 'job'}, session)
                if not d['job'].get('running'):
                    return d['job']
            time.sleep(0.25)
        return None
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    ok('read only may not even look', call('/api/rbackup', session=tok['watcher'])[0], 403)
    ok('...nor send anything', call('/api/rbackup', {'action': 'run'}, tok['watcher'])[0], 403)
    ok('...nor download', call('/api/rbackup/download?made=x', session=tok['watcher'])[0], 403)
    ok('...nor upload', call('/api/rbackup/upload', session=tok['watcher'], raw=b'x' * 10)[0], 403)
    ok('nobody signed in: nothing', call('/api/rbackup')[0], 401)
    st, page = call('/api/rbackup', session=tok['boss'])
    ok('a full administrator sees the page', (st, page['locked'], len(page['targets'])),
       (200, True, 4))
    ok('...with nothing secret in it', any(s in json.dumps(page) for s in (
        'server-pass-77', 'PRIVATE KEY', PW)), False)
    ok('...and what is on this machine', set(page['tools']) >= {'ssh', 'smbclient', 'openssl'})
    st, said = call('/api/rbackup', {'action': 'save', 'target': {'kind': 'smb', 'host': 'nas',
                                                                  'share': 'a;b'}}, tok['boss'])
    ok('a share with ; in it is refused here too', (st, 'no ; or "' in said['error'] or
                                                    'is not one' in said['error']), (400, True))
    st, said = call('/api/rbackup', {'action': 'try', 'id': t['id']}, tok['boss'])
    ok('Try it', (st, said['ok']), (200, True))
    st, said = call('/api/rbackup', {'action': 'run'}, tok['boss'])
    ok('Back up now: a job', (st, said['job']['running'] in (True, False)), (200, True))
    job = wait(tok['boss'])
    ok('...that finishes, sent', (job and job['error'], job and job['result']['ok']), ('', True))
    st, said = call('/api/rbackup', {'action': 'here'}, tok['boss'])
    job = wait(tok['boss'])
    made = (job or {}).get('result', {}).get('made')
    ok('Download one here: made ready', bool(made and isemon.RB_NAME_RE.match(made)))
    st, blob = call('/api/rbackup/download?made=%s' % made, session=tok['boss'], binary=True)
    ok('...and downloaded, locked', (st, blob[:8]), (200, b'Salted__'))
    for _ in range(40):
        if not (state / 'rbackup-made' / made).exists():
            break
        time.sleep(0.1)
    ok('...then gone from here', (state / 'rbackup-made' / made).exists(), False)
    ok('a name that is not one is not sent',
       call('/api/rbackup/download?made=..%2Fsettings.key', session=tok['boss'])[0], 404)
    st, said = call('/api/rbackup', {'action': 'list', 'id': t['id']}, tok['boss'])
    newest = said['files'][0]['name']
    st, said = call('/api/rbackup', {'action': 'fetch', 'id': t['id'], 'name': newest},
                    tok['boss'])
    job = wait(tok['boss'])
    st, blob2 = call('/api/rbackup/download?made=%s' % newest, session=tok['boss'], binary=True)
    ok('one at a destination fetched and downloaded', isemon.rb_sha(dest / newest),
       hashlib.sha256(blob2).hexdigest())
    st, said = call('/api/rbackup', {'action': 'restore_md'}, tok['boss'])
    ok('How to put it back: RESTORE.md as one made now has it',
       ('--restore-bundle' in said['md'], PW in said['md']), (True, False))
    # A file sent from the page, put back.
    daemon.save_settings({'block_tries': 7}, by='boss')
    st, said = call('/api/rbackup/upload', session=tok['boss'], raw=blob)
    ok('a file sent from the page: what it is, read', (st, said.get('locked'),
                                                       said.get('manifest', {}).get('host')),
       (200, True, isemon.rb_host()))
    st, said = call('/api/rbackup/upload', session=tok['boss'], raw=b'not a backup at all')
    ok('...something else is refused', st, 400)
    st, said2 = call('/api/rbackup', {'action': 'restore', 'upload': '0' * 16}, tok['boss'])
    ok('...a file that was never sent is not put back', st, 400)
    st, said2 = call('/api/rbackup', {'action': 'restore', 'upload': '../settings.key'},
                     tok['boss'])
    ok('...nor anything that is not the name of one', st, 400)
    st, up = call('/api/rbackup/upload', session=tok['boss'], raw=blob)
    st, said = call('/api/rbackup', {'action': 'restore', 'upload': up['upload']}, tok['boss'])
    ok('put back: a job', (st, bool(said.get('job_id'))), (200, True))
    job = wait(tok['boss'], said.get('job_id'))
    ok('...that finishes', (job or {}).get('ok'), True)
    if job and not job.get('ok'):
        print(job.get('error'))
    ok('...a copy of what it replaced made first', 'before-restore' in
       ((job or {}).get('result') or {}).get('safety', ''))
    ok('...the settings are the backup\'s again', int(isemon.CONFIG.get('block_tries')),
       int(isemon.DEFAULTS['block_tries']))
    ok('...the file sent is gone', (state / 'rbackup-uploads' / up['upload']).exists(), False)
    st, said = call('/api/rbackup', {'action': 'restore', 'upload': up['upload']}, tok['boss'])
    ok('...and cannot be put back twice', st, 400)
    st, said = call('/api/rbackup', {'action': 'runs_forget', 'all': 1}, tok['boss'])
    ok('the list of what was sent can be emptied', (st, said['runs']), (200, []))
    ok('...the backups stay where they went', newest in os.listdir(str(dest)))
    isemon.CONFIG['rbackup_password'] = ''
    st, said = call('/api/rbackup', {'action': 'here'}, tok['boss'])
    ok('without a password, Download one here is refused', st, 400)
    isemon.CONFIG['rbackup_password'] = PW
    api.stop() if hasattr(api, 'stop') else None

    # ------------------------------------------------------------------------
    print('\nThe schedule, from the daemon\'s minute')
    isemon.CONFIG.update({'rbackup': 1, 'rbackup_at': '00:00', 'rbackup_every': 'daily'})
    store.drop_meta('rbackup_day')
    before = len(isemon.rb_history(store))
    isemon.rb_tick(daemon)
    job = isemon.rb_job_of(daemon)
    for _ in range(400):
        if job['done']:
            break
        time.sleep(0.25)
    ok('due: one is made and sent', (job['done'], job['ok'], len(isemon.rb_history(store))),
       (True, True, before + 1))
    ok('...by the schedule', isemon.rb_history(store)[0]['by'], 'isemon (scheduled)')
    isemon.rb_tick(daemon)
    ok('...and only once that day', isemon.rb_job_of(daemon)['id'], job['id'])
    isemon.CONFIG['rbackup'] = 0

    # ------------------------------------------------------------------------
    print('\nThe command line')
    held_env = dict(os.environ, ISEMON_CONFIG=str(fresh / 'config.json'), ISEMON_STATE=str(fresh))
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--rbackup-status', env=held_env,
             timeout=120)
    ok('--rbackup-status says the destinations', (got.returncode, 'NAS' in got.stdout), (0, True))
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--help', timeout=60)
    ok('--help names the three', all(x in got.stdout for x in (
        '--restore-bundle', '--rbackup-now', '--rbackup-status', '--passphrase-file')))

    # ------------------------------------------------------------------------
    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('the pane is drawn by loadRbackup', 'function loadRbackup()' in page and
       'id="rb-top"' in page and 'id="sect-backup"' in page)
    ok('its settings are in its pane', "backup:  ['rbackup', 'rbackup_what', 'rbackup_at'" in page)
    ok('a backup is sent as the file itself with a header of ours, never multipart',
       "'X-Isemon-Rbackup': '1', 'Content-Type': 'application/octet-stream'" in page and
       "$what === 'rbackup-upload' && strpos($kind, 'application/octet-stream') === 0" in page)
    ok('...and its size is held to a limit', "isemon_take_body(4 * 1024 * 1024 * 1024)" in page
       and "$what === 'rbackup-upload' && $told <= 4 * 1024 * 1024 * 1024" in page)
    ok('a download is piped, never held', "isemon_pipe('/api/rbackup/download?made='" in page)
    php = shutil.which('php')
    if php:
        ok('index.php parses', sh(php, '-l', str(ROOT / 'web' / 'index.php')).returncode, 0)
    doc = (ROOT / 'docs' / 'remote-backups.md')
    ok('the doc is there', doc.exists() and '--restore-bundle' in doc.read_text())
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
