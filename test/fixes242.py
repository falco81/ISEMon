#!/usr/bin/env python3
"""1.10.242: Settings - System updates and Settings - SSH keys of root from the
command line and from `isemon --console`, as the pages have them.

A daemon and its API in a folder of the test's own, with root's half
(isemon_web.py) run for real by a thread that plays isemon-web.path: the
package manager is a small script of the test's (ISEMON_OSUP_PM), root's
authorized_keys a file of the test's (ISEMON_ROOT_AUTHKEYS), sshd a script
(ISEMON_SSHD), a restart a new boot time (ISEMON_BTIME_FILE). The commands
are run as `isemon` runs them, against that API; the console's menu items
are walked with their windows answered by the test.

    ./test/fixes242.py
"""
import argparse
import builtins
import contextlib
import io
import json
import os
import random
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

if not shutil.which('ssh-keygen'):
    print('ssh-keygen is needed for this test (dnf install openssh-clients)')
    sys.exit(1)

work = Path(tempfile.mkdtemp(prefix='isemon-242-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
PM_STATE = work / 'pm.json'
PM = work / 'fake-dnf'
LOCK = work / 'osup.lock'
POWER = work / 'power.log'
BTIME = work / 'btime'
BTIME.write_text('1000\n')
AUTH = work / 'root' / '.ssh' / 'authorized_keys'
(work / 'root').mkdir()
SSHD = work / 'sshd'
SSHD.write_text('#!/bin/sh\n[ "$1" = "-T" ] || exit 1\n'
                'printf "port 2222\\npermitrootlogin prohibit-password\\n'
                'pubkeyauthentication yes\\npasswordauthentication no\\n"\n')
SSHD.chmod(0o755)

os.environ.update(ISEMON_WEB_HELPER='1', ISEMON_BTIME_FILE=str(BTIME))
os.environ.pop('ISEMON_KEY_PASSPHRASE', None)
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_OSUP_PM=str(PM), ISEMON_OSUP_LOCK=str(LOCK),
                  ISEMON_POWER_CMD=str(POWER), ISEMON_RSYSLOG=str(work / 'none'),
                  ISEMON_NGINX_CONF=str(work / 'none.conf'),
                  ISEMON_ROOT_AUTHKEYS=str(AUTH), ISEMON_SSHD=str(SSHD))

PY = sys.executable
PM.write_text('''#!%s
import json, sys, time
p = %r
s = json.load(open(p))
a = sys.argv[1]
if a == 'check':
    print('# Last metadata expiration check: 0:01:00 ago')
    for x in s['pk']:
        print(x)
elif a == 'upgrade':
    print('Dependencies resolved.')
    sys.stdout.flush()
    n = len(s['pk'])
    for i, x in enumerate(s['pk'], 1):
        time.sleep(s.get('slow', 0))
        print('  Upgrading        : %%s   %%d/%%d' %% (x.split()[0], i, n))
        sys.stdout.flush()
        if s.get('fail') and i == n:
            print('Error: Transaction test error: file /x conflicts')
            sys.exit(1)
    print('Complete!')
    if s.get('needs_after'):
        s['needs'] = True
    s['pk'] = []
    json.dump(s, open(p, 'w'))
elif a == 'needs-restart':
    sys.exit(1 if s.get('needs') else 0)
else:
    sys.exit(2)
''' % (PY, str(PM_STATE)))
PM.chmod(0o755)
PKGS = ['kernel-core.x86_64 5.14.0-503.el9', 'openssl.x86_64 3.2.2-6.el9 security',
        'nginx.x86_64 1.20.1-20.el9']


def pm(**kw):
    s = json.loads(PM_STATE.read_text()) if PM_STATE.exists() else {}
    s.update(kw)
    PM_STATE.write_text(json.dumps(s))


pm(pk=PKGS, needs=False)


def keypair(name, *how, pw=''):
    path = work / name
    subprocess.run(['ssh-keygen', '-q'] + list(how) + ['-N', pw, '-C', name, '-f', str(path)],
                   check=True, capture_output=True)
    fp = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(path) + '.pub'],
                        capture_output=True, text=True).stdout.split()[1]
    return path, (work / (name + '.pub')).read_text().strip(), fp


A_FILE, A, A_FP = keypair('alice@laptop', '-t', 'ed25519')
B_FILE, B, B_FP = keypair('bob@desk', '-t', 'ed25519')
_, WEAK, _ = keypair('old@box', '-t', 'rsa', '-b', '2048')
R_FILE, RSA3K, RSA3K_FP = keypair('rsa@box', '-t', 'rsa', '-b', '3072')
L_FILE, LOCKED, LOCKED_FP = keypair('locked@laptop', '-t', 'ed25519', pw='sesame-242')
L2_FILE, LOCKED2, LOCKED2_FP = keypair('locked2@laptop', '-t', 'ed25519', pw='sesame-242')

import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19700 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def wait_for(fn, secs=30):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.1)
    return False


isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
isemon.OSUP_GRACE_S = 2
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
np = daemon.netpower
STOP = threading.Event()


def run_helper():
    return subprocess.run(['python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py')],
                          capture_output=True, text=True, env=HELPER_ENV)


def path_unit():
    """isemon-web.path: what is asked handed to root's helper at once."""
    while not STOP.is_set():
        if any(os.path.lexists(str(state / 'web' / f)) for f in
               ('osup.ask', 'net.ask', 'sshkeys.ask')):
            run_helper()
        time.sleep(0.05)


def ticker():
    """The daemon's passes every few seconds - and a restart asked of root
    is a new boot time, as the machine coming back."""
    while not STOP.is_set():
        try:
            if POWER.exists() and POWER.read_text().split()[:1] == ['reboot']:
                POWER.write_text('')
                BTIME.write_text(str(float(BTIME.read_text()) + 100) + '\n')
                pm(needs=False)
                np.tick()
            isemon.osup_tick(daemon)
            isemon.sshkeys_tick(daemon.webroot)
        except Exception as e:                          # noqa: BLE001
            import traceback
            traceback.print_exc(file=sys.__stderr__)
        time.sleep(0.3)


def no_look():
    """No look for updates going on, for a whole second: one ends an update
    and is begun by the daemon a moment later, so a single glance can come
    just before it."""
    calm = [0.0]

    def still():
        if isemon.osup_check(store).get('state') == 'running':
            calm[0] = 0.0
            return False
        calm[0] = calm[0] or time.time()
        return time.time() - calm[0] >= 1.0
    wait_for(still, secs=60)


def run(fn, answers=(), **kw):
    """One command as `isemon` runs it: (exit code, what it printed).
    `answers` are what is typed at its questions, in turn."""
    ns = dict(json=False, yes=False, reboot_after=None, last=False, out=None,
              passphrase_file=None, root_key_add=None, root_key_drop=None,
              root_key_make=None)
    ns.update(kw)
    args = argparse.Namespace(**ns)
    buf = io.StringIO()
    asked = []
    queue = list(answers)
    was = builtins.input

    def typed(prompt=''):
        asked.append(prompt)
        return queue.pop(0) if queue else ''
    builtins.input = typed
    try:
        with contextlib.redirect_stdout(buf):
            rc = fn(args, isemon.Palette(False, buf), store)
    finally:
        builtins.input = was
    run.asked = asked
    return rc, buf.getvalue()


def sq(text):
    """The words with the columns' spaces squeezed out."""
    return ' '.join(text.split())


def files_blob():
    blob = b''
    for f in list(state.rglob('*')):
        if f.is_file() and not f.name.startswith('sshkeys'):
            blob += f.read_bytes()
    return blob


try:
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)
    (state / 'api-token').write_text(isemon.API_TOKEN)
    for fn in (path_unit, ticker):
        threading.Thread(target=fn, daemon=True).start()

    # ------------------------------------------------------------------------
    print('isemon --os-updates and --os-updates-check')
    rc, out = run(isemon.cmd_os_updates)
    ok('--os-updates before any look: said so', (rc, 'not looked yet' in out), (0, True))
    rc, out = run(isemon.cmd_os_updates_check)
    ok('--os-updates-check looks, followed until it is done', rc, 0)
    ok('...the package manager\'s lines shown as they came', 'kernel-core.x86_64' in out and
       'Last metadata expiration check' in out)
    ok('...then what is waiting: three, one of them security', ('updates waiting 3' in sq(out),
                                                               'of them security 1' in sq(out)),
       (True, True))
    ok('...a restart after the update, and why', 'needed after the update - kernel-core' in out)
    ok('...the packages', '• openssl.x86_64 3.2.2-6.el9' in out)
    ok('...when it was looked, and by what', ('looked ' in out, 'updated by fake'
                                              in sq(out)), (True, True))
    rc, out = run(isemon.cmd_os_updates, json=True)
    v = json.loads(out)
    ck = v['nodes'][0]['check']
    ok('--os-updates --json: the view the page reads', (rc, v['ok'], ck['count'],
                                                        ck['security'], len(ck['packages'])),
       (0, True, 3, 1, 3))
    rc, out = run(isemon.cmd_os_updates_check, json=True)
    ok('--os-updates-check --json: followed quietly, the view at the end',
       (rc, json.loads(out)['nodes'][0]['check']['state']), (0, 'done'))

    # ------------------------------------------------------------------------
    print('\nisemon --os-update: asked first, refused when the daemon refuses')
    rc, out = run(isemon.cmd_os_update, answers=['no'])
    ok('asked first, in the page\'s words, and no is no',
       (rc, 'Every package of the system is updated.' in out,
        'A restart it needs is offered when it is done.' in out,
        'This server needs a restart after this update: kernel-core.' in out,
        'nothing was done' in out, isemon.osup_plan(store)), (1, True, True, True, True, {}))
    rc, out = run(isemon.cmd_os_update, answers=['no'], reboot_after='auto')
    ok('...with --reboot-after auto it says the server restarts by itself',
       'When it needs one, the server is restarted by itself.' in out)
    np._put('power:plan', {'id': 'p', 'how': 'reboot', 'state': 'asked', 'at': time.time()})
    rc, out = run(isemon.cmd_os_update, yes=True)
    ok('a restart going on: refused, in the daemon\'s words',
       (rc, 'a restart or a power-off is going on - wait for it to end' in out,
        isemon.osup_plan(store)), (1, True, {}))
    np._put('power:plan', {})
    rc, out = run(isemon.cmd_os_update_stop)
    ok('--os-update-stop with nothing going on: the daemon\'s refusal',
       (rc, 'no update is going on' in out), (1, True))

    print('\nStopped while it waits to begin')
    isemon.OSUP_GRACE_S = 30
    res = {}
    th = threading.Thread(target=lambda: res.update(r=run(isemon.cmd_os_update, yes=True)))
    th.start()
    ok('started', wait_for(lambda: isemon.osup_plan(store).get('state') == 'running'))
    rc, out = run(isemon.cmd_os_update, yes=True)
    ok('a second one meanwhile: refused', (rc, 'an update is going on already' in out),
       (1, True))
    rc, out = run(isemon.cmd_os_update_stop)
    ok('--os-update-stop stops it', (rc, 'stopped - nothing was updated' in out), (0, True))
    th.join(30)
    rc, out = res['r']
    ok('...and the one following it says so', (rc, 'it begins in' in out,
                                               'isemon --os-update-stop' in out,
                                               'stopped before it began - nothing was updated'
                                               in out), (1, True, True, True))
    isemon.OSUP_GRACE_S = 2

    print('\nAn update that needs a restart after it, asked for')
    pm(pk=PKGS, slow=0.4, needs_after=True, needs=False)
    rc, out = run(isemon.cmd_os_update, answers=['yes'])
    ok('asked, said yes: followed until it is done', (rc, run.asked[0].strip()),
       (0, 'update this server now? type yes to go ahead:'))
    ok('...with its bar', '[#' in out and '%' in out)
    ok('...and the package manager\'s lines', ('Upgrading        : kernel-core.x86_64' in out,
                                               'Complete!' in out), (True, True))
    ok('...the result', 'updated - it needs a restart' in out)
    ok('...and how to restart', 'isemon --reboot' in out)
    ok('...nothing restarted by itself', POWER.read_text() if POWER.exists() else '', '')
    rc, out = run(isemon.cmd_os_updates)
    ok('--os-updates shows the last update', ('The update (done)' in out,
                                              'started by boss' in sq(out),
                                              'this server needs a restart' in out),
       (True, True, True))

    print('\nRestarted by itself when it needs it')
    pm(pk=PKGS[:1], slow=0.2, needs_after=True, needs=False)
    no_look()
    rc, out = run(isemon.cmd_os_update, yes=True, reboot_after='auto')
    ok('updated and restarted by itself: followed to the end', rc, 0)
    ok('...the restart said', 'updated - restarting, as it needs' in out)
    ok('...and the machine up again after it', (isemon.osup_row(store).get('said'),
                                                isemon.osup_plan(store).get('reboot')),
       ('up again after the restart', 'auto'))

    print('\nAn update that fails')
    no_look()
    pm(pk=PKGS, slow=0, fail=True, needs_after=False)
    rc, out = run(isemon.cmd_os_update, yes=True, json=True)
    v = json.loads(out)
    ok('--os-update --json: the view at the end, and it failed', (rc, v['plan']['state']),
       (1, 'failed'))
    no_look()
    rc, out = run(isemon.cmd_os_update, yes=True)
    ok('failed: said, with what the package manager said',
       (rc, 'the update failed: fake-dnf ended with 1' in out, 'Error: Transaction' in out),
       (1, True, True))
    pm(fail=False)

    # ------------------------------------------------------------------------
    print('\nisemon --root-keys')
    AUTH.parent.mkdir(mode=0o700)
    AUTH.write_text(A + '\n')
    rc, out = run(isemon.cmd_root_keys)
    ok('the keys, read afresh', (rc, 'ED25519' in out, A_FP in out, 'alice@laptop' in out),
       (0, True, True, True))
    ok('...and what sshd says', ('root may sign in prohibit-password' in sq(out),
                                 'with a password no' in sq(out), 'SSH port 2222'
                                 in sq(out), str(AUTH) in out), (True,) * 4)
    rc, out = run(isemon.cmd_root_keys, json=True)
    v = json.loads(out)
    ok('--root-keys --json', (rc, [k['fp'] for k in v['keys']], v['sshd']['port']),
       (0, [A_FP], '2222'))
    AUTH.write_text(A + '\nno-pty ' + B + '\n')
    rc, out = run(isemon.cmd_root_keys)
    ok('a key with options is marked so', [ln for ln in out.splitlines() if B_FP in ln][0]
       .rstrip().endswith('with options'))
    AUTH.write_text(A + '\n')

    print('\nisemon --root-key-add')
    rc, out = run(isemon.cmd_root_key_add, root_key_add=B)
    ok('a public line', (rc, B in AUTH.read_text(), B_FP in out), (0, True, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=str(R_FILE) + '.pub')
    ok('a .pub file', (rc, RSA3K in AUTH.read_text()), (0, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=WEAK)
    ok('a weak key: refused, said', (rc, 'too weak' in out, WEAK not in AUTH.read_text()),
       (1, True, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add='no-pty ' + B)
    ok('options before the key: refused', (rc, 'not a public key line' in out), (1, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=str(L_FILE))
    ok('a locked private key with no passphrase: said (no terminal to ask on)',
       (rc, 'passphrase' in out, LOCKED.split()[1] in AUTH.read_text()), (1, True, False))
    pp = work / 'pp'
    pp.write_text('sesame-242\n')
    rc, out = run(isemon.cmd_root_key_add, root_key_add=str(L_FILE), passphrase_file=str(pp))
    ok('...with --passphrase-file: only its public half goes in',
       (rc, LOCKED.split()[1] in AUTH.read_text(), 'private half was not kept' in out,
        'PRIVATE' in AUTH.read_text()), (0, True, True, False))
    os.environ['ISEMON_KEY_PASSPHRASE'] = 'sesame-242'
    rc, out = run(isemon.cmd_root_key_add, root_key_add=str(L2_FILE))
    os.environ.pop('ISEMON_KEY_PASSPHRASE')
    ok('...with ISEMON_KEY_PASSPHRASE too', (rc, LOCKED2.split()[1] in AUTH.read_text()),
       (0, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=str(A_FILE))
    ok('a private key file without a passphrase: its public half', (rc, 'PRIVATE' in
                                                                    AUTH.read_text()), (0, False))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=B, json=True)
    ok('--json: the keys after it', (rc, B_FP in [k['fp'] for k in json.loads(out)['keys']]),
       (0, True))

    print('\nisemon --root-key-drop')
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop=RSA3K_FP, answers=['no'])
    ok('asked first, no is no', (rc, 'Root no longer signs in with %s (rsa@box)' % RSA3K_FP
                                 in out, RSA3K in AUTH.read_text()), (1, True, True))
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop=RSA3K_FP, answers=['yes'])
    ok('yes: taken away', (rc, RSA3K not in AUTH.read_text(), len(run.asked)), (0, True, 1))
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop='SHA256:' + 'x' * 43, yes=True)
    ok('a fingerprint of no key: said', (rc, 'no key of root has the fingerprint' in out),
       (1, True))
    for fp in (B_FP, LOCKED_FP, LOCKED2_FP):
        rc, out = run(isemon.cmd_root_key_drop, root_key_drop=fp, yes=True)
    ok('--yes: not asked', (rc, run.asked, [k for k in AUTH.read_text().split('\n') if k]),
       (0, [], [A]))
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop=A_FP, yes=True)
    ok('the last key without --last: refused here, said', (rc, 'is the last key root signs in '
                                                           'with' in out, '--last' in out,
                                                           A in AUTH.read_text()),
       (1, True, True, True))
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop=A_FP, last=True, answers=['yes', 'no'])
    ok('with --last: asked twice, as the page asks - no the second time is no',
       (rc, len(run.asked), 'take the last key away anyway?' in run.asked[1],
        'Said again:' in out, A in AUTH.read_text()), (1, 2, True, True, True))
    rc, out = run(isemon.cmd_root_key_drop, root_key_drop=A_FP, last=True, answers=['yes', 'yes'])
    ok('...yes twice: the last key goes', (rc, A in AUTH.read_text()), (0, False))

    print('\nisemon --root-key-make')
    AUTH.write_text(B + '\n')
    keyfile = work / 'out' / 'isemon-root'
    keyfile.parent.mkdir()
    rc, out = run(isemon.cmd_root_key_make, root_key_make='ed25519', out=str(keyfile))
    made = keyfile.read_text()
    ok('made: the private half into --out, 0600', (rc, 'OPENSSH PRIVATE KEY' in made,
                                                   stat.S_IMODE(keyfile.stat().st_mode)),
       (0, True, 0o600))
    ok('...not printed', 'PRIVATE KEY' in out, False)
    pub = subprocess.run(['ssh-keygen', '-y', '-f', str(keyfile)], capture_output=True,
                         text=True).stdout.split()[1]
    ok('...its public half in root\'s authorized_keys, the old key kept',
       (pub in AUTH.read_text(), B in AUTH.read_text()), (True, True))
    ok('...its fingerprint said', 'fingerprint SHA256:' in sq(out) and
       'its public half is in root\'s authorized_keys' in out)
    rc, out2 = run(isemon.cmd_root_keys)
    ok('--root-keys marks it made here', 'made here' in out2)
    rc, out = run(isemon.cmd_root_key_make, root_key_make='ed25519', out=str(keyfile))
    ok('--out a file that is there: refused, nothing made, the file as it was',
       (rc, 'is there already' in out, keyfile.read_text() == made,
        len([x for x in AUTH.read_text().split('\n') if x])), (1, True, True, 2))
    link = work / 'out' / 'link'
    link.symlink_to(work / 'out' / 'elsewhere')
    rc, out = run(isemon.cmd_root_key_make, root_key_make='ed25519', out=str(link))
    ok('...nor through a link', (rc, (work / 'out' / 'elsewhere').exists()), (1, False))
    rc, out = run(isemon.cmd_root_key_make, root_key_make='rsa4096')
    ok('without --out: printed once', (rc, 'BEGIN OPENSSH PRIVATE KEY' in out,
                                       'it is not shown again' in out), (0, True, True))
    rc, out = run(isemon.cmd_root_key_make, root_key_make='ed25519', json=True)
    v = json.loads(out)
    ok('--json without --out: the private half in it, once', (rc, 'PRIVATE KEY' in v['private'],
                                                               v['fp'].startswith('SHA256:')),
       (0, True, True))
    keyfile2 = work / 'out' / 'second'
    rc, out = run(isemon.cmd_root_key_make, root_key_make='ed25519', out=str(keyfile2),
                  json=True)
    v = json.loads(out)
    ok('--json with --out: no private half in it', (rc, 'private' in v, v['out']),
       (0, False, str(keyfile2)))
    blob = files_blob()
    ok('no private key, nor a passphrase, in the database, the log or any file of the '
       'daemon\'s', (b'PRIVATE KEY' in blob, made.split('\n')[1].encode() in blob,
                     b'sesame-242' in blob), (False, False, False))

    # ------------------------------------------------------------------------
    print('\nOnly a full administrator')
    real = isemon.cli_session
    isemon.cli_session = lambda st, name='root': store.new_session('watcher', 'readonly',
                                                                   'command line', 'isemon-cli')
    before = AUTH.read_text()
    for what, fn, kw in (('--root-keys', isemon.cmd_root_keys, {}),
                         ('--root-key-add', isemon.cmd_root_key_add, {'root_key_add': A}),
                         ('--root-key-drop', isemon.cmd_root_key_drop, {'root_key_drop': B_FP,
                                                                        'yes': True}),
                         ('--root-key-make', isemon.cmd_root_key_make,
                          {'root_key_make': 'ed25519'}),
                         ('--os-updates-check', isemon.cmd_os_updates_check, {}),
                         ('--os-update', isemon.cmd_os_update, {'yes': True}),
                         ('--os-update-stop', isemon.cmd_os_update_stop, {})):
        rc, out = run(fn, **kw)
        ok('a read-only account may not %s' % what, (rc, 'PRIVATE' in out), (1, False))
    ok('...and nothing changed', AUTH.read_text(), before)
    rc, out = run(isemon.cmd_os_updates)
    ok('...it may look at the updates, as on the page', rc, 0)
    isemon.cli_session = real
    db = sqlite3.connect(str(isemon.DB_FILE))
    db.execute("UPDATE users SET disabled=1 WHERE role='fulladmin'")
    db.commit()
    db.close()
    rc, out = run(isemon.cmd_root_key_add, root_key_add=A)
    ok('with no full administrator at all: refused', (rc, A in AUTH.read_text()), (1, False))
    db = sqlite3.connect(str(isemon.DB_FILE))
    db.execute("UPDATE users SET disabled=0")
    db.commit()
    db.close()

    print('\nWithout root\'s half')
    os.environ['ISEMON_WEB_HELPER'] = '0'
    rc, out = run(isemon.cmd_os_update, yes=True)
    ok('--os-update says what to run', (rc, './install.sh --upgrade' in out), (1, True))
    rc, out = run(isemon.cmd_root_keys)
    ok('--root-keys says what to run', (rc, './install.sh --upgrade' in out), (1, True))
    rc, out = run(isemon.cmd_root_key_add, root_key_add=A)
    ok('--root-key-add: the daemon\'s refusal', (rc, 'install.sh --upgrade' in out), (1, True))
    os.environ['ISEMON_WEB_HELPER'] = '1'
    api.stop() if hasattr(api, 'stop') else None

    # ------------------------------------------------------------------------
    print('\nThe parser and --help')
    parser = isemon.cli_parser()
    for argv in (['--os-updates'], ['--os-updates-check', '--json'],
                 ['--os-update', '--reboot-after', 'auto', '--yes'], ['--os-update-stop'],
                 ['--root-keys', '--json'], ['--root-key-add', A],
                 ['--root-key-add', '/root/k', '--passphrase-file', '/root/pp'],
                 ['--root-key-drop', A_FP, '--last', '--yes'],
                 ['--root-key-make', 'rsa4096', '--out', '/root/k']):
        try:
            parser.parse_args(argv)
            ok('isemon %s parses' % ' '.join(argv[:2]), True)
        except SystemExit:
            ok('isemon %s parses' % ' '.join(argv[:2]), False)
    for argv in (['--os-update', '--reboot-after', 'never'], ['--root-key-make', 'dsa']):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(argv)
            ok('isemon %s is refused' % ' '.join(argv), False)
        except SystemExit:
            ok('isemon %s is refused' % ' '.join(argv), True)
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                         capture_output=True, text=True)
    ok('--help works, and has them all', (got.returncode, all(
        x in got.stdout for x in ('--os-updates ', '--os-updates-check', '--os-update ',
                                  '--reboot-after', '--os-update-stop', '--root-keys',
                                  '--root-key-add', '--root-key-drop', '--last',
                                  '--root-key-make', '--out'))), (0, True))
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--reboot-after', 'ask'],
                         capture_output=True, text=True)
    ok('--reboot-after alone does nothing, and says so', (got.returncode,
                                                         'nothing was asked for' in got.stderr),
       (2, True))

    # ------------------------------------------------------------------------
    print('\nThe console: Network, time and power')
    known = isemon.cli_options()

    class Dry(isemon.Console):
        def __init__(self):
            super(Dry, self).__init__(isemon.Palette(False))
            self.ran, self.picks, self.asks, self.items, self.keys = [], {}, {}, None, []
            self.said = []

        def out(self, *args):
            if args[0] == '--root-keys':
                return {'keys': self.keys, 'helper': True}
            if args[0] == '--os-updates':
                return {'nodes': [{'check': {'reboot_after': True, 'count': 2,
                                             'reboot_why': ['kernel-core']}}]}
            return None

        def sub(self, title_, items):
            self.items = (title_, items)

        def choose(self, title_, options, words='', cur=0):
            want = self.picks.get(title_)
            vals = [o[0] for o in options]
            return want if want in vals else (vals[0] if vals and want is None else None)

        def confirm(self, title_, words, yes='Yes', no='No', danger=False):
            self.said.append((title_, words))
            return True

        def ask_one(self, title_, label, value='', help_='', need=True, secret=False,
                    check=None):
            got = self.asks.get(label, value)
            if check and got is not None and check(got, {}):
                return None
            return got

        def note(self, *a, **k):
            self.said.append(a)

        def working(self, *a):
            pass

        def act(self, *args, env=None, title=None, quiet_ok=None):
            self.ran.append((tuple(str(a) for a in args), env, 'act'))

        def show_live(self, *args, env=None):
            self.ran.append((tuple(str(a) for a in args), env, 'live'))

        def go_plain(self, fn):
            return fn()

    d = Dry()
    d.m_machine()
    title_, items = d.items
    names = {it[1]: it for it in items}
    ok('System updates and SSH keys of root in it', ('System updates' in names,
                                                     'SSH keys of root' in names), (True, True))
    ok('...after what was there, numbered on', [it[0] for it in items],
       ['0', '1', '2', '3', '4', '5', '6', '7'])

    def walk(item, picks=None, asks=None, keys=None):
        d.ran, d.said = [], []
        d.picks, d.asks, d.keys = picks or {}, asks or {}, keys or []
        names[item][2]()
        return [(a, e, h) for a, e, h in d.ran]
    ok('System updates > show', walk('System updates', {'System updates': 'show'}),
       [(('--os-updates',), None, 'act')])
    ok('...look for updates, followed', walk('System updates', {'System updates': 'check'}),
       [(('--os-updates-check',), None, 'live')])
    for how in ('ask', 'auto'):
        got = walk('System updates', {'System updates': 'update', 'After the update': how})
        ok('...update, %s: confirmed first, then followed' % how,
           (got, 'This server needs a restart after this update: kernel-core.' in d.said[0][1]),
           ([(('--os-update', '--reboot-after', how, '--yes'), None, 'live')], True))
    ok('...the words of the page in the confirmation', 'restarted by itself' in d.said[0][1])
    ok('...nothing without a choice of the restart',
       walk('System updates', {'System updates': 'update', 'After the update': 'x'}), [])
    ok('...stop', walk('System updates', {'System updates': 'stop'}),
       [(('--os-update-stop',), None, 'act')])
    ok('SSH keys of root > list', walk('SSH keys of root', {'SSH keys of root': 'list'}),
       [(('--root-keys',), None, 'act')])
    ok('...add a pasted line', walk('SSH keys of root', {'SSH keys of root': 'add'},
                                    {'the key line or a file': B}),
       [(('--root-key-add', B), None, 'act')])
    got = walk('SSH keys of root', {'SSH keys of root': 'add'},
               {'the key line or a file': str(L_FILE), 'the passphrase': 'sesame-242'})
    ok('...add a private key file: its passphrase by the environment, never the command line',
       got, [(('--root-key-add', str(L_FILE)), {'ISEMON_KEY_PASSPHRASE': 'sesame-242'},
              'act')])
    two = [{'fp': A_FP, 'type': 'ED25519', 'comment': 'alice'},
           {'fp': B_FP, 'type': 'ED25519', 'comment': 'bob'}]
    got = walk('SSH keys of root', {'SSH keys of root': 'drop', 'Take a key away': B_FP},
               keys=two)
    ok('...take a key away: confirmed once', (got, len(d.said)),
       ([(('--root-key-drop', B_FP, '--yes'), None, 'act')], 1))
    got = walk('SSH keys of root', {'SSH keys of root': 'drop', 'Take a key away': A_FP},
               keys=two[:1])
    ok('...the last one: confirmed twice, and --last', (got, [s[0] for s in d.said]),
       ([(('--root-key-drop', A_FP, '--last', '--yes'), None, 'act')],
        ['Take the key away', 'Take the last key away?']))
    ok('...no key read: nothing run', walk('SSH keys of root', {'SSH keys of root': 'drop'}), [])
    newfile = str(work / 'out' / 'console-key')
    got = walk('SSH keys of root', {'SSH keys of root': 'make', 'Make a key for root': 'rsa4096'},
               {'into the file': newfile})
    ok('...make a key, its private half into the file asked for', got,
       [(('--root-key-make', 'rsa4096', '--out', newfile), None, 'act')])
    ok('...never over a file that is there', walk(
        'SSH keys of root', {'SSH keys of root': 'make'}, {'into the file': str(keyfile)}), [])
    all_args = []
    for item, picks, asks, keys in (
            ('System updates', {'System updates': 'show'}, {}, []),
            ('System updates', {'System updates': 'update', 'After the update': 'auto'}, {}, []),
            ('System updates', {'System updates': 'stop'}, {}, []),
            ('SSH keys of root', {'SSH keys of root': 'add'}, {'the key line or a file': B}, []),
            ('SSH keys of root', {'SSH keys of root': 'drop', 'Take a key away': A_FP}, {},
             two[:1]),
            ('SSH keys of root', {'SSH keys of root': 'make'}, {'into the file': newfile}, [])):
        all_args += [a for a, _e, _h in walk(item, picks, asks, keys)]
    ok('every command the items run is in this version and parses',
       [a for a in all_args if isemon.cli_missing(a, known)], [])
finally:
    STOP.set()
    time.sleep(0.3)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
