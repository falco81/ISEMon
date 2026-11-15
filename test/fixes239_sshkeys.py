#!/usr/bin/env python3
"""1.10.239: Settings → SSH keys of root, after otp's (1.0.158-1.0.161) - the
keys in /root/.ssh/authorized_keys read by root's helper (sshkeys.ask,
sshkeys.json). Since 1.10.351 root's keys are only shown: every add, drop and
make for root is refused by the API (403), the daemon and root's helper, the
file byte for byte as it was (test/fixes351_sshkeys_users.py has the keys of
the other users). The file is one in
a folder of the test's own (ISEMON_ROOT_AUTHKEYS) and sshd is a small script,
so nothing of this machine's root is read or touched. ssh-keygen is the real
one: the bits and fingerprints are what it says.

    ./test/fixes239_sshkeys.py
"""
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
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19600 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


if not shutil.which('ssh-keygen'):
    print('ssh-keygen is needed for this test (dnf install openssh-clients)')
    sys.exit(1)

work = Path(tempfile.mkdtemp(prefix='isemon-239-sshkeys-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
home = work / 'root'
home.mkdir()
SSHDIR = home / '.ssh'
AUTH = SSHDIR / 'authorized_keys'
sshd = work / 'sshd'
sshd.write_text('#!/bin/sh\n[ "$1" = "-T" ] || exit 1\n'
                'printf "port 2222\\npermitrootlogin prohibit-password\\n'
                'pubkeyauthentication yes\\npasswordauthentication no\\nx11forwarding no\\n"\n')
sshd.chmod(0o755)
ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
           ISEMON_ROOT_AUTHKEYS=str(AUTH), ISEMON_SSHD=str(sshd),
           ISEMON_NGINX_CONF=str(work / 'none.conf'))
HELPER = ROOT / 'deploy' / 'isemon_web.py'


def keypair(name, *how):
    path = work / name
    subprocess.run(['ssh-keygen', '-q'] + list(how) + ['-N', '', '-C', name, '-f', str(path)],
                   check=True, capture_output=True)
    fp = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(path) + '.pub'],
                        capture_output=True, text=True).stdout.split()[1]
    return (path.read_text(), (work / (name + '.pub')).read_text().strip(), fp)


A_PRIV, A, A_FP = keypair('alice@laptop', '-t', 'ed25519')
B_PRIV, B, B_FP = keypair('bob@desk', '-t', 'ed25519')
_, WEAK, _ = keypair('old@box', '-t', 'rsa', '-b', '2048')
_, RSA3K, RSA3K_FP = keypair('rsa@box', '-t', 'rsa', '-b', '3072')
subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', 'sesame', '-C', 'locked@laptop', '-f',
                str(work / 'locked')], check=True, capture_output=True)
LOCKED_PRIV = (work / 'locked').read_text()
LOCKED_PUB = (work / 'locked.pub').read_text().strip()


def root_runs():
    """isemon-web.service, as isemon-web.path starts it."""
    return subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True,
                          text=True)


def ask(req, fresh=True):
    if fresh and 'at' not in req:
        req = dict(req, at=time.time())
    (state / 'web' / 'sshkeys.ask').write_text(json.dumps(req))
    got = root_runs()
    if got.returncode:
        print(got.stderr)
    return json.loads((state / 'web' / 'sshkeys.json').read_text())


def mode(p):
    return stat.S_IMODE(os.lstat(str(p)).st_mode)


try:
    # ------------------------------------------------------------------------
    print('Root\'s helper')
    got = ask({'id': 'r1', 'do': 'list'})
    ok('nothing there: no keys, and nothing written for a read',
       (got['ok'], got['id'], got['data']['keys'], AUTH.exists(), SSHDIR.exists()),
       (True, 'r1', [], False, False))
    ok('what sshd says', got['data']['sshd'],
       {'there': True, 'permit_root': 'prohibit-password', 'allow_users': '', 'pubkey': 'yes',
        'password': 'no', 'port': '2222'})
    ok('the file it is', got['data']['file'], str(AUTH))

    # Root's keys only read since 1.10.351: nothing asked here changes them.
    OWN = ('# keys of root, kept by hand\n' + A + '\n'
           'from="10.0.0.0/8",no-pty ' + B.split(' ', 2)[0] + ' ' + B.split(' ', 2)[1] +
           ' bob-with-options\n'
           'something nobody understands\n')
    SSHDIR.mkdir(mode=0o700)
    AUTH.write_text(OWN)
    AUTH.chmod(0o644)
    got = ask({'id': 'r4', 'do': 'list'})
    ks = got['data']['keys']
    ok('a line with options is listed as such, a line not read too',
       [(x['options'], x['readable']) for x in ks], [(False, True), (True, True), (True, False)])
    k = ks[0]
    ok('...listed with its kind, comment and line',
       (k['type'], k['comment'], k['options'], k['text']), ('ED25519', 'alice@laptop', False, A))

    print('\nRoot\'s keys only shown (1.10.351)')
    for what, req in (('a key added', {'do': 'add', 'line': RSA3K}),
                      ('a key added, root named', {'do': 'add', 'line': RSA3K, 'user': 'root'}),
                      ('a key taken away', {'do': 'drop', 'fp': A_FP}),
                      ('the last key taken away, said again',
                       {'do': 'drop', 'fp': A_FP, 'last_ok': True}),
                      ('anything else', {'do': 'what'})):
        got = ask(dict(req, id='x'))
        ok('%s: refused with the words, the file byte for byte as it was' % what,
           (got['ok'], got['said'], AUTH.read_text(), mode(AUTH)),
           (False, isemon.ROOT_KEYS_SHOWN_ONLY, OWN, 0o644))
    src = HELPER.read_text()
    ok('no code left in the helper that writes root\'s file',
       ('def auth_write' in src, 'os.replace(tmp, ROOT_AUTH)' in src), (False, False))

    print('\nLinks')
    AUTH.unlink()
    elsewhere = work / 'elsewhere'
    elsewhere.write_text(B + '\n')
    AUTH.symlink_to(elsewhere)
    got = ask({'id': 'l1', 'do': 'list'})
    ok('authorized_keys a link: not read through it', (got['ok'], 'cannot be read' in got['said']),
       (False, True))
    AUTH.unlink()
    (state / 'web' / 'sshkeys.json').unlink()
    (state / 'web' / 'sshkeys.ask').symlink_to(work / 'elsewhere')
    root_runs()
    ok('the ask a link: taken away, never followed, not answered',
       (os.path.lexists(str(state / 'web' / 'sshkeys.ask')),
        (state / 'web' / 'sshkeys.json').exists(), elsewhere.read_text()), (False, False, B + '\n'))
    ok('nothing asked: the helper does nothing',
       (root_runs().returncode, (state / 'web' / 'sshkeys.json').exists()), (0, False))

    # ------------------------------------------------------------------------
    print('\nThe daemon')
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
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    wr = daemon.webroot
    AUTH.write_text(A + '\n')

    isemon.sshkeys_tick(wr)
    ok('nothing asked: the minute\'s pass asks root nothing',
       (isemon.SSHKEYS_WORK['busy'], (state / 'web' / 'sshkeys.ask').exists()), (False, False))

    stop = threading.Event()

    def path_unit():
        while not stop.is_set():
            if os.path.lexists(str(state / 'web' / 'sshkeys.ask')):
                root_runs()
            time.sleep(0.1)
    th = threading.Thread(target=path_unit, daemon=True)
    th.start()

    def settle(cond, s=30):
        end = time.time() + s
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def idle():
        return not isemon.SSHKEYS_WORK['busy'] and not isemon.SSHKEYS_WORK['queue']

    v = isemon.sshkeys_view(wr)
    ok('the view, never read: a read asked by itself', (v['at'], v['keys'], v['helper']),
       (None, [], True))
    ok('...and read behind', settle(lambda: idle() and isemon.SSHKEYS_WORK['now'].get('keys')))
    v = isemon.sshkeys_view(wr)
    ok('the keys there, what sshd says, the file',
       ([k['fp'] for k in v['keys']], v['sshd']['port'], v['file'], v['error'], v['pending']),
       ([A_FP], '2222', str(AUTH), '', 0))
    ok('...nothing changed for it', AUTH.read_text(), A + '\n')
    for what, args in (('a key added', ('add', 'boss', B)),
                       ('a weak RSA key', ('add', 'boss', WEAK)),
                       ('a key taken away', ('drop', 'boss', '', A_FP)),
                       ('something else', ('chmod', 'boss'))):
        try:
            isemon.sshkeys_ask(wr, *args)
            ok('the daemon refuses %s for root at once' % what, 'taken', 'refused')
        except ValueError as e:
            ok('the daemon refuses %s for root at once' % what,
               (str(e), isinstance(e, isemon.RootKeysShownOnly)) if args[0] != 'chmod'
               else True, (isemon.ROOT_KEYS_SHOWN_ONLY, True) if args[0] != 'chmod' else True)
    ok('...no ask written for any of it', (isemon.SSHKEYS_WORK['queue'], AUTH.read_text()),
       ([], A + '\n'))

    print('\nA key made here, a key given - not for root')
    for body in ({'action': 'rk_make', 'kind': 'ed25519'}, {'action': 'uk_make'},
                 {'action': 'add', 'line': LOCKED_PRIV, 'passphrase': 'sesame'},
                 {'action': 'rk_given', 'key': B}, {'action': 'rk_again'},
                 {'action': 'drop', 'fp': A_FP, 'user': 'root'}):
        try:
            x = isemon.sshkeys_api(wr, body, 'boss')
            ok('%s for root: refused' % body['action'], 'private' in x, 'refused')
        except isemon.RootKeysShownOnly:
            ok('%s for root: refused' % body['action'], True)
    settle(idle)
    ok('root\'s file as it was', AUTH.read_text(), A + '\n')
    blob = b''
    for f in state.iterdir():
        if f.is_file() and not f.name.startswith('sshkeys'):
            blob += f.read_bytes()
    ok('no private key in the database, the log or any file of the daemon\'s',
       (b'PRIVATE KEY' in blob, b'sesame' in blob), (False, False))
    db = sqlite3.connect(str(isemon.DB_FILE))
    ev = [r[0] for r in db.execute("SELECT detail FROM events WHERE kind='settings' "
                                   "ORDER BY id")]
    db.close()
    ok('no event says a key of root\'s was added, taken away or made',
       any('for root' in e for e in ev), False)

    # ------------------------------------------------------------------------
    print('\nThrough the API')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(payload).encode() if payload is not None
                                     else None, method='POST' if payload is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    ok('nobody signed in may not look', call('/api/sshkeys')[0], 401)
    ok('read only may not look either', call('/api/sshkeys', session=tok['watcher'])[0], 403)
    for act in ('refresh', 'add', 'drop', 'rk_make'):
        ok('read only may not %s' % act, call('/api/sshkeys', {'action': act, 'line': B},
                                              tok['watcher'])[0], 403)
    st, v = call('/api/sshkeys', session=tok['boss'])
    ok('a full admin looks', (st, v['ok'], v['helper'], v['keygen'], bool(v['keys'])),
       (200, True, True, True, True))
    st, v = call('/api/sshkeys', {'action': 'refresh'}, tok['boss'])
    ok('read again', (st, v['message']), (200, 'asked again'))
    settle(idle)
    for body in ({'action': 'add', 'line': RSA3K}, {'action': 'drop', 'fp': A_FP},
                 {'action': 'rk_make', 'kind': 'ed25519'}, {'action': 'uk_make'}):
        st, v = call('/api/sshkeys', body, tok['boss'])
        ok('%s for root: 403 with the words' % body['action'], (st, v.get('error')),
           (403, isemon.ROOT_KEYS_SHOWN_ONLY))
    settle(idle)
    ok('...root\'s file as it was', AUTH.read_text(), A + '\n')
    st, v2 = call('/api/sshkeys', session=tok['boss'])
    ok('...no private key anywhere', 'PRIVATE' in json.dumps(v2), False)
    st, v = call('/api/sshkeys', {'action': 'nothing', 'user': 'someone'}, tok['boss'])
    ok('nothing else to do', st, 400)
    api.stop() if hasattr(api, 'stop') else None
    stop.set()

    print('\nWithout root\'s half')
    os.environ['ISEMON_WEB_HELPER'] = '0'
    try:
        isemon.sshkeys_ask(wr, 'list', 'boss')
        ok('asking says what to run', 'asked', 'refused')
    except isemon.WebRootError as e:
        ok('asking says what to run', 'install.sh --upgrade' in str(e))
    v = isemon.sshkeys_view(wr)
    ok('the view says so', v['helper'], False)
    os.environ['ISEMON_WEB_HELPER'] = '1'

    # ------------------------------------------------------------------------
    print('\nThe files')
    unit = (ROOT / 'deploy' / 'isemon-web.path').read_text()
    ok('isemon-web.path watches sshkeys.ask', 'PathExists=/var/lib/isemon/web/sshkeys.ask' in unit)
    php = (ROOT / 'web' / 'index.php').read_text()
    ok('?api=sshkeys read and written', php.count("'sshkeys'      => '/api/sshkeys',") >= 1 or
       "'/api/sshkeys'" in php)
    srv = php[php.index('<div class="ctl-group">Server</div>'):]
    srv = srv[:srv.index('<div class="ctl-group">', 10)]
    ok('the pane under Server, for a full admin',
       'class="admin-only" data-pane="sshkeys" data-icon="key"' in srv and
       ('>SSH keys of root</button>' in srv or '>SSH keys</button>' in srv))
    doc = (ROOT / 'docs' / 'ssh-keys.md').read_text()
    ok('docs/ssh-keys.md', all(x in doc for x in ('/root/.ssh/authorized_keys', '0600', '0700',
                                                 'sshkeys.ask', 'Make a key', 'Add a key',
                                                 '3072', 'only shown', '403')))
    ok('docs/ssh-keys-of-root.md says where it went',
       'ssh-keys.md' in (ROOT / 'docs' / 'ssh-keys-of-root.md').read_text())
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
