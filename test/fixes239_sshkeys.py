#!/usr/bin/env python3
"""1.10.239: Settings → SSH keys of root, after otp's (1.0.158-1.0.161) - the
keys in /root/.ssh/authorized_keys read, added and taken away by root's
helper (sshkeys.ask, sshkeys.json); a key made here shown once and kept
nowhere; a private key given leaves only its public half. The file is one in
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
       {'there': True, 'permit_root': 'prohibit-password', 'pubkey': 'yes', 'password': 'no',
        'port': '2222'})
    ok('the file it is', got['data']['file'], str(AUTH))
    got = ask({'id': 'r2', 'do': 'add', 'line': A})
    ok('a key added', (got['ok'], [k['fp'] for k in got['data']['keys']]), (True, [A_FP]))
    ok('...its folder made 0700, the file 0600', (mode(SSHDIR), mode(AUTH)), (0o700, 0o600))
    ok('...the file is the line', AUTH.read_text(), A + '\n')
    k = got['data']['keys'][0]
    ok('...listed with its kind, comment and line',
       (k['type'], k['comment'], k['options'], k['text']), ('ED25519', 'alice@laptop', False, A))
    got = ask({'id': 'r3', 'do': 'add', 'line': A})
    ok('the same key again is no fault, and not there twice',
       (got['ok'], AUTH.read_text().count('alice@laptop')), (True, 1))

    OWN = ('# keys of root, kept by hand\n' + A + '\n'
           'from="10.0.0.0/8",no-pty ' + B.split(' ', 2)[0] + ' ' + B.split(' ', 2)[1] +
           ' bob-with-options\n'
           'something nobody understands\n')
    AUTH.write_text(OWN)
    AUTH.chmod(0o644)
    got = ask({'id': 'r4', 'do': 'list'})
    ks = got['data']['keys']
    ok('a line with options is listed as such, a line not read too',
       [(x['options'], x['readable']) for x in ks], [(False, True), (True, True), (True, False)])
    got = ask({'id': 'r5', 'do': 'add', 'line': RSA3K})
    ok('an RSA key of 3072 bits is taken', (got['ok'], RSA3K_FP in [x['fp'] for x in
                                                                   got['data']['keys']]),
       (True, True))
    ok('...every line it does not understand kept as it was',
       AUTH.read_text(), OWN + RSA3K + '\n')
    ok('...written as a new file of 0600', mode(AUTH), 0o600)

    print('\nRefused')
    before = AUTH.read_text()
    for what, line, said in (
            ('an RSA key under 3072 bits', WEAK, 'too weak'),
            ('a DSA key', 'ssh-dss ' + 'A' * 60 + ' old', 'not one public key line'),
            ('options before the key', 'no-pty ' + B, 'not one public key line'),
            ('two lines', A + '\n' + B, 'not one public key line'),
            ('a private key', A_PRIV, 'not one public key line'),
            ('a line ssh-keygen does not read', 'ssh-ed25519 ' + 'A' * 68 + ' x',
             'does not read')):
        got = ask({'id': 'x', 'do': 'add', 'line': line})
        ok('%s: refused, the file as it was' % what,
           (got['ok'], said in got.get('said', ''), AUTH.read_text()), (False, True, before))
    got = ask({'id': 'x', 'do': 'what'})
    ok('nothing else may be asked', (got['ok'], got['said']), (False, 'list, add or drop'))
    got = ask({'id': 'x', 'do': 'add', 'line': B, 'at': time.time() - 3600}, fresh=False)
    ok('a change asked long ago is not done',
       (got['ok'], 'too long ago' in got['said'], AUTH.read_text()), (False, True, before))
    got = ask({'id': 'x', 'do': 'add', 'line': B}, fresh=False)
    ok('...nor one that does not say when', got['ok'], False)
    got = ask({'id': 'x', 'do': 'drop', 'fp': 'SHA256:nothere'})
    ok('a key that is not there is not taken away', (got['ok'], 'no key' in got['said']),
       (False, True))

    print('\nTaking keys away')
    got = ask({'id': 'd1', 'do': 'drop', 'fp': RSA3K_FP})
    ok('a key taken away, everything else kept',
       (got['ok'], AUTH.read_text()), (True, OWN))
    AUTH.write_text(A + '\n')
    got = ask({'id': 'd2', 'do': 'drop', 'fp': A_FP})
    ok('the last key is not taken away unless said again',
       (got['ok'], 'last key' in got['said'], AUTH.read_text()), (False, True, A + '\n'))
    got = ask({'id': 'd3', 'do': 'drop', 'fp': A_FP, 'last_ok': 'yes'})
    ok('..."yes" is not said again', (got['ok'], AUTH.read_text()), (False, A + '\n'))
    got = ask({'id': 'd4', 'do': 'drop', 'fp': A_FP, 'last_ok': True})
    ok('...said again, it goes', (got['ok'], got['data']['keys'], AUTH.read_text()),
       (True, [], '\n'))

    print('\nLinks')
    AUTH.unlink()
    elsewhere = work / 'elsewhere'
    elsewhere.write_text(B + '\n')
    AUTH.symlink_to(elsewhere)
    got = ask({'id': 'l1', 'do': 'list'})
    ok('authorized_keys a link: not read through it', (got['ok'], 'cannot be read' in got['said']),
       (False, True))
    got = ask({'id': 'l2', 'do': 'add', 'line': A})
    ok('...nor written through it', (got['ok'], elsewhere.read_text(), AUTH.is_symlink()),
       (False, B + '\n', True))
    AUTH.unlink()
    shutil.rmtree(str(SSHDIR))
    other = work / 'other-ssh'
    other.mkdir()
    SSHDIR.symlink_to(other)
    got = ask({'id': 'l3', 'do': 'add', 'line': A})
    ok('.ssh a link: nothing written there', (got['ok'], 'not a plain folder' in got['said'],
                                              os.listdir(str(other))), (False, True, []))
    SSHDIR.unlink()
    SSHDIR.mkdir(mode=0o700)
    (state / 'web' / 'sshkeys.json').unlink()
    (state / 'web' / 'sshkeys.ask').symlink_to(work / 'elsewhere')
    root_runs()
    ok('the ask a link: taken away, never followed, not answered',
       (os.path.lexists(str(state / 'web' / 'sshkeys.ask')),
        (state / 'web' / 'sshkeys.json').exists(), elsewhere.read_text()), (False, False, B + '\n'))
    ok('nothing asked: the helper does nothing',
       (root_runs().returncode, (state / 'web' / 'sshkeys.json').exists()), (0, False))
    got = ask({'id': 'l4', 'do': 'add', 'line': A})
    ok('a plain folder again: written', (got['ok'], mode(AUTH)), (True, 0o600))

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

    isemon.sshkeys_ask(wr, 'add', 'boss', line=B)
    ok('a key added behind',
       settle(lambda: idle() and B_FP in [k['fp'] for k in isemon.SSHKEYS_WORK['now']['keys']]))
    ok('...into the file', AUTH.read_text(), A + '\n' + B + '\n')
    for what, args in (('a weak RSA key', ('add', 'boss', WEAK)),
                       ('options before it', ('add', 'boss', 'no-pty ' + B)),
                       ('a private key as a line', ('add', 'boss', A_PRIV)),
                       ('something else', ('chmod', 'boss')),
                       ('a drop of no fingerprint', ('drop', 'boss', '', 'x'))):
        try:
            isemon.sshkeys_ask(wr, *args)
            ok('the daemon refuses %s at once' % what, 'taken', 'refused')
        except ValueError:
            ok('the daemon refuses %s at once' % what, True)
    isemon.sshkeys_ask(wr, 'drop', 'boss', fp=A_FP)
    ok('a key taken away behind', settle(lambda: idle() and [
        k['fp'] for k in isemon.SSHKEYS_WORK['now']['keys']] == [B_FP]))
    isemon.sshkeys_ask(wr, 'drop', 'boss', fp=B_FP)
    settle(idle)
    v = isemon.sshkeys_view(wr)
    ok('the last one: refused, said, still there',
       ('last key' in v['error'], [k['fp'] for k in v['keys']], AUTH.read_text()),
       (True, [B_FP], B + '\n'))
    isemon.sshkeys_ask(wr, 'list', 'boss')
    settle(idle)
    ok('...said over the read after it', 'last key' in isemon.sshkeys_view(wr)['error'])

    print('\nA key made here, a key given')
    x = isemon.sshkeys_api(wr, {'action': 'rk_make', 'kind': 'ed25519'}, 'boss')
    ok('made: the private half handed over, the public half and its fingerprint',
       ('PRIVATE KEY' in x['private'], x['pub'].startswith('ssh-ed25519 '),
        x['fp'].startswith('SHA256:'), x['file'].startswith('isemon-root-')),
       (True, True, True, True))
    ok('...its public half goes in', settle(lambda: idle() and x['fp'] in [
        k['fp'] for k in isemon.SSHKEYS_WORK['now']['keys']]))
    v = isemon.sshkeys_view(wr)
    ok('...remembered as made here, and on', (v['kept']['fp'], v['kept']['how'], v['kept']['on']),
       (x['fp'], 'made', True))
    ok('...B still there: a key made does not take the old one away',
       sorted(k['fp'] for k in v['keys']) == sorted([B_FP, x['fp']]))
    x2 = isemon.sshkeys_api(wr, {'action': 'rk_make', 'kind': 'rsa4096'}, 'boss')
    ok('RSA 4096 made too', settle(lambda: idle() and x2['fp'] in [
        k['fp'] for k in isemon.SSHKEYS_WORK['now']['keys']]))
    ok('...4096 bits', [k['bits'] for k in isemon.SSHKEYS_WORK['now']['keys']
                        if k['fp'] == x2['fp']], [4096])
    try:
        isemon.sshkeys_api(wr, {'action': 'rk_make', 'kind': 'dsa'}, 'boss')
        ok('no other kind is made', 'made', 'refused')
    except ValueError:
        ok('no other kind is made', True)
    got = isemon.sshkeys_api(wr, {'action': 'add', 'line': LOCKED_PRIV, 'passphrase': 'sesame'},
                             'boss')
    ok('a private key with its passphrase: only its public half goes in',
       ('private half was not kept' in got['message'],
        settle(lambda: idle() and LOCKED_PUB.split()[1] in AUTH.read_text())), (True, True))
    try:
        isemon.sshkeys_api(wr, {'action': 'add', 'line': LOCKED_PRIV}, 'boss')
        ok('...without it, said', 'taken', 'refused')
    except ValueError as e:
        ok('...without it, said', 'passphrase' in str(e))
    got = isemon.sshkeys_api(wr, {'action': 'add', 'line': A_PRIV}, 'boss')
    settle(lambda: idle() and A.split()[1] in AUTH.read_text())
    ok('a private key without one: its public half', A.split()[1] in AUTH.read_text())
    ok('no private key anywhere in root\'s file', 'PRIVATE' in AUTH.read_text(), False)
    blob = b''
    for f in state.iterdir():
        if f.is_file() and not f.name.startswith('sshkeys'):
            blob += f.read_bytes()
    ok('no private key in the database, the log or any file of the daemon\'s',
       (b'PRIVATE KEY' in blob, x['private'].split('\n')[1].encode() in blob,
        b'sesame' in blob), (False, False, False))
    db = sqlite3.connect(str(isemon.DB_FILE))
    ev = [r[0] for r in db.execute("SELECT detail FROM events WHERE kind='settings' "
                                   "ORDER BY id")]
    db.close()
    ok('every change an event', (any('boss added the SSH key bob@desk for root' in e for e in ev),
                                 any('boss took away the SSH key %s for root' % A_FP in e
                                     for e in ev),
                                 any('was not taken away for root' in e and 'last key' in e
                                     for e in ev),
                                 any('made a new SSH key for root (%s)' % x['fp'] in e
                                     for e in ev)),
       (True, True, True, True))
    ok('...and none of them carries a private key', any('PRIVATE' in e for e in ev), False)

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
    st, v = call('/api/sshkeys', {'action': 'add', 'line': WEAK}, tok['boss'])
    ok('a weak key: said at once', (st, 'too weak' in v.get('error', '')), (400, True))
    st, v = call('/api/sshkeys', {'action': 'add', 'line': RSA3K}, tok['boss'])
    ok('a key added', (st, settle(lambda: idle() and RSA3K.split()[1] in AUTH.read_text())),
       (200, True))
    st, v = call('/api/sshkeys', {'action': 'drop', 'fp': RSA3K_FP}, tok['boss'])
    ok('...and taken away', (st, settle(lambda: idle() and
                                        RSA3K.split()[1] not in AUTH.read_text())), (200, True))
    st, v = call('/api/sshkeys', {'action': 'rk_make', 'kind': 'ed25519'}, tok['boss'])
    ok('a key made: its private half in the answer, once',
       (st, 'PRIVATE KEY' in v.get('private', ''), 'not shown again' in v.get('message', '')),
       (200, True, True))
    settle(idle)
    st, v2 = call('/api/sshkeys', session=tok['boss'])
    ok('...never again', ('PRIVATE' in json.dumps(v2), v2['kept']['fp'], v2['kept']['on']),
       (False, v['fp'], True))
    st, v = call('/api/sshkeys', {'action': 'nothing'}, tok['boss'])
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
    ok('?api=sshkeys read and written', php.count("'sshkeys'      => '/api/sshkeys',"), 2)
    srv = php[php.index('<div class="ctl-group">Server</div>'):]
    srv = srv[:srv.index('<div class="ctl-group">', 10)]
    ok('the pane under Server, for a full admin',
       'class="admin-only" data-pane="sshkeys" data-icon="key"' in srv and
       '>SSH keys of root</button>' in srv)
    # Up to the otp logs over TLS (1.10.245), whose otp words are otp's own.
    sk_text = php[php.index('Settings → SSH keys of root'):]
    sk_text = sk_text.split('otptls.ask, answered in otptls.json')[0]
    ok('nothing of a cluster on it', any(w in sk_text
                                         for w in ('both nodes', 'every node', 'Onto the nodes',
                                                   'Put it on again')), False)
    doc = (ROOT / 'docs' / 'ssh-keys-of-root.md').read_text()
    ok('docs/ssh-keys-of-root.md', all(x in doc for x in ('/root/.ssh/authorized_keys', '0600',
                                                         'sshkeys.ask', 'Make a key',
                                                         'Add a key', '3072')))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
