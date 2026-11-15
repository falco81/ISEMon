#!/usr/bin/env python3
"""1.10.351: Settings → SSH keys of every user who may sign in (root's only
shown) and Settings → Local users with their password policy - after acme's
(1.0.108, 1.0.240, 1.0.243, 1.0.43), for one machine.

- root's keys: read, never changed - the API answers 403, the daemon writes no
  ask, root's helper refuses one laid in its folder; the file byte for byte;
- a user's ~/.ssh/authorized_keys written as the user, 0700/0600, never
  through a link; weak, DSA and options refused; a key made here only in the
  answer;
- local users made, given a password (its hash only, on stdin), sudo, aging,
  locked, unlocked and taken away by root's helper; root, services and the
  system refused; a bad hash refused before anything is done;
- the password policy put in and taken out again, byte for byte, on copies of
  the system's files, with a fake authselect;
- a full administrator only, an event for every change, never a password, a
  hash or a private key in the database, the log or an event.

Runs as root: the users are throwaway ones (isemontestu1...), made by the
code under test and always taken away at the end. Nothing of the system's
policy files or of /root/.ssh is written (copies, ISEMON_* overrides).

    ./test/fixes351_sshkeys_users.py
"""
import hashlib
import json
import os
import pwd
import random
import re
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
PORT = 19700 + random.randint(0, 90)
U1, U2, U3, U4 = 'isemontestu1', 'isemontestu2', 'isemontestu3', 'isemontestu4'
TEST_USERS = (U1, U2, U3, U4)
PASSWORD = 'Corr3ct-Horse-Battery-351'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


if os.geteuid() != 0:
    print('this test runs as root (it makes and takes away throwaway users)')
    sys.exit(1)
for tool in ('ssh-keygen', 'useradd', 'chpasswd', 'chage', 'gpasswd', 'userdel', 'openssl'):
    if not shutil.which(tool):
        print('%s is needed for this test' % tool)
        sys.exit(1)
for u in TEST_USERS:
    try:
        pwd.getpwnam(u)
        print('%s is there already - not a user of this test: nothing done' % u)
        sys.exit(1)
    except KeyError:
        pass


def sha(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


REAL_ROOT_AUTH = sha('/root/.ssh/authorized_keys')
REAL_FILES = {p: sha(p) for p in ('/etc/login.defs', '/etc/security/pwhistory.conf',
                                  '/etc/security/faillock.conf', '/etc/security/pwquality.conf')}

work = Path(tempfile.mkdtemp(prefix='isemon-351-'))
os.chmod(str(work), 0o755)
state = work / 'state'
(state / 'web').mkdir(parents=True)
rstate = work / 'root-state'
AUTH = work / 'root' / '.ssh' / 'authorized_keys'
AUTH.parent.mkdir(parents=True)
sshd = work / 'sshd'
sshd.write_text('#!/bin/sh\n[ "$1" = "-T" ] || exit 1\n'
                'printf "port 2222\\npermitrootlogin prohibit-password\\n'
                'pubkeyauthentication yes\\npasswordauthentication no\\n'
                'allowusers root\\nallowusers jnovak@10.*\\n"\n')
sshd.chmod(0o755)
# Copies of the system's own files for the policy.
SEC = work / 'security'
shutil.copytree('/etc/security', str(SEC), symlinks=True)
PAM = work / 'pam.d'
shutil.copytree('/etc/pam.d', str(PAM), symlinks=True)
DEFS = work / 'login.defs'
shutil.copy2('/etc/login.defs', str(DEFS))
AS_STATE = work / 'authselect.json'
AS_STATE.write_text(json.dumps({'profile': 'local', 'features': ['with-faillock'], 'log': []}))
AS = work / 'authselect'
AS.write_text('''#!%s
import json, sys
p = %r
s = json.load(open(p))
a = sys.argv[1:]
if a[:2] == ['current', '--raw']:
    print(' '.join([s['profile']] + s['features']))
elif a[:1] == ['enable-feature'] and a[1] not in s['features']:
    s['features'].append(a[1])
elif a[:1] == ['disable-feature']:
    s['features'] = [x for x in s['features'] if x != a[1]]
s['log'].append(a)
json.dump(s, open(p, 'w'))
''' % (sys.executable, str(AS_STATE)))
AS.chmod(0o755)
ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
           ISEMON_ROOT_AUTHKEYS=str(AUTH), ISEMON_SSHD=str(sshd),
           ISEMON_NGINX_CONF=str(work / 'none.conf'), ISEMON_ROOT_STATE=str(rstate),
           ISEMON_SECURITY_DIR=str(SEC), ISEMON_PAM_DIR=str(PAM), ISEMON_LOGIN_DEFS=str(DEFS),
           ISEMON_AUTHSELECT=str(AS))
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
ROOT_TEXT = '# root\'s own, by hand\n' + A + '\n'
AUTH.write_text(ROOT_TEXT)
AUTH.chmod(0o600)


def root_runs():
    return subprocess.run([sys.executable, '-I', str(HELPER)], env=ENV, capture_output=True,
                          text=True)


def ask(name, req, fresh=True):
    if fresh and 'at' not in req:
        req = dict(req, at=time.time())
    (state / 'web' / (name + '.ask')).write_text(json.dumps(req))
    got = root_runs()
    if got.returncode:
        print(got.stderr)
    return json.loads((state / 'web' / (name + '.json')).read_text())


def mode(p):
    return stat.S_IMODE(os.lstat(str(p)).st_mode)


def shadow(name):
    for ln in Path('/etc/shadow').read_text().splitlines():
        p = ln.split(':')
        if p[0] == name:
            return p
    return None


def files_of(*tops):
    out = {}
    for top in tops:
        top = Path(top)
        if top.is_file():
            out[str(top)] = top.read_bytes()
            continue
        for dp, dn, fn in os.walk(str(top)):
            for f in fn:
                p = os.path.join(dp, f)
                out[p] = os.readlink(p) if os.path.islink(p) else open(p, 'rb').read()
    return out


stop = threading.Event()
api = None
try:
    # ------------------------------------------------------------------------
    print('1. root\'s keys: only read, by root\'s helper')
    got = ask('sshkeys', {'id': 'r1', 'do': 'list'})
    ok('listed, with what sshd says and who else may sign in',
       (got['ok'], [k['fp'] for k in got['data']['keys']], got['data']['sshd']['allow_users'],
        isinstance(got['data']['users'], list)), (True, [A_FP], 'root jnovak@10.*', True))
    for req in ({'id': 'r2', 'do': 'add', 'line': B}, {'id': 'r3', 'do': 'add', 'line': B,
                                                       'user': 'root'},
                {'id': 'r4', 'do': 'drop', 'fp': A_FP}, {'id': 'r5', 'do': 'drop', 'fp': A_FP,
                                                         'user': 'root', 'last_ok': True},
                {'id': 'r6', 'do': 'add', 'line': B, 'at': 0}, {'id': 'r7', 'do': 'what'}):
        got = ask('sshkeys', req, fresh='at' not in req)
        ok('%s for root: refused with the words, the file as it was' % req['do'],
           (got['ok'], got['said'], AUTH.read_text()),
           (False, isemon.ROOT_KEYS_SHOWN_ONLY, ROOT_TEXT))
    src = HELPER.read_text()
    ok('no code left in the helper that writes root\'s file',
       ('def auth_write' in src, bool(re.search(r'(?<![a-z_])auth_write\(', src)),
        'ROOT_AUTH, ' in src.split('def auth_lines')[0]), (False, False, False))
    for who in ('nobody', 'sshd', '../root', 'isemon'):
        got = ask('sshkeys', {'id': 'n', 'do': 'add', 'line': B, 'user': who})
        ok('a key for %s: refused' % who, (got['ok'], 'not a user who may sign in' in
                                          got.get('said', '')), (False, True))

    # ------------------------------------------------------------------------
    print('\n2. a user\'s own file, written as the user')
    subprocess.run(['useradd', '-m', '-s', '/bin/bash', U1], check=True, capture_output=True)
    p1 = pwd.getpwnam(U1)
    home = Path(p1.pw_dir)
    got = ask('sshkeys', {'id': 'u1', 'do': 'list', 'user': U1})
    ok('the user is one who may sign in, no keys yet, nothing written for a read',
       (got['ok'], got['data']['keys'], U1 in [u['name'] for u in got['data']['users']],
        (home / '.ssh').exists()), (True, [], True, False))
    got = ask('sshkeys', {'id': 'u2', 'do': 'add', 'line': A, 'user': U1})
    f = home / '.ssh' / 'authorized_keys'
    ok('a key added: ~/.ssh 0700, the file 0600, both the user\'s',
       (got['ok'], mode(home / '.ssh'), mode(f), os.lstat(str(f)).st_uid,
        os.lstat(str(home / '.ssh')).st_uid, f.read_text()),
       (True, 0o700, 0o600, p1.pw_uid, p1.pw_uid, A + '\n'))
    got = ask('sshkeys', {'id': 'u3', 'do': 'add', 'line': A, 'user': U1})
    ok('the same key again: no fault, there once', (got['ok'], f.read_text()), (True, A + '\n'))
    for what, line, said in (('an RSA key under 3072 bits', WEAK, 'too weak'),
                             ('a DSA key', 'ssh-dss ' + 'A' * 60 + ' old',
                              'not one public key line'),
                             ('options before the key', 'no-pty ' + B, 'not one public key line'),
                             ('a private key as a line', B_PRIV, 'not one public key line')):
        got = ask('sshkeys', {'id': 'x', 'do': 'add', 'line': line, 'user': U1})
        ok('%s: refused, the file as it was' % what,
           (got['ok'], said in got.get('said', ''), f.read_text()), (False, True, A + '\n'))
    # A link in place of the file, to a file of root's.
    target = work / 'roots-secret'
    target.write_text('secret\n')
    target.chmod(0o600)
    f.unlink()
    f.symlink_to(target)
    got = ask('sshkeys', {'id': 'l1', 'do': 'add', 'line': B, 'user': U1})
    ok('authorized_keys a link: refused, the link\'s target untouched',
       (got['ok'], 'link' in got.get('said', ''), target.read_text(), f.is_symlink()),
       (False, True, 'secret\n', True))
    f.unlink()
    shutil.rmtree(str(home / '.ssh'))
    other = work / 'other-ssh'
    other.mkdir()
    (home / '.ssh').symlink_to(other)
    got = ask('sshkeys', {'id': 'l2', 'do': 'add', 'line': B, 'user': U1})
    ok('~/.ssh a link: refused, nothing written where it leads',
       (got['ok'], os.listdir(str(other))), (False, []))
    (home / '.ssh').unlink()
    got = ask('sshkeys', {'id': 'l3', 'do': 'add', 'line': B, 'user': U1})
    ok('a plain folder again: written', (got['ok'], [k['fp'] for k in got['data']['keys']]),
       (True, [B_FP]))
    got = ask('sshkeys', {'id': 'l4', 'do': 'drop', 'fp': B_FP, 'user': U1})
    ok('taken away - no "last key" guard for a user', (got['ok'], got['data']['keys']),
       (True, []))
    big = '\n'.join(['# a line'] * 400 + [A] * 2) + '\n'
    (home / '.ssh' / 'authorized_keys').write_text(big)
    got = ask('sshkeys', {'id': 'l5', 'do': 'list', 'user': U1})
    ok('a long file is read, the keys counted', (got['ok'], len(got['data']['keys'])), (True, 2))
    (home / '.ssh' / 'authorized_keys').write_text('')

    # ------------------------------------------------------------------------
    print('\n5. a bad hash refused before anything (root\'s helper)')
    got = ask('users', {'id': 'h1', 'do': 'add', 'name': U2, 'hash': 'plaintext-password'})
    ok('refused, and no user made', (got['ok'], got.get('said'), shadow(U2)),
       (False, 'the password does not come as a hash this takes', None))
    got = ask('users', {'id': 'h2', 'do': 'password', 'name': U1, 'hash': '$1$abc$defghijklmnopqrs'})
    ok('an MD5 hash refused too', got['ok'], False)
    got = ask('users', {'id': 'h3', 'do': 'add', 'name': U2}, fresh=False)
    ok('a change that does not say when it was asked: refused', (got['ok'], shadow(U2)),
       (False, None))
    got = ask('users', {'id': 'h4', 'do': 'lock', 'name': U1, 'at': time.time() - 3600})
    ok('...nor one asked an hour ago', (got['ok'], 'too long ago' in got['said']), (False, True))
    for who in ('root', 'nobody', 'sshd', 'isemon', 'postgres', 'daemon', 'Root', '../x'):
        got = ask('users', {'id': 'k', 'do': 'lock', 'name': who})
        ok('%s: never changed' % who, got['ok'], False)
    got = ask('users', {'id': 'k2', 'do': 'list'})
    names = [u['name'] for u in got['data']['users']]
    ok('the list: root first and view only, no service account, no system account',
       (names[0], got['data']['users'][0]['root'], 'nobody' in names, 'daemon' in names,
        U1 in names), ('root', True, False, False, True))
    ok('no hash anywhere in the answer', '$6$' in json.dumps(got) or '$y$' in json.dumps(got),
       False)

    # ------------------------------------------------------------------------
    print('\n7. the password policy, on copies of the system\'s files')
    before = files_of(SEC, DEFS)
    got = ask('users', {'id': 'p0', 'do': 'list'})
    ok('read as the system has it: not managed',
       (got['data']['policy']['managed'], got['data']['policy']['authselect']),
       (False, {'profile': 'local', 'features': ['with-faillock']}))
    conf = {'managed': True, 'minlen': 14, 'minclass': 3, 'maxrepeat': 3, 'dictcheck': 1,
            'usercheck': 1, 'difok': 5, 'remember': 5, 'max_days': 90, 'min_days': 1,
            'warn_days': 7, 'deny': 5, 'unlock_time': 900, 'fail_interval': 900,
            'existing': False}
    got = ask('users', {'id': 'p1', 'do': 'policy', 'conf': conf})
    drop = SEC / 'pwquality.conf.d' / '50-isemon.conf'
    pol = got['data']['policy']
    ok('put in: the drop-in, the history, the lockout, the aging',
       (got['ok'], drop.exists(), pol['pwquality']['minlen'], pol['remember'],
        pol['faillock']['deny'], pol['aging']['max_days'], pol['managed']),
       (True, True, 14, 5, 5, 90, True))
    ok('...the old login.defs lines kept in it', '# isemon-was: PASS_MAX_DAYS' in DEFS.read_text())
    ok('...never even_deny_root', 'even_deny_root' in (SEC / 'faillock.conf').read_text()
       .split('# ---- isemon')[-1], False)
    st = json.loads(AS_STATE.read_text())
    ok('...authselect: only the feature not on before switched on',
       (sorted(st['features']), [x for x in st['log'] if x[0] != 'current']),
       (['with-faillock', 'with-pwhistory'], [['enable-feature', 'with-pwhistory']]))
    once = files_of(SEC, DEFS)
    got = ask('users', {'id': 'p2', 'do': 'policy', 'conf': conf})
    ok('put in again: nothing changes', (got['ok'], files_of(SEC, DEFS) == once), (True, True))
    for bad in ({'minlen': 3}, {'deny': 101}, {'fail_interval': 10}, {'max_days': 'x'}):
        got = ask('users', {'id': 'p3', 'do': 'policy', 'conf': dict(conf, **bad)})
        ok('out of range %s: refused, nothing changed' % list(bad)[0],
           (got['ok'], files_of(SEC, DEFS) == once), (False, True))
    hist = SEC / 'pwhistory.conf'
    keep = hist.read_bytes()
    hist.unlink()
    hist.symlink_to(work / 'roots-secret')
    got = ask('users', {'id': 'p4', 'do': 'policy', 'conf': dict(conf, remember=6)})
    ok('a link in place of a file: refused, its target untouched',
       (got['ok'], (work / 'roots-secret').read_text()), (False, 'secret\n'))
    hist.unlink()
    hist.write_bytes(keep)
    got = ask('users', {'id': 'p5', 'do': 'policy', 'conf': dict(conf, managed=False)})
    st = json.loads(AS_STATE.read_text())
    ok('switched off: every file back byte for byte', (got['ok'], files_of(SEC, DEFS) == before),
       (True, True))
    ok('...only isemon\'s authselect feature switched off again', st['features'],
       ['with-faillock'])
    got = ask('users', {'id': 'p6', 'do': 'policy', 'conf': dict(conf, managed=False)})
    ok('off again: nothing to do, nothing written', (got['ok'], files_of(SEC, DEFS) == before),
       (True, True))

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

    def path_unit():
        while not stop.is_set():
            if any(os.path.lexists(str(state / 'web' / n)) for n in ('sshkeys.ask', 'users.ask')):
                root_runs()
            time.sleep(0.1)
    threading.Thread(target=path_unit, daemon=True).start()

    def settle(cond, s=60):
        end = time.time() + s
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def sk_idle():
        return not isemon.SSHKEYS_WORK['busy'] and not isemon.SSHKEYS_WORK['queue']

    def osu_idle():
        return not isemon.OSU_WORK['busy'] and not isemon.OSU_WORK['queue']

    me = isemon.db_node_name()
    for what, args in (('add', dict(line=B)), ('drop', dict(fp=A_FP))):
        try:
            isemon.sshkeys_ask(wr, what, 'boss', **args)
            ok('the daemon refuses %s for root' % what, 'asked', 'refused')
        except isemon.RootKeysShownOnly as e:
            ok('the daemon refuses %s for root, with the words' % what, str(e),
               isemon.ROOT_KEYS_SHOWN_ONLY)
    ok('...no ask written for it', (isemon.SSHKEYS_WORK['queue'],
                                    (state / 'web' / 'sshkeys.ask').exists()), ([], False))
    # One that came anyway (written past the API): never handed to root.
    with isemon.SSHKEYS_LOCK:
        isemon.SSHKEYS_WORK['queue'].append({'id': 'forged', 'do': 'add', 'line': B, 'fp': '',
                                             'user': 'root', 'by': 'nobody',
                                             'at': time.time()})
    isemon.sshkeys_tick(wr)
    settle(sk_idle)
    ok('a forged ask for root in the queue: refused, the file as it was',
       (AUTH.read_text(), isemon.ROOT_KEYS_SHOWN_ONLY in isemon.SSHKEYS_WORK['error']),
       (ROOT_TEXT, True))
    v = isemon.sshkeys_view(wr)
    ok('the view: one node, this server, not a cluster',
       (v['cluster'], [n['name'] for n in v['nodes']], v['nodes'][0]['me'], v['kept']),
       (False, [me], True, []))
    ok('...root still listed', settle(lambda: sk_idle() and [
        k['fp'] for k in isemon.sshkeys_view(wr)['nodes'][0]['keys']] == [A_FP]))

    # ------------------------------------------------------------------------
    print('\nThrough the API')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    daemon.add_user('banner', 'a-fourth-long-password', 'banadmin', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)
    argv_seen = []
    real_run = isemon.subprocess.run

    def watching_run(cmd, *a, **k):
        argv_seen.append(list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)])
        return real_run(cmd, *a, **k)
    isemon.subprocess.run = watching_run

    def call(path, payload=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(payload).encode() if payload is not None
                                     else None, method='POST' if payload is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'),
                        ('banner', 'a-fourth-long-password'))}
    for path in ('/api/sshkeys', '/api/osusers'):
        ok('%s: nobody signed in may not look' % path, call(path)[0], 401)
        for who in ('watcher', 'banner'):
            ok('%s: %s may not look' % (path, who), call(path, session=tok[who])[0], 403)
            ok('%s: %s may not change' % (path, who),
               call(path, {'action': 'refresh'}, tok[who])[0], 403)

    print('\n1. root through the API')
    for body in ({'action': 'add', 'line': B}, {'action': 'add', 'line': B, 'user': 'root'},
                 {'action': 'drop', 'fp': A_FP}, {'action': 'uk_make', 'kind': 'ed25519'},
                 {'action': 'uk_make', 'user': 'root', 'scope': 'all'},
                 {'action': 'rk_make', 'kind': 'ed25519'}, {'action': 'rk_given', 'key': B},
                 {'action': 'rk_again'}):
        st, got = call('/api/sshkeys', body, tok['boss'])
        ok('%s%s: 403 with the words' % (body['action'], ' (root named)' if 'user' in body else ''),
           (st, got.get('error')), (403, isemon.ROOT_KEYS_SHOWN_ONLY))
    ok('...nothing asked of root', isemon.SSHKEYS_WORK['queue'], [])
    st, v = call('/api/sshkeys', session=tok['boss'])
    ok('GET: the old fields and acme\'s shape',
       (st, v['cluster'], v['nodes'][0]['name'], v['nodes'][0]['me'],
        sorted(set(v['nodes'][0]) - {'before'}),
        [k['fp'] for k in v['keys']]),
       (200, False, me, True, ['alive', 'at', 'error', 'file', 'keys', 'keys_of', 'me', 'name',
                               'pending', 'sshd', 'users'], [A_FP]))
    ok('...root\'s file byte for byte', AUTH.read_text(), ROOT_TEXT)

    print('\n2/3. a user\'s keys through the API')
    st, got = call('/api/sshkeys', {'action': 'refresh', 'user': U1, 'nodes': ['x']}, tok['boss'])
    ok('read a user\'s keys (nodes given and not needed)', (st, got.get('message')),
       (200, 'asked again'))
    ok('...read', settle(lambda: sk_idle() and U1 in isemon.SSHKEYS_WORK['keys_of']))
    st, got = call('/api/sshkeys', {'action': 'add', 'user': U1, 'line': WEAK}, tok['boss'])
    ok('a weak key: 400 at once', (st, 'too weak' in got.get('error', '')), (400, True))
    st, got = call('/api/sshkeys', {'action': 'uk_make', 'user': U1, 'scope': 'node2',
                                    'kind': 'ed25519'}, tok['boss'])
    ok('a key made for a node that is not this one: 400', st, 400)
    st, got = call('/api/sshkeys', {'action': 'uk_make', 'user': 'nobody', 'scope': 'all'},
                   tok['boss'])
    ok('a key made for a service account: 400', st, 400)
    st, made = call('/api/sshkeys', {'action': 'uk_make', 'user': U1, 'scope': me,
                                     'kind': 'ed25519'}, tok['boss'])
    ok('a key made: the private half in the answer, once, with the shape',
       (st, 'PRIVATE KEY' in made.get('private', ''), made.get('nodes'),
        made.get('file', '').startswith('isemon-%s-' % U1), 'not shown again' in made['message']),
       (200, True, [me], True, True))
    ok('...its public half into the user\'s file', settle(lambda: sk_idle() and made['pub'].split()[1]
                                                          in (home / '.ssh' / 'authorized_keys')
                                                          .read_text()))
    st, got = call('/api/sshkeys', {'action': 'add', 'user': U1, 'line': B_PRIV}, tok['boss'])
    ok('a private key given: only its public half', (st, 'private half was not kept' in
                                                     got.get('message', '')), (200, True))
    settle(lambda: sk_idle() and B.split()[1] in (home / '.ssh' / 'authorized_keys').read_text())
    ok('...no private key in the user\'s file',
       ('PRIVATE' in (home / '.ssh' / 'authorized_keys').read_text(),
        B.split()[1] in (home / '.ssh' / 'authorized_keys').read_text()), (False, True))
    st, got = call('/api/sshkeys', {'action': 'drop', 'user': U1, 'fp': B_FP}, tok['boss'])
    ok('a key taken away', (st, settle(lambda: sk_idle() and B.split()[1] not in
                                       (home / '.ssh' / 'authorized_keys').read_text())),
       (200, True))
    st, v = call('/api/sshkeys', session=tok['boss'])
    ok('GET: the user\'s keys in keys_of, never the private half',
       (made['fp'] in [k['fp'] for k in v['nodes'][0]['keys_of'][U1]['keys']],
        'PRIVATE' in json.dumps(v)), (True, False))

    print('\n4. local users through the API')
    st, v = call('/api/osusers', session=tok['boss'])
    ok('GET: acme\'s shape, one node',
       (st, v['cluster'], v['policy_refused'], v['openssl'], v['pw_min'],
        [n['name'] for n in v['nodes']], v['policy']['managed']),
       (200, False, False, True, 8, [me], False))
    ok('...read behind', settle(lambda: osu_idle() and isemon.OSU_WORK['now'].get('at')))
    st, v = call('/api/osusers', session=tok['boss'])
    node = v['nodes'][0]
    ok('...the node\'s fields', sorted(node), sorted(
        ['name', 'me', 'alive', 'at', 'pending', 'error', 'admin_group', 'shells', 'uid_min',
         'uid_max', 'today', 'users', 'before', 'said', 'policy', 'policy_applied',
         'policy_said', 'policy_error']))
    ok('...root first, view only, and the policy as never set: in effect',
       (node['users'][0]['name'], node['users'][0]['root'], node['policy_applied']),
       ('root', True, True))
    for body, said in (({'action': 'lock', 'name': 'root'}, 'root is shown here'),
                       ({'action': 'add', 'name': 'nobody'}, 'not one of the system'),
                       ({'action': 'add', 'name': 'isemon'}, 'not one of the system'),
                       ({'action': 'add', 'name': U2, 'sudo': True}, 'sudo asks for the user'),
                       ({'action': 'add', 'name': U2, 'password': 'short'}, '8 characters'),
                       ({'action': 'remake', 'node': me}, 'no such thing'),
                       ({'action': 'lock', 'name': 'nosuchuser351'}, 'has no user')):
        st, got = call('/api/osusers', body, tok['boss'])
        ok('%s %s: 400' % (body['action'], body.get('name', '')),
           (st, said in got.get('error', '')), (400, True))
    st, got = call('/api/osusers', {'action': 'add', 'name': U2, 'gecos': 'Test Two',
                                    'shell': '/bin/bash', 'password': '', 'nodes': [me]},
                   tok['boss'])
    ok('a user made with no password', (st, got.get('nodes'), 'within a few seconds' in
                                        got.get('message', '')), (200, [me], True))
    ok('...made', settle(lambda: osu_idle() and shadow(U2) is not None))
    settle(osu_idle)
    p2 = pwd.getpwnam(U2)
    u1uid = pwd.getpwnam(U1).pw_uid
    used = {p.pw_uid for p in pwd.getpwall() if 1000 <= p.pw_uid <= 60000 and p.pw_name != U2}
    ok('...the lowest UID nobody uses', p2.pw_uid, min(set(range(1000, 60001)) - used))
    ok('...its full name, no aging (a key only), no password', (p2.pw_gecos, shadow(U2)[4],
                                                               shadow(U2)[1][:1]),
       ('Test Two', '', '!'))
    st, v = call('/api/osusers', session=tok['boss'])
    u = [x for x in v['nodes'][0]['users'] if x['name'] == U2][0]
    ok('...listed: no password is not locked', (u['password'], u['locked'], u['login']),
       (False, False, True))
    ok('...done last says so', [(s['do'], s['name'], s['ok'], s['by'])
                                for s in v['nodes'][0]['said']][-1:], [('add', U2, True, 'boss')])
    argv_seen[:] = []
    st, got = call('/api/osusers', {'action': 'add', 'name': U3, 'password': PASSWORD,
                                    'sudo': True, 'must_change': True}, tok['boss'])
    ok('a user made with a password and sudo', st, 200)
    ok('...made', settle(lambda: osu_idle() and shadow(U3) is not None and
                         shadow(U3)[1].startswith('$6$')))
    settle(osu_idle)
    ok('...SHA-512 crypt, to change at the next sign-in, in the sudo group',
       (shadow(U3)[1][:3], shadow(U3)[2], U3 in subprocess.run(
           ['getent', 'group', 'sudo'], capture_output=True, text=True).stdout),
       ('$6$', '0', True))
    ok('...the password never on a command line', any(PASSWORD in ' '.join(a)
                                                      for a in argv_seen), False)
    ok('...openssl given it on stdin', any(a[1:4] == ['passwd', '-6', '-stdin']
                                           for a in argv_seen), True)
    ok('...the ask file is gone', (state / 'web' / 'users.ask').exists(), False)
    argv_seen[:] = []
    st, got = call('/api/osusers', {'action': 'password', 'name': U2, 'password': PASSWORD},
                   tok['boss'])
    ok('a password given later', (st, settle(lambda: osu_idle() and
                                             shadow(U2)[1].startswith('$6$'))), (200, True))
    ok('...the day it was changed', shadow(U2)[2], str(int(time.time() // 86400)))
    st, got = call('/api/osusers', {'action': 'aging', 'name': U2, 'max_days': 90,
                                    'min_days': 1, 'warn_days': 7}, tok['boss'])
    ok('aging', (st, settle(lambda: osu_idle() and shadow(U2)[4] == '90')), (200, True))
    ok('...min and warn', (shadow(U2)[3], shadow(U2)[5]), ('1', '7'))
    st, got = call('/api/osusers', {'action': 'aging', 'name': U2, 'max_days': 5,
                                    'min_days': 10, 'warn_days': 7}, tok['boss'])
    ok('aging: least days more than good for: 400', st, 400)

    print('\n6. lock and unlock')
    ahead = int(time.time() // 86400) + 30
    subprocess.run(['chage', '-E', str(ahead), U2], check=True)
    st, got = call('/api/osusers', {'action': 'lock', 'name': U2}, tok['boss'])
    ok('locked: the password put out of use and the account ended',
       (st, settle(lambda: osu_idle() and shadow(U2)[7] == '0'), shadow(U2)[1][:2]),
       (200, True, '!$'))
    st, v = call('/api/osusers', session=tok['boss'])
    ok('...listed as locked', [x['locked'] for x in v['nodes'][0]['users'] if x['name'] == U2],
       [True])
    st, got = call('/api/osusers', {'action': 'unlock', 'name': U2}, tok['boss'])
    ok('unlocked: the password back and its own end day still ahead back',
       (st, settle(lambda: osu_idle() and shadow(U2)[7] == str(ahead)), shadow(U2)[1][:3]),
       (200, True, '$6$'))
    st, got = call('/api/osusers', {'action': 'sudo', 'name': U3, 'on': False}, tok['boss'])
    ok('sudo taken away', (st, settle(lambda: osu_idle() and U3 not in subprocess.run(
        ['getent', 'group', 'sudo'], capture_output=True, text=True).stdout)), (200, True))
    st, got = call('/api/osusers', {'action': 'set', 'name': U3, 'gecos': 'Three',
                                    'shell': '/bin/sh'}, tok['boss'])
    ok('name and shell', (st, settle(lambda: osu_idle() and
                                     pwd.getpwnam(U3).pw_gecos == 'Three')), (200, True))
    st, got = call('/api/osusers', {'action': 'set', 'name': U3, 'gecos': 'a:b'}, tok['boss'])
    ok('a colon in the full name: 400', st, 400)

    print('\n7. the policy through the API')
    st, got = call('/api/osusers', {'action': 'policy', 'policy': {'managed': True,
                                                                   'minlen': 200}}, tok['boss'])
    ok('out of range: 400', st, 400)
    st, got = call('/api/osusers', {'action': 'policy', 'policy': dict(conf, minlen=16)},
                   tok['boss'])
    ok('saved', (st, got['policy']['minlen'], 'each node puts it in' in got['message']),
       (200, 16, True))
    ok('...put in behind', settle(lambda: osu_idle() and isemon.OSU_WORK['now'].get(
        'policy_hash') == isemon.pwp_hash(isemon.pwp_conf(wr))))
    st, v = call('/api/osusers', session=tok['boss'])
    ok('...in effect, as set', (v['pw_min'], v['nodes'][0]['policy_applied'],
                                v['nodes'][0]['policy']['pwquality']['minlen']), (16, True, 16))
    st, got = call('/api/osusers', {'action': 'password', 'name': U2, 'password': 'aaaaaaaaaa'},
                   tok['boss'])
    ok('a password the policy does not take: 400', st, 400)
    st, got = call('/api/osusers', {'action': 'policy', 'policy': {'managed': False}},
                   tok['boss'])
    ok('given back to the system', (st, settle(lambda: osu_idle() and not (
        SEC / 'pwquality.conf.d' / '50-isemon.conf').exists() and isemon.OSU_WORK['now'].get(
        'policy_hash') == isemon.pwp_hash(isemon.pwp_conf(wr)))), (200, True))
    ok('...every copied file back byte for byte', files_of(SEC, DEFS) == before)

    print('\ntaking away')
    st, got = call('/api/osusers', {'action': 'drop', 'name': U2, 'home': True}, tok['boss'])
    ok('a user taken away with the home folder', (st, settle(lambda: osu_idle() and
                                                             shadow(U2) is None)), (200, True))
    ok('...the home folder gone', os.path.exists('/home/' + U2), False)
    runner = subprocess.Popen(['setpriv', '--reuid', U3, '--regid', U3, '--clear-groups',
                               'sleep', '30']) if shutil.which('setpriv') else None
    if runner:
        time.sleep(0.5)
        st, got = call('/api/osusers', {'action': 'drop', 'name': U3}, tok['boss'])
        settle(osu_idle)
        v = call('/api/osusers', session=tok['boss'])[1]
        last = v['nodes'][0]['said'][-1]
        ok('one who runs something is not taken away', (shadow(U3) is not None, last['ok'],
                                                        'sign them out first' in last['said']),
           (True, False, True))
        runner.kill()
        runner.wait()

    # ------------------------------------------------------------------------
    print('\nthe command line, through the daemon')
    import argparse
    import contextlib
    import io
    (state / 'api-token').write_text(isemon.API_TOKEN)

    def cli(fn, **kw):
        ns = dict(json=False, yes=False, local_user=None, local_full_name=None,
                  local_shell=None, local_must_change=False, local_max_days=None,
                  local_min_days=None, local_warn_days=None, local_policy=False,
                  local_policy_set=None)
        ns.update(kw)
        buf = io.StringIO()
        was = sys.stdin
        sys.stdin = io.StringIO()               # no terminal
        try:
            with contextlib.redirect_stdout(buf):
                rc = fn(argparse.Namespace(**ns), isemon.Palette(False, buf), store)
        finally:
            sys.stdin = was
        return rc, buf.getvalue()
    rc, out = cli(isemon.cmd_local_users, local_users=True)
    ok('--local-users: root view only, the users', (rc, 'view only' in out, U3 in out,
                                                    U1 in out), (0, True, True, True))
    rc, out = cli(isemon.cmd_local_users, local_users=True, json=True)
    ok('...--json', (rc, json.loads(out)['nodes'][0]['name']), (0, me))
    rc, out = cli(isemon.cmd_local_users, local_user=['lock', U3])
    ok('--local-user lock', (rc, 'done' in out, shadow(U3)[7]), (0, True, '0'))
    rc, out = cli(isemon.cmd_local_users, local_user=['unlock', U3])
    ok('--local-user unlock', (rc, shadow(U3)[7]), (0, ''))
    rc, out = cli(isemon.cmd_local_users, local_user=['aging', U3], local_max_days=60)
    ok('--local-user aging: what is not given stays', (rc, shadow(U3)[4]), (0, '60'))
    rc, out = cli(isemon.cmd_local_users, local_user=['password', U3])
    ok('--local-user password with no terminal: refused, never an argument',
       (rc, 'asked at a terminal only' in out), (2, True))
    rc, out = cli(isemon.cmd_local_users, local_user=['drop', U3])
    ok('--local-user drop with no terminal and no --yes: refused',
       (rc, '--yes' in out, shadow(U3) is not None), (1, True, True))
    rc, out = cli(isemon.cmd_local_users, local_user=['lock', 'root'])
    ok('--local-user lock root: refused', (rc, 'never changed' in out), (1, True))
    rc, out = cli(isemon.cmd_local_users, local_user=['shout', U3])
    ok('--local-user with no such thing to do', rc, 2)
    rc, out = cli(isemon.cmd_local_policy, local_policy_set=['minlen=x'])
    ok('--local-policy-set out of range: refused', rc, 1)
    rc, out = cli(isemon.cmd_local_policy, local_policy_set=['dictcheck=maybe'])
    ok('--local-policy-set a switch neither on nor off: refused', rc, 2)
    rc, out = cli(isemon.cmd_local_policy, local_policy_set=['nosuch=1'])
    ok('--local-policy-set no such rule: refused', (rc, 'no such rule' in out), (2, True))
    rc, out = cli(isemon.cmd_local_policy, local_policy=True)
    ok('--local-policy: as set, and in effect here', (rc, 'the system\'s own' in out, me in out),
       (0, True, True))
    rc, out = cli(isemon.cmd_local_users, local_user=['drop-home', U3], yes=True)
    ok('--local-user drop-home --yes', (rc, shadow(U3)), (0, None))

    # ------------------------------------------------------------------------
    print('\nnever a password, a hash or a private key kept')
    isemon.subprocess.run = real_run
    blob = b''
    for f in state.rglob('*'):
        if f.is_file():
            blob += f.read_bytes()
    db = sqlite3.connect(str(isemon.DB_FILE))
    ev = [r[0] for r in db.execute("SELECT detail FROM events WHERE kind='settings' ORDER BY id")]
    meta = json.dumps(list(db.execute('SELECT * FROM meta')))
    db.close()
    secret = made['private'].split('\n')[1]
    ok('not in any file of the daemon\'s (the database, the log, the answers)',
       (PASSWORD.encode() in blob, b'$6$' in blob, secret.encode() in blob,
        b'PRIVATE KEY' in blob), (False, False, False, False))
    ok('not in the database\'s settings', ('$6$' in meta, PASSWORD in meta), (False, False))
    ok('not in the daemon\'s memory of what was asked',
       ('$6$' in json.dumps(isemon.OSU_WORK, default=str),
        PASSWORD in json.dumps(isemon.OSU_WORK, default=str)), (False, False))
    ok('an event for every change, saying who, what and which user', all(any(w in e for e in ev)
       for w in ('boss made the local user %s (UID' % U2, 'boss made the local user %s' % U3,
                 'boss set a new password for the local user %s' % U2,
                 'boss set the password aging of the local user %s (90 days' % U2,
                 'boss locked the local user %s' % U2, 'boss unlocked the local user %s' % U2,
                 'boss took from the local user %s sudo' % U3,
                 'boss changed the local user %s' % U3,
                 'boss took away the local user %s and the home folder' % U2,
                 'boss set the password policy of the local users: at least 16',
                 'boss gave back to the system the password policy',
                 'boss made a new SSH key for %s on %s' % (U1, me),
                 'boss added the SSH key', 'boss took away the SSH key %s for %s' % (B_FP, U1),
                 'boss took away the local user %s' % U3)))
    ok('...none with a password, a hash or a private key',
       any(PASSWORD in e or '$6$' in e or 'PRIVATE' in e for e in ev), False)

    # ------------------------------------------------------------------------
    print('\nthe command line')
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rcs = [fn(argparse.Namespace(), isemon.Palette(False), store)
               for fn in (isemon.cmd_root_key_add, isemon.cmd_root_key_drop,
                          isemon.cmd_root_key_make)]
    ok('--root-key-add, -drop, -make: refused with the words',
       (rcs, out.getvalue().count('only shown on the pages')), ([1, 1, 1], 3))
    help_text = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                               capture_output=True, text=True).stdout
    ok('the options are there', all(o in help_text for o in (
        '--local-users', '--local-user', '--local-full-name', '--local-shell',
        '--local-must-change', '--local-max-days', '--local-min-days', '--local-warn-days',
        '--local-policy', '--local-policy-set')))
    src = (ROOT / 'isemon.py').read_text()
    ok('a password only at a terminal, twice', ('getpass.getpass(\'  again: \')' in src and
                                                'the password is asked at a terminal only' in src))
    ok('the path unit watches users.ask', 'PathExists=/var/lib/isemon/web/users.ask' in
       (ROOT / 'deploy' / 'isemon-web.path').read_text())
    ok('docs', all((ROOT / 'docs' / d).exists() for d in ('ssh-keys.md', 'local-users.md')))
finally:
    stop.set()
    try:
        isemon.subprocess.run = subprocess.run
    except Exception:
        pass
    if api is not None and hasattr(api, 'stop'):
        try:
            api.stop()
        except Exception:
            pass
    for u in TEST_USERS:
        try:
            pwd.getpwnam(u)
        except KeyError:
            continue
        subprocess.run(['pkill', '-KILL', '-u', u], capture_output=True)
        subprocess.run(['userdel', '-r', u], capture_output=True)
    shutil.rmtree(str(work), ignore_errors=True)

ok('the test users are gone', [u for u in TEST_USERS if u in {p.pw_name for p in pwd.getpwall()}],
   [])
ok('root\'s real authorized_keys untouched', sha('/root/.ssh/authorized_keys'), REAL_ROOT_AUTH)
ok('the system\'s policy files untouched', {p: sha(p) for p in REAL_FILES}, REAL_FILES)
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
