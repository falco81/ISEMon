#!/usr/bin/env python3
"""1.10.165: a third role, the ban admin - read only, and also ban, let back
in and put the lists on the firewall. For local accounts and for the
directory's.

    ./test/fixes165.py
"""
import json
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19000 + random.randint(0, 900)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


folder = tempfile.mkdtemp(prefix='isemon-165-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nThe roles')
ok('three of them', isemon.Daemon.ROLES, ('fulladmin', 'banadmin', 'readonly'))
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('guard', 'another-long-password', 'banadmin', by='test')
daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
ok('a local account may be a ban admin', store.user('guard')['role'] if hasattr(
    store, 'user') else [u['role'] for u in store.users() if u['name'] == 'guard'][0],
   'banadmin')
try:
    daemon.add_user('nobody', 'a-fourth-long-password', 'superuser', by='test')
    ok('a role that is not one is refused', False, True)
except Exception:
    ok('a role that is not one is refused', True, True)

print('\nThe directory\'s groups')
isemon.CONFIG.update({'directory_admin_group': 'CN=Admins,DC=example,DC=org',
                      'directory_banadmin_group': 'CN=Guards,DC=example,DC=org',
                      'directory_readonly_group': 'CN=Readers,DC=example,DC=org'})
ok('in the ban admin group: a ban admin',
   daemon.directory_role({'cn=guards,dc=example,dc=org'}), 'banadmin')
ok('...in it and the admin group: a full admin',
   daemon.directory_role({'cn=guards,dc=example,dc=org', 'cn=admins,dc=example,dc=org'}),
   'fulladmin')
ok('...in it and the readers: still a ban admin',
   daemon.directory_role({'cn=guards,dc=example,dc=org', 'cn=readers,dc=example,dc=org'}),
   'banadmin')
ok('...in none: nothing', daemon.directory_role({'cn=other,dc=example,dc=org'}), None)
ok('the groups each role comes from are said', daemon.directory_role_groups()['banadmin'],
   ['cn=guards,dc=example,dc=org'])
isemon.CONFIG.update({'directory_admin_group': '', 'directory_readonly_group': ''})
ok('only a ban admin group named: the others are nobody, not everybody',
   daemon.directory_role({'cn=other,dc=example,dc=org'}), None)
isemon.CONFIG.update({'directory_banadmin_group': ''})
ok('no group named at all: nobody from the directory gets in (1.10.221)',
   daemon.directory_role({'cn=other,dc=example,dc=org'}), None)

print('\nWhat each may do')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
try:
    tokens = {}
    for name, pw in (('boss', 'a-long-enough-password'), ('guard', 'another-long-password'),
                     ('watcher', 'a-third-long-password')):
        tokens[name] = call('/api/auth/login', 'POST', {'name': name, 'password': pw})[1]['token']
    status, said = call('/api/blocked', 'POST', {'add': '203.0.113.9', 'minutes': 60,
                                                 'why': 'by hand'}, session=tokens['guard'])
    ok('a ban admin bans', (status, store.blocked_one('203.0.113.9') is not None), (200, True))
    status, said = call('/api/blocked', 'POST', {'remove': '203.0.113.9'},
                        session=tokens['guard'])
    ok('...and lets back in', (status, store.blocked_one('203.0.113.9')), (200, None))
    status, said = call('/api/blocked', 'POST', {'add': '203.0.113.10'},
                        session=tokens['watcher'])
    ok('read only may not ban', (status, store.blocked_one('203.0.113.10')), (403, None))
    call('/api/blocked', 'POST', {'add': '203.0.113.11'}, session=tokens['boss'])
    for asked in ({'clear': True}, {'clear_counting': True}, {'forget_history': True},
                  {'add': '203.0.113.12', 'clear': True}):
        status, said = call('/api/blocked', 'POST', asked, session=tokens['guard'])
        ok('a ban admin may not %s' % ','.join(sorted(asked)), status, 403)
    ok('...and nothing of it was done', store.blocked_one('203.0.113.11') is not None, True)
    status, said = call('/api/mikrotik', 'POST', {'sync': True}, session=tokens['guard'])
    ok('a ban admin puts the lists on the firewall', (status, bool(said.get('job'))),
       (200, True))
    for asked in ({'purge': True, 'which': 'both'}, {'forget_key': True},
                  {'sync': True, 'purge': True}):
        status, said = call('/api/mikrotik', 'POST', asked, session=tokens['guard'])
        ok('...but may not %s' % ','.join(sorted(asked)), status, 403)
    status, said = call('/api/mikrotik', 'POST', {'sync': True}, session=tokens['watcher'])
    ok('read only may not sync', status, 403)
    for path, payload in (('/api/settings', {'settings': {'block_tries': 9}}),
                          ('/api/whitelist', {'add': '10.9.9.9'}),
                          ('/api/users', {'add': 'x', 'password': 'a-long-enough-pw!'})):
        status, said = call(path, 'POST', payload, session=tokens['guard'])
        ok('a ban admin may not change %s' % path, status, 403)
    status, said = call('/api/blocked', session=tokens['guard'])
    ok('...and reads every page', status, 200)
    status, said = call('/api/auth/whoami', session=tokens['guard'])
    ok('the page is told the role', (said.get('who') or {}).get('role'), 'banadmin')
finally:
    api.stop() if hasattr(api, 'stop') else None
    shutil.rmtree(folder, ignore_errors=True)

print('\nThe page')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
ok('the ban buttons follow what may ban, not what may change everything',
   all(x in page for x in ('if (!CAN_BAN || !ip) return out;', 'if (CAN_BAN && one.ip',
                           'class="btn primary ban-only" id="ban-add"',
                           'class="btn primary ban-only" id="router-sync"')))
ok('...and what only a full admin may do stays so',
   all(x in page for x in ('class="btn admin-only" id="ban-fold"',
                           'class="btn danger admin-only" id="ban-clear"',
                           'class="btn danger admin-only" id="router-purge"')))
ok('the group for it is offered beside the other two',
   "['directory_banadmin_group', 'Ban admin', 'ban']" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
