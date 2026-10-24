#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
endpoints.py - start a real daemon on a spare port and ask it things.

The checks next door test the engine; this tests the door. Every answer the
dashboard depends on is asked for here, as a readonly account and as a full
administrator, because "the page works" and "a readonly account cannot ban
somebody" are two different questions and only one of them is obvious.

    ./test/endpoints.py
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                       # noqa: E402

PASS, FAIL = 0, 0
PORT = 19851


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None, token=None):
    url = 'http://127.0.0.1:%d%s' % (PORT, path)
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if token is not False:
        req.add_header('X-Isemon-Token', token or isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if body is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=20) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, {}
    except Exception as e:
        return 0, {'error': str(e)}


def raw(path, session=None, token=None):
    """A call whose answer is a file rather than JSON."""
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path), method='GET')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN if token is None else token)
    if session:
        req.add_header('X-Isemon-Session', session)
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def send(path, blob, session=None):
    """A call whose body is a file rather than JSON."""
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path), data=blob,
                                 method='POST')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('Content-Type', 'application/octet-stream')
    if session:
        req.add_header('X-Isemon-Session', session)
    try:
        with urllib.request.urlopen(req, timeout=120) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, {}
    except Exception as e:
        return 0, {'error': str(e)}


def rows_in(blob, table):
    """How many rows a downloaded database holds - by opening it, which is
    also the only way to find out whether it opens at all."""
    where = Path(tempfile.mkdtemp(prefix='isemon-opened-')) / 'it.db'
    where.write_bytes(blob)
    try:
        other = sqlite3.connect(str(where))
        try:
            return int(other.execute('SELECT COUNT(*) FROM %s' % table).fetchone()[0])
        finally:
            other.close()
    finally:
        shutil.rmtree(str(where.parent), ignore_errors=True)


folder = tempfile.mkdtemp(prefix='isemon-endpoints-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'e.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'e.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder]})
# ...and in the file's layer too: the running settings are built again from it
# whenever a setting is saved from outside the daemon (1.10.197).
isemon.FILE_CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder]})

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)

try:
    print('\nGetting in')
    status, data = call('/api/health', token=False)
    ok('health answers without a token at all', status, 200)
    status, data = call('/api/status', token='not-the-token')
    ok('a wrong token is refused', status, 401)
    status, data = call('/api/status')
    ok('the right token, but nobody signed in, is refused', status, 401)

    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    ok('a full administrator signs in', (status, data.get('role')), (200, 'fulladmin'))
    admin = data['token']
    status, data = call('/api/auth/login', 'POST', {'name': 'watcher',
                                                    'password': 'another-long-password'})
    ok('a readonly account signs in', (status, data.get('role')), (200, 'readonly'))
    looker = data['token']
    status, data = call('/api/auth/login', 'POST', {'name': 'boss', 'password': 'wrong'})
    ok('a wrong password is refused', status, 400)

    print('\nWhat a readonly account may do')
    for path in ('/api/status', '/api/dashboard', '/api/failed', '/api/passed', '/api/blocked',
                 '/api/events', '/api/settings', '/api/feeds', '/api/geo', '/api/geolist',
                 '/api/sessions', '/api/db', '/api/blocked/fold', '/api/rescan',
                 '/api/passed?kind=tacacs'):
        status, _ = call(path, session=looker)
        ok('it may read %s' % path, status, 200)

    print('\nWhat it may not')
    for path, body in (('/api/blocked', {'add': '198.51.100.5'}),
                       ('/api/settings', {'settings': {'block_tries': 9}}),
                       ('/api/users', {'add': 'somebody', 'password': 'x' * 10}),
                       ('/api/mikrotik', {'sync': True}),
                       ('/api/geolist', {'sync': True}),
                       ('/api/feeds', {'fetch_all': True}),
                       ('/api/geo', {'fetch': True}),
                       ('/api/db/backup', {}),
                       ('/api/rescan', {}),
                       ('/api/import', {'config': {}})):
        status, data = call(path, 'POST', body, session=looker)
        ok('it may not POST %s' % path, status, 403)
    status, _ = call('/api/log', session=looker)
    ok('it may not read the daemon log', status, 403)

    print('\nOne span of time, which is what a bar of the chart asks for')
    now = time.time()
    for n in range(6):
        store.add_failed({'session': 'span/%d' % n, 'ts': now - 7200 + n * 600,
                          'ip': '203.0.113.%d' % (n + 1), 'username': 'INVALID',
                          'server': 'ise2', 'detail': '{}'})
    status, data = call('/api/failed?from=%d&to=%d' % (int(now - 7200), int(now - 5400)),
                        session=looker)
    ok('a window asks for exactly what is in it', (status, data['total']), (200, 3))
    status, data = call('/api/failed?from=%d' % int(now - 5400), session=looker)
    ok('...and an open end is everything after it', (status, data['total']), (200, 3))

    print('\nBanning, by hand')
    status, data = call('/api/blocked', 'POST', {'add': '198.51.100.5', 'minutes': 30,
                                                 'why': 'a test'}, session=admin)
    ok('an administrator may ban', status, 200)
    status, data = call('/api/blocked', session=admin)
    rows = {r['ip']: r for r in data['blocked']}
    ok('...and the address is on the list', '198.51.100.5' in rows, True)
    ok('...with the reason it was given', rows['198.51.100.5']['why'], 'a test')
    ok('...and it runs out rather than lasting for ever',
       0 < rows['198.51.100.5']['left'] <= 1800, True)
    status, data = call('/api/blocked', 'POST', {'add': '2a01:430::/48', 'why': 'v6'},
                        session=admin)
    ok('a whole IPv6 prefix may be banned', status, 200)
    status, data = call('/api/blocked', 'POST', {'add': 'not-an-address'}, session=admin)
    ok('nonsense is refused', status, 400)
    status, data = call('/api/address?ip=198.51.100.5', session=looker)
    ok('the story of one address can be asked for', data.get('blocked'), True)
    status, data = call('/api/blocked', 'POST', {'remove': '198.51.100.5'}, session=admin)
    ok('it may be let back in', status, 200)
    status, data = call('/api/blocked', session=looker)
    ok('...and it is off the list',
       '198.51.100.5' in {r['ip'] for r in data['blocked']}, False)
    ok('...but it is in the history',
       '198.51.100.5' in {r['ip'] for r in data['history']}, True)

    print('\nNever kept out beats everything')
    call('/api/settings', 'POST', {'settings': {'never_block': '192.0.2.0/24'}}, session=admin)
    status, data = call('/api/blocked', 'POST', {'add': '192.0.2.9'}, session=admin)
    ok('an address under "never kept out" cannot be banned even by hand', status, 400)

    print('\nSettings')
    status, data = call('/api/settings', 'POST', {'settings': {'block_tries': 9}}, session=admin)
    ok('a setting is saved', status, 200)
    status, data = call('/api/settings', session=admin)
    one = {s['key']: s for s in data['settings']}
    ok('...and reads back changed', one['block_tries']['value'], 9)
    ok('every setting carries its words', all(s['says'] for s in data['settings']
                                              if s['key'] != 'block_ladder' or True), True)
    ok('a secret is never sent back as itself',
       one['mikrotik_password']['value'].startswith('•')
       or one['mikrotik_password']['value'] == '', True)
    status, data = call('/api/settings', 'POST', {'settings': {'block_tries': 0}}, session=admin)
    ok('a bad setting is refused', status, 400)
    ok('...and every setting says which of the three layers it is standing on',
       one['block_tries']['source'], 'saved')
    ok('...in the words the page shows',
       one['block_tries']['source_says'],
       'saved on this dashboard \u2014 wins over config.json')
    ok('an untouched setting says it is the built-in default',
       one['block_window_min']['source'], 'default')

    print('\nGoing back over every log')
    status, data = call('/api/rescan', session=admin)
    ok('the pass says what it would be weighing', status, 200)
    ok('...how many records there are', isinstance(data['records'].get('rows'), int), True)
    ok('...and what the rule is', bool(data['trigger'] and data['lengths']), True)
    status, data = call('/api/rescan', 'POST', {}, session=looker)
    ok('a readonly account may not start one', status, 403)
    status, data = call('/api/rescan', 'POST', {'read_files': False}, session=admin)
    ok('an admin may', status, 200)
    for _ in range(60):
        status, got = call('/api/job?id=' + data['job'], session=admin)
        if got['job']['done']:
            break
        time.sleep(0.1)
    ok('...and it finishes', got['job']['ok'], True)
    ok('...saying what it did', 'record(s) weighed' in (got['job']['last'] or ''), True)

    print('\nSuccessful logins, split by kind')
    status, data = call('/api/passed?kind=vpn', session=admin)
    ok('asking for the VPN logins is answered', status, 200)
    ok('...with the counts of each kind beside it',
       set(['dacl', 'tacacs', 'tacacs-cmd', 'vpn']) <= set(data['counts']), True)
    status, data = call('/api/passed?kind=tacacs', session=admin)
    ok('asking for the TACACS logins is answered', status, 200)

    print('\nAccounts')
    status, data = call('/api/users', 'POST', {'add': 'third', 'password': 'a-good-password',
                                               'role': 'readonly'}, session=admin)
    ok('an account can be made', status, 200)
    status, data = call('/api/users', session=admin)
    ok('...and shows up', 'third' in {u['name'] for u in data['users']}, True)
    ok('a password hash is never sent to the page',
       any('hash' in u for u in data['users']), False)
    status, data = call('/api/users', 'POST', {'role_for': 'third', 'role': 'fulladmin'},
                        session=admin)
    ok('a role can be changed', status, 200)
    print('\nSwitching an account off, and what it is told')
    status, data = call('/api/auth/login', 'POST', {'name': 'third',
                                                    'password': 'a-good-password'})
    ok('it can sign in while it is on', status, 200)
    status, data = call('/api/users', 'POST', {'name': 'third', 'disable': True},
                        session=admin)
    ok('an account can be switched off', status, 200)
    status, data = call('/api/auth/login', 'POST', {'name': 'third',
                                                    'password': 'a-good-password'})
    ok('...and then it cannot sign in', status, 400)
    # Being told "that name and password do not go together" sends somebody
    # who has done nothing wrong off to reset a password that was never the
    # problem. The password WAS right; what is wrong is the account.
    ok('...and is told why, rather than to check its password',
       'switched off' in (data.get('error') or ''), True)
    status, data = call('/api/auth/login', 'POST', {'name': 'third', 'password': 'wrong'})
    ok('...while a wrong password is still told nothing',
       'switched off' in (data.get('error') or ''), False)
    # ...and a right password against a switched-off account must not count
    # as a wrong one, or five of them lock this address out for everybody.
    for _ in range(8):
        call('/api/auth/login', 'POST', {'name': 'third', 'password': 'a-good-password'})
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    ok('...and it never locks the address out for anybody else', status, 200)
    status, data = call('/api/users', 'POST', {'name': 'third', 'disable': False},
                        session=admin)
    ok('an account can be switched back on', status, 200)
    status, data = call('/api/auth/login', 'POST', {'name': 'third',
                                                    'password': 'a-good-password'})
    ok('...and then it signs in again', status, 200)

    status, data = call('/api/users', 'POST', {'remove': 'boss'}, session=admin)
    ok('you cannot remove the account you are using', status, 400)
    status, data = call('/api/users', 'POST', {'remove': 'third'}, session=admin)
    ok('...but another one, yes', status, 200)

    print('\nThe password of whoever is signed in')
    status, data = call('/api/auth/password', 'POST', {'old': 'wrong', 'new': 'x' * 10},
                        session=looker)
    ok('the current password has to be right', status, 403)
    status, data = call('/api/auth/password', 'POST',
                        {'old': 'another-long-password', 'new': 'short'}, session=looker)
    ok('a short new password is refused', status, 400)
    status, data = call('/api/auth/password', 'POST',
                        {'old': 'another-long-password', 'new': 'a-fresh-long-password'},
                        session=looker)
    ok('a good one is taken', status, 200)
    fresh_token = data['token']
    status, _ = call('/api/status', session=looker)
    ok('the old session is gone', status, 401)
    status, _ = call('/api/status', session=fresh_token)
    ok('the new one works', status, 200)

    # An account the domain owns has its password in the domain. Setting one
    # here would make a second way in that nobody looking at the domain would
    # ever see - which is why the page does not offer it and the daemon does
    # not take it.
    daemon.add_user('fromad', 'a-password-of-its-own', 'readonly', by='a test')
    store.put_user('fromad', role='readonly')
    with store.db_write() as db:
        db.execute('UPDATE users SET from_dir=1 WHERE name=?', ('fromad',))
    status, data = call('/api/auth/login', 'POST', {'name': 'fromad',
                                                    'password': 'a-password-of-its-own'})
    ok('an account the directory owns can still sign in', status, 200)
    dir_session = data.get('token')
    status, data = call('/api/auth/whoami', session=dir_session)
    ok('...and its session says where it came from', data['who'].get('from_dir'), True)
    status, data = call('/api/auth/password', 'POST',
                        {'old': 'a-password-of-its-own', 'new': 'a-fresh-long-password'},
                        session=dir_session)
    ok('...but its password cannot be changed here', status, 409)
    ok('...and it is told why', 'directory' in str(data.get('error') or data), True)

    print('\nThe firewalls the logins were handed')
    status, data = call('/api/acls', session=admin)
    ok('the ACLs the logins name can be asked for', status, 200)
    ok('...and it says how many of them can be read here',
       set(['acls', 'known', 'waiting', 'logins_waiting']) <= set(data), True)

    print('\nSigning out')
    status, _ = call('/api/auth/logout', 'POST', session=fresh_token)
    ok('signing out is allowed', status, 200)
    status, _ = call('/api/status', session=fresh_token)
    ok('...and the session stops working', status, 401)

    print('\nThe database')
    status, data = call('/api/db/check', 'POST', {}, session=admin)
    ok('the database says it is sound', data.get('said'), 'ok')
    status, data = call('/api/db/backup', 'POST', {'label': 'test'}, session=admin)
    ok('a copy can be made', status, 200)
    status, data = call('/api/db', session=admin)
    ok('...and it is listed', len(data['backups']) >= 1, True)
    made = data['backups'][0]['name']

    print('\nWhich database everything is kept in')
    status, data = call('/api/db/engine', session=dir_session)
    ok('a readonly account may see which one it is', status, 200)
    # Normally the file. This same suite is also run against MariaDB and
    # PostgreSQL to check they answer the same way, and there it is not.
    on_a_file = data.get('engine') == 'sqlite'
    ok('...and it says which one, and it is one this version knows',
       data.get('engine') in ('sqlite', 'mariadb', 'postgres'), True)
    if not on_a_file:
        print('  --    run against %s on purpose, so the rest of this is skipped'
              % data.get('engine'))
    ok('...and every engine there is, is offered',
       sorted(one['name'] for one in data['engines']),
       ['mariadb', 'postgres', 'sqlite'])
    ok('...with whether the driver for each is installed',
       sorted(data['drivers']), ['mariadb', 'postgres'])
    ok('...and it says where the address of the database is kept',
       data['file'].endswith('config.json'), True)
    ok('...and that nothing is wrong with it', data.get('trouble'), '')
    status, data = call('/api/db/engine', 'POST', {'act': 'test'}, session=dir_session)
    ok('but a readonly account may not touch it', status, 403)

    status, data = call('/api/db/engine', 'POST',
                        {'act': 'test', 'to': 'mariadb',
                         'settings': {'db_host': '127.0.0.1', 'db_port': 1,
                                      'db_name': 'isemon', 'db_user': 'isemon',
                                      'db_password': 'x', 'db_timeout_s': 2}},
                        session=admin)
    ok('a server that is not there is an answer, not an error', status, 200)
    ok('...which says it was not reached', data.get('reached'), False)
    ok('...and why, in words', bool(str(data.get('trouble') or '').strip()), True)
    ok('...and nothing typed into it was saved',
       isemon.CONFIG.get('db_host'), isemon.DEFAULTS['db_host'])
    ok('...and the file was not written either',
       'db_host' in json.loads(isemon.CONFIG_FILE.read_text())
       if isemon.CONFIG_FILE.exists() else False, False)
    # The rest of these are about the database this is running on, and this
    # suite is written for the file. Run against a server on purpose - which
    # is how the same suite is used to check the other two engines - they
    # would be asking a different question, and one of them would empty the
    # database the suite is sitting in.
    if on_a_file:
        status, data = call('/api/db/engine', 'POST', {'act': 'setup'}, session=admin)
        ok('there is nothing to set up for a file', status, 400)
        status, data = call('/api/db/engine', 'POST', {'act': 'move', 'to': 'sqlite'},
                            session=admin)
        ok('nothing can be carried into the database it is already in', status, 400)
        status, data = call('/api/db/engine', 'POST', {'act': 'empty', 'to': 'sqlite'},
                            session=admin)
        ok('...and the one in use is never the one emptied', status, 400)
        status, data = call('/api/db/engine', 'POST',
                            {'act': 'use', 'to': 'postgres',
                             'settings': {'db_host': '127.0.0.1', 'db_port': 1,
                                          'db_timeout_s': 2}}, session=admin)
        ok('and one that cannot be reached is not taken up', status, 400)
        ok('...so what is in use is still the file',
           isemon.CONFIG.get('db_engine'), 'sqlite')

    print('\nTwo firewalls, over the API')
    status, data = call('/api/mikrotik', session=admin)
    ok('it reports both of them', sorted(data['walls']), ['mikrotik', 'mikrotik2'])
    ok('...and the second is off to begin with', data['walls']['mikrotik2']['on'], False)
    ok('...so there is nothing to compare', data['marks'].get('agree'), None)
    # Each of them has a key of its own, and every road that touches one
    # touches only that one. (Making a key needs ssh-keygen, which a test
    # machine may not have; what is being tested here is which firewall the
    # road reaches, so the keys are put in place directly.)
    store.set_meta('mikrotik_key', 'the first key')
    store.set_meta('mikrotik_public', 'ssh-ed25519 AAAAfirst')
    store.set_meta('mikrotik2_key', 'the second key')
    store.set_meta('mikrotik2_public', 'ssh-ed25519 AAAAsecond')
    status, data = call('/api/mikrotik', session=admin)
    ok('each of them shows its own key',
       [data['walls']['mikrotik']['public'], data['walls']['mikrotik2']['public']],
       ['ssh-ed25519 AAAAfirst', 'ssh-ed25519 AAAAsecond'])
    status, data = call('/api/mikrotik', 'POST', {'forget_key': True, 'fw': 'mikrotik2'},
                        session=admin)
    ok('forgetting the second one\u2019s key is allowed', status, 200)
    ok('...and it is really gone', store.get_meta('mikrotik2_key') or '', '')
    ok('...and the first one\u2019s is untouched',
       store.get_meta('mikrotik_key'), 'the first key')
    status, data = call('/api/mikrotik', 'POST', {'forget_key': True}, session=admin)
    ok('leaving the firewall out means the first one, as it always did',
       store.get_meta('mikrotik_key') or '', '')
    status, data = call('/api/mikrotik', 'POST', {'test': True, 'fw': 'nonesuch'},
                        session=admin)
    ok('a firewall that does not exist is refused', status, 400)
    watching2 = call('/api/auth/login', 'POST',
                     {'name': 'watcher', 'password': 'a-fresh-long-password'})[1]['token']
    status, data = call('/api/mikrotik', 'POST', {'forget_key': True, 'fw': 'mikrotik2'},
                        session=watching2)
    ok('somebody who may only look may not touch either key', status, 403)

    print('\nOne box that finds anything')
    store.block('203.0.113.210', None, 'a failed VPN login as INVALID', auto=True)
    for n in range(3):
        store.add_failed({'session': 'find-ep/%d' % n, 'ts': time.time(),
                          'ip': '203.0.113.210', 'username': 'INVALID', 'server': 'ise1'})
        store.add_failed({'session': 'find-ep-b/%d' % n, 'ts': time.time(),
                          'ip': '203.0.113.211', 'username': 'jan.novak', 'server': 'ise1'})
    status, data = call('/api/find?q=203.0.113.210', session=admin)
    ok('a whole address comes back in full', status, 200)
    ok('...with whether it is banned', data['address']['blocked'], True)
    ok('...and for how long', data['address']['forever'], True)
    ok('...and what it has been trying',
       [n['name'] for n in data['address']['names']], ['INVALID'])
    ok('...and it is not repeated in the list below',
       [b['ip'] for b in data['bans']], [])
    status, data = call('/api/find?q=203.0.113.21', session=admin)
    ok('part of an address finds the ones that start with it',
       sorted(a['ip'] for a in data['addresses']), ['203.0.113.210', '203.0.113.211'])
    ok('...and says which of them are banned',
       '203.0.113.210' in data['banned'], True)
    status, data = call('/api/find?q=jan.nov', session=admin)
    ok('part of a name finds the name', [n['name'] for n in data['names']], ['jan.novak'])
    ok('...with how many attempts and from how many addresses',
       (data['names'][0]['tries'], data['names'][0]['addresses']), (3, 1))
    status, data = call('/api/find?q=', session=admin)
    ok('nothing typed finds nothing', (data['addresses'], data['names']), ([], []))
    status, data = call('/api/find?q=not+an+address+at+all', session=admin)
    ok('nonsense is an empty answer rather than an error', status, 200)
    ok('...with no address in it', data['address'], None)
    # The readonly account's session was ended a few checks ago, on purpose.
    watching = call('/api/auth/login', 'POST',
                    {'name': 'watcher', 'password': 'a-fresh-long-password'})[1]['token']
    status, data = call('/api/find?q=203.0.113.210', session=watching)
    ok('somebody who may only look may use it', status, 200)
    call('/api/blocked', 'POST', {'remove': '203.0.113.210'}, session=admin)

    print('\nOne name, everything about it')
    # What Enter on a name asks for. It is asked after the typing has
    # finished rather than while it is going on, because it is several
    # queries at once - and because a half-typed name is a question nobody
    # has asked yet.
    now = time.time()
    store.add_passed({'session': 'person-ep/vpn', 'ts': now - 10, 'server': 'ise1',
                      'ip': '203.0.113.211', 'username': 'jan.novak', 'kind': 'vpn',
                      'device': 'FTD-VPN', 'machine': 'NB-NOVAK'})
    store.add_passed({'session': 'person-ep/lan', 'ts': now - 40, 'server': 'isea',
                      'username': 'PC9', 'kind': 'dot1x-lan', 'device': 'SW-1',
                      'port': 'Gi1/0/9', 'mac': 'AA-BB-CC-00-00-09',
                      'client': '10.9.0.9', 'subtype': 'let on', 'tkey': '607/VLAN607'})
    store.add_failed({'session': 'person-ep/lan-no', 'ts': now - 90, 'server': 'isea',
                      'ip': '', 'username': 'PC9', 'kind': 'dot1x-lan', 'device': 'SW-1',
                      'port': 'Gi1/0/9', 'mac': 'AA-BB-CC-00-00-09',
                      'reason': '22056 Subject not found'})
    status, data = call('/api/person?name=jan.novak', session=admin)
    ok('everything about one name comes back at once', status, 200)
    ok('...the doors it has been seen at',
       sorted(d['kind'] for d in data['doors']), ['vpn'])
    ok('...how often it was refused and how often it got in',
       (data['tries'], data['signed_in']), (3, 1))
    ok('...the addresses it came from',
       [a['ip'] for a in data['addresses']], ['203.0.113.211'])
    ok('...and whether any of them is banned now', data['banned'], {})
    # A name seen only at a socket or on the wireless is a machine, whatever
    # it is called: a log gives no other sign, and `host/PC1` and `jnovak`
    # are both just names. The directory has the last word and is asked
    # separately, which is why the answer says whether there is one to ask.
    ok('a name seen only on the VPN is taken for a person', data['looks_like'], 'a person')
    status, data = call('/api/person?name=PC9', session=admin)
    ok('...and one seen only at a socket for a machine', data['looks_like'], 'a machine')
    ok('...with what it did on the network, off both lists at once',
       [(r['ok'], r['switch'], r['port'], r['vlan'], r['said'][:5]) for r in data['network']],
       [(True, 'SW-1', 'Gi1/0/9', '607/VLAN607', 'let o'),
        (False, 'SW-1', 'Gi1/0/9', '', '22056')])
    ok('...and whether there is a directory to ask about it at all',
       data['directory'], False)
    status, data = call('/api/person?name=nobody-here-at-all', session=admin)
    ok('a name nothing has ever seen is an empty answer rather than an error',
       (status, data['doors'], data['looks_like']), (200, [], ''))
    status, data = call('/api/person?name=', session=admin)
    ok('...and no name at all is refused outright', status, 400)
    status, data = call('/api/person?name=jan.novak', session=watching)
    ok('somebody who may only look may ask it', status, 200)

    print('\nWhat the addresses on a page are called')
    # The page asks for a whole table's worth at once, after it has drawn
    # them: what is known comes straight back and the rest is queued. It may
    # never wait for a name server, so it is answered whether or not there
    # is one - here there is none, and the answer is still an answer.
    store.ptr_note('203.0.113.211', 'nb-novak.example.loc', at=now - 3600, server='dc1')
    store.ptr_note('203.0.113.211', 'nb-kolar.example.loc', at=now, server='dc1')
    status, data = call('/api/ptr?ips=203.0.113.211,203.0.113.212', session=admin)
    ok('the names of a page of addresses come back in one answer', status, 200)
    ok('...the one that has a name', data['names']['203.0.113.211']['name'],
       'nb-kolar.example.loc')
    ok('...and the one nobody has asked about is simply not in it',
       '203.0.113.212' in data['names'], False)
    ok('...and it says whether anything is looking at all', data['on'], False)
    status, data = call('/api/ptr?ips=203.0.113.211@%d' % int(now - 3600), session=admin)
    ok('an address asked about as at a moment gets the name it had then',
       data['then']['203.0.113.211|%d' % int(now - 3600)]['name'], 'nb-novak.example.loc')
    status, data = call('/api/ptr', 'POST', {'ips': ['203.0.113.211']}, session=admin)
    ok('...and a list too long for an address bar may be posted instead',
       data['names']['203.0.113.211']['name'], 'nb-kolar.example.loc')
    status, data = call('/api/ptr', 'POST', {'try': '203.0.113.211'}, session=watching)
    ok('somebody who may only look may not make this machine go and ask', status, 403)
    status, data = call('/api/ptr', 'POST', {'try': 'not-an-address'}, session=admin)
    ok('...and an administrator asking about nonsense is told so, not left waiting',
       data['trouble'], 'that is not an address')
    status, data = call('/api/ptr', 'POST', {'missing': True}, session=admin)
    ok('the page can ask how many addresses have no name yet',
       isinstance(data.get('missing'), int), True)
    status, data = call('/api/ptr', 'POST', {'fill': True}, session=watching)
    ok('...and somebody who may only look cannot start the pass that fills them in',
       status, 403)
    status, data = call('/api/ptr', 'POST', {'fill': True}, session=admin)
    ok('...while an administrator gets a job to watch', bool(data.get('job')), True)
    status, data = call('/api/find?q=nb-kolar', session=admin)
    ok('a machine can be found by the name its address has',
       [m['ip'] for m in data.get('machines') or []], ['203.0.113.211'])
    status, data = call('/api/address?ip=203.0.113.211', session=admin)
    ok('...and the popup about it lists every name it has had',
       [h['name'] for h in data['ptr']], ['nb-kolar.example.loc', 'nb-novak.example.loc'])

    print('\nAn account the directory owns')
    # No directory here, and none needed: what is tested is that the two
    # things the directory decides cannot be set on this page, whatever the
    # page offers.
    store.put_user_as_kept({'name': 'domainer', 'role': 'readonly', 'hash': '',
                            'from_dir': 1}, by='a test')
    status, data = call('/api/users', 'POST',
                        {'password_for': 'domainer', 'password': 'a-long-enough-one'},
                        session=admin)
    ok('its password cannot be set here', status, 409)
    ok('...and it says where it lives', 'lives in the directory' in str(data.get('error')),
       True)
    ok('...and how to make a way in for an outage anyway',
       'isemon --passwd' in str(data.get('error')), True)
    status, data = call('/api/users', 'POST',
                        {'role_for': 'domainer', 'role': 'fulladmin'}, session=admin)
    ok('nor what it may do', status, 409)
    ok('...because that is worked out again at every sign-in',
       'every time they sign in' in str(data.get('error')), True)
    ok('...and it really was not changed', store.user('domainer')['role'], 'readonly')
    status, data = call('/api/users', 'POST',
                        {'name': 'domainer', 'disable': True}, session=admin)
    ok('but it can be switched off here, which is the one local lock', status, 200)
    ok('...and it took', bool(store.user('domainer')['disabled']), True)
    call('/api/users', 'POST', {'remove': 'domainer'}, session=admin)

    print('\nWhitelisting something that is already banned')
    store.block('198.51.100.80', None, 'a test ban', auto=True)
    store.block('198.51.100.81', time.time() + 3600, 'another', auto=True)
    store.block('203.0.113.77', None, 'not in the range', auto=True)
    status, data = call('/api/whitelist', 'POST',
                        {'add': '198.51.100.0/24', 'note': 'ours'}, session=admin)
    ok('a range can be whitelisted', status, 200)
    ok('...and it says which banned addresses it let back in',
       sorted(data['freed']), ['198.51.100.80', '198.51.100.81'])
    ok('...and they really are back in',
       store.blocked_states(['198.51.100.80', '198.51.100.81']), {})
    ok('...while an address outside the range is untouched',
       '203.0.113.77' in store.blocked_states(['203.0.113.77']), True)
    # And it stays out of the counting from now on.
    for n in range(20):
        store.add_failed({'session': 'white-ep/%d' % n, 'ts': time.time(),
                          'ip': '198.51.100.80', 'username': 'INVALID', 'server': 'ise1'})
    ok('...and it cannot be banned again while it is on the list',
       daemon.maybe_block('198.51.100.80'), None)
    call('/api/whitelist', 'POST', {'remove': '198.51.100.0/24'}, session=admin)
    call('/api/blocked', 'POST', {'remove': '203.0.113.77'}, session=admin)

    print('\nTaking a copy away')
    # The readonly account was signed out a few checks ago, on purpose; it
    # needs to be back in for "may it do this" to mean anything.
    looker = call('/api/auth/login', 'POST',
                  {'name': 'watcher', 'password': 'a-fresh-long-password'})[1]['token']
    was_failed = store.counts()['failed']
    status, good_copy = raw('/api/db/download', session=admin)
    ok('a copy of the live database can be downloaded', status, 200)
    ok('...and it is a database', good_copy[:16], b'SQLite format 3\x00')
    ok('...with what is in the live one in it', rows_in(good_copy, 'failed'), was_failed)
    status, body = raw('/api/db/download?name=' + made, session=admin)
    ok('so can one of the copies already kept', status, 200)
    ok('...and that is a database too', body[:16], b'SQLite format 3\x00')
    status, body = raw('/api/db/download?name=../../etc/passwd', session=admin)
    ok('a name that tries to climb out of the folder is refused', status, 404)
    status, body = raw('/api/db/download?name=isemon-nothing.db', session=admin)
    ok('...and so is one that is not there', status, 404)
    status, body = raw('/api/db/download', session=looker)
    ok('somebody who may only look may not take the database away', status, 403)

    print('\nPutting a copy back')
    status, data = send('/api/db/restore', b'not a database at all' * 40, session=admin)
    ok('something that is not a database is refused', status, 400)
    # What arrives is read rather than believed: a file that is neither a
    # copy nor either engine's dump is named as none of the three.
    ok('...and it says why', 'not a dump this program made' in str(data.get('error')), True)

    other = Path(folder) / 'someone-elses.db'
    spare = sqlite3.connect(str(other))
    spare.execute('CREATE TABLE things (a)')
    spare.commit()
    spare.close()
    status, data = send('/api/db/restore', other.read_bytes(), session=admin)
    ok('somebody else\u2019s database is refused', status, 400)
    ok('...and it says which table is missing', 'not one of ours' in str(data.get('error')),
       True)

    # A copy of ours with the accounts taken out: restoring it would leave
    # nobody able to sign in, which is worth refusing rather than doing and
    # apologising for.
    nobody = Path(folder) / 'nobody.db'
    nobody.write_bytes(good_copy)
    spare = sqlite3.connect(str(nobody))
    spare.execute('DELETE FROM users')
    spare.commit()
    spare.close()
    status, data = send('/api/db/restore', nobody.read_bytes(), session=admin)
    ok('a copy with no administrator in it is refused', status, 400)
    ok('...and it says what that would have cost',
       'lock everybody out' in str(data.get('error')), True)

    status, data = send('/api/db/restore?check=1', good_copy, session=admin)
    ok('a real copy can be looked at without being put back', status, 200)
    ok('...and it says what is in it', data['says']['counts']['failed'], was_failed)
    ok('...and nothing has changed', store.counts()['failed'], was_failed)

    status, data = send('/api/db/restore', good_copy, session=looker)
    ok('somebody who may only look may not put one back', status, 403)

    # And now for real: the live database has gained a row since the copy was
    # taken, and putting the copy back takes it away again.
    store.add_failed({'session': 'restore-test-1', 'ts': time.time(),
                      'ip': '198.51.100.9', 'username': 'INVALID', 'server': 'ise1'})
    ok('the live database has one more row than the copy',
       store.counts()['failed'], was_failed + 1)
    status, data = send('/api/db/restore', good_copy, session=admin)
    ok('a real copy is put back', status, 200)
    ok('...and the row that was not in it is gone', store.counts()['failed'], was_failed)
    ok('...and a copy of what it replaced was made first',
       str(data['safety']).endswith('-before-restore.db'), True)
    ok('...and that copy is there to be had',
       (isemon.BACKUP_DIR / data['safety']).exists(), True)
    # Who is signed in came with the file, like everything else: this copy
    # was taken while this session was open, so it is in there and the
    # session carries on. A copy from last week is not, and whoever restores
    # it signs in again - which is why the page reloads itself afterwards
    # either way.
    ok('...and who is signed in is whatever the copy said',
       store.counts()['sessions'], rows_in(good_copy, 'sessions'))
    ok('...so this session, which the copy holds, still works',
       call('/api/status', session=admin)[0], 200)

    print('\nPutting back a copy this machine already holds')
    status, data = call('/api/db/restore-kept', 'POST', {'name': made, 'check': True},
                        session=admin)
    ok('a kept copy can be looked at without being put back', status, 200)
    ok('...and it says what is in it', data['says']['counts']['failed'] >= 0, True)
    status, data = call('/api/db/restore-kept', 'POST', {'name': '../../etc/passwd'},
                        session=admin)
    ok('a name that tries to climb out of the folder is refused', status, 404)
    status, data = call('/api/db/restore-kept', 'POST', {'name': 'isemon-nothing.db'},
                        session=admin)
    ok('...and so is one that is not there', status, 404)
    status, data = call('/api/db/restore-kept', 'POST', {'name': made}, session=looker)
    ok('somebody who may only look may not put one back', status, 403)
    store.add_failed({'session': 'kept-test-1', 'ts': time.time(), 'ip': '198.51.100.11',
                      'username': 'INVALID', 'server': 'ise1'})
    status, data = call('/api/db/restore-kept', 'POST', {'name': made}, session=admin)
    ok('a kept copy is put back without being sent anywhere', status, 200)
    ok('...and nothing is uploaded to do it', store.counts()['failed'], data['now']['failed'])
    ok('...and a copy of what it replaced was made first',
       (isemon.BACKUP_DIR / data['safety']).exists(), True)
    # Who is signed in came back with the copy, so both sessions are gone.
    admin = call('/api/auth/login', 'POST',
                 {'name': 'boss', 'password': 'a-long-enough-password'})[1]['token']
    looker = call('/api/auth/login', 'POST',
                  {'name': 'watcher', 'password': 'a-fresh-long-password'})[1]['token']

    print('\nStarting the counting again')
    now = time.time()
    for n in range(3):
        store.add_failed({'session': 'clear-ep/%d' % n, 'ts': now - 60 + n,
                          'ip': '198.51.100.44', 'username': 'jnovak', 'server': 'ise1'})
    status, data = call('/api/blocked', session=admin)
    ok('the page can see it counting up',
       any(r['ip'] == '198.51.100.44' for r in data['counting']['rows']), True)
    status, data = call('/api/blocked', 'POST', {'clear_counting': True}, session=looker)
    ok('somebody who may only look may not clear it', status, 403)
    status, data = call('/api/blocked', 'POST', {'clear_counting': True}, session=admin)
    ok('a full administrator may', status, 200)
    ok('...and it says how many went back to nought', data['cleared'] >= 1, True)
    status, data = call('/api/blocked', session=admin)
    ok('...and nothing is counting up any more', data['counting']['rows'], [])
    ok('...and the page is told when the line was drawn', data['counting']['from'] > 0, True)
    status, data = call('/api/failed?ip=198.51.100.44', session=admin)
    ok('...while every attempt is still there to read', data['total'], 3)

    print('\nCarrying the configuration elsewhere')
    status, data = call('/api/export', session=admin)
    ok('a configuration can be exported', data.get('_what'), 'isemon configuration')
    ok('...without the router password in it', 'mikrotik_password' in data['settings'], False)
    exported = data
    status, data = call('/api/import', 'POST', {'config': exported}, session=admin)
    ok('...and imported again', status, 200)
    status, data = call('/api/import', 'POST', {'config': {'_what': 'something else'}},
                        session=admin)
    ok('something that is not one is refused', status, 400)

    print('\nWork that is watched rather than waited for')
    job = daemon.job_start('test-job', lambda progress: (progress(1, 2, 'halfway'),
                                                         time.sleep(0.2),
                                                         progress(2, 2, 'there'),
                                                         {'message': 'done'})[-1])
    for _ in range(40):
        status, data = call('/api/job?id=%s' % job['id'], session=admin)
        if data.get('job', {}).get('done'):
            break
        time.sleep(0.1)
    ok('a job reports itself finished', data['job']['done'], True)
    ok('...and says how it went', data['job']['ok'], True)
    ok('...and what it said last', data['job']['last'], 'done')
    status, data = call('/api/job?id=nosuchjob', session=admin)
    ok('a job that never existed is a 404', status, 404)

    print('\nThe ending of a Cisco access list, read before it is saved')
    status, data = call('/api/acl/try', 'POST',
                        {'text': 'remark ours\npermit ip any any'}, session=admin)
    ok('a reading is answered', (status, data['ok']), (200, True))
    ok('...with nothing wrong with that one', data['faults'], [])
    ok('...and the lines as they will be written, indented the way IOS prints them',
       data['lines'], [' remark ours', ' permit ip any any'])
    status, data = call('/api/acl/try', 'POST',
                        {'text': 'permit ip any any\nnonsense'}, session=admin)
    ok('...and a line a router would refuse is named', [f['n'] for f in data['faults']], [2])
    status, data = call('/api/acl/try', 'POST',
                        {'text': 'permit ip any any', 'family': 'ipv6'}, session=admin)
    ok('...against the family it was asked about',
       bool(data['faults']) and 'other family' in data['faults'][0]['why'], True)
    status, data = call('/api/acl/try', 'POST', {'text': ''}, session=admin)
    ok('nothing typed falls back to the ending that ships', data['lines'],
       [' deny   udp any any eq snmp', ' permit ip any any'])
    status, _ = call('/api/acl/try', 'POST', {'text': 'permit ip any any'})
    ok('...and it is not answered to somebody who has not signed in', status, 401)

    print('\nOne door at a time')
    # The front page has always been about the VPN, because the VPN is all
    # that is ever banned. Every other door went into one chart and nowhere
    # else: same rows, same window, a question nobody could ask.
    nowd = time.time()
    for n in range(4):
        store.add_failed({'session': 'door/e%d' % n, 'ts': nowd - n, 'kind': 'eduroam',
                          'ip': '10.4.4.%d' % n, 'username': 'guest%d@jamu.cz' % (n % 2),
                          'realm': 'jamu.cz' if n % 2 else 'vutbr.cz', 'ssid': 'eduroam',
                          'device': 'WLC-01', 'mac': '00-11-22-33-44-%02d' % n,
                          'server': 'edurad1', 'reason': 'the password was wrong',
                          'detail': '{}'})
    store.add_passed({'session': 'door/eok', 'ts': nowd, 'kind': 'eduroam', 'ip': '10.4.4.9',
                      'username': 'ok@jamu.cz', 'realm': 'jamu.cz', 'ssid': 'eduroam',
                      'device': 'WLC-01', 'mac': '00-11-22-33-44-99', 'server': 'edurad1',
                      'detail': '{}'})
    store.add_failed({'session': 'door/v1', 'ts': nowd, 'kind': 'vpn', 'ip': '203.0.113.44',
                      'username': 'INVALID', 'device': 'FTD-VPN', 'server': 'ise2',
                      'reason': 'wrong password', 'detail': '{}'})
    store.add_failed({'session': 'door/n1', 'ts': nowd, 'kind': 'mab-lan', 'ip': '',
                      'username': '001122334455', 'device': 'sw1rco12np',
                      'port': 'GigabitEthernet1/0/41', 'mac': '00-11-22-33-44-55',
                      'server': 'ise2', 'reason': 'no such MAC in the register',
                      'detail': '{}'})
    status, data = call('/api/door?door=eduroam&hours=24', session=looker)
    ok('a door answers to anybody who has signed in', status, 200)
    ok('...and counts both sides of it',
       (data['totals']['failed']['n'], data['totals']['passed']['n']), (4, 1))
    got = {v['key']: v for v in data['views']}
    ok('...and a card is a list of subjects, not of one column',
       sorted(got), ['people', 'realms', 'reasons'])
    who = {r['said']: r for r in got['people']['rows']}
    ok('...one row to an account', sorted(who), ['guest0@jamu.cz', 'guest1@jamu.cz',
                                                'ok@jamu.cz'])
    ok('...with both sides on the row',
       (who['guest0@jamu.cz']['failed'], who['ok@jamu.cz']['passed']), (2, 1))
    # The half that was missing: what the newest attempt actually WAS.
    newest = who['guest0@jamu.cz']['newest']
    ok('...and the newest attempt beside it, so the row says something',
       (newest.get('realm'), newest.get('device'), newest.get('ssid'),
        newest.get('reason')),
       ('vutbr.cz', 'WLC-01', 'eduroam', 'the password was wrong'))
    ok('...and the institutions are their own card',
       sorted(r['said'] for r in got['realms']['rows']), ['jamu.cz', 'vutbr.cz'])
    ok('...as is what the server said',
       [r['said'] for r in got['reasons']['rows']], ['the password was wrong'])
    ok('every card is named for the page', all(v['name'] for v in data['views']), True)
    ok('...and said in a sentence', all(v['says'] for v in data['views']), True)
    ok('one door does not count another door\'s rows',
       call('/api/door?door=vpn&hours=24', session=looker)[1]['totals']['failed']['n'], 1)
    # A door that stands for four kinds at once answers as one door, and a row
    # of it can be pressed and land on exactly those records.
    status, data = call('/api/door?door=network&hours=24', session=looker)
    ok('a door made of four kinds counts all of them',
       data['totals']['failed']['n'], 1)
    ok('...and says which kinds it is made of', sorted(data['kinds']),
       ['dot1x-lan', 'dot1x-wifi', 'mab-lan', 'mab-wifi'])
    machines = {v['key']: v for v in data['views']}['machines']['rows']
    ok('...one row to a machine', [r['said'] for r in machines], ['00-11-22-33-44-55'])
    ok('...with where it is and why, on the row',
       (machines[0]['newest'].get('device'), machines[0]['newest'].get('port'),
        machines[0]['newest'].get('reason')),
       ('sw1rco12np', 'GigabitEthernet1/0/41', 'no such MAC in the register'))
    # The filters above a list offer what is BEHIND that door and nothing
    # else. Offered every switch in the building, the filter over a list of
    # token attempts offers devices that were never in one, and picking any
    # of them empties the list with no way of knowing why.
    status, all_of_it = call('/api/failed?hours=24&limit=1', session=looker)
    status, just_net = call('/api/failed?kind=network&hours=24&limit=1', session=looker)
    status, just_vpn = call('/api/failed?kind=vpn&hours=24&limit=1', session=looker)
    ok('the filters over one door offer only what is behind it',
       set(just_net['devices']) <= set(all_of_it['devices']), True)
    ok('...and the doors do not offer each other\u2019s',
       set(just_net['devices']) & set(just_vpn['devices']), set())
    ok('...while no door at all still offers the lot',
       set(all_of_it['devices']) >= (set(just_net['devices']) | set(just_vpn['devices'])),
       True)

    status, data = call('/api/failed?kind=network&hours=24&limit=10', session=looker)
    ok('...and the records of that door can be asked for by the door\'s name',
       data['total'], 1)
    status, data = call('/api/failed?kind=network&hours=24&limit=10&q=00-11-22-33-44-55',
                        session=looker)
    ok('...and found by the hardware address a row of it stands for', data['total'], 1)
    # How MAB actually works: every PC offers its hardware address, is refused
    # because that address is in no list, and authenticates with a certificate
    # a second later. Both halves are in the logs and only the first looks
    # like a fault - so a machine that got on afterwards is not a machine that
    # cannot get on, and a card that counts it is a card of ordinary mornings.
    store.add_passed({'session': 'door/n1ok', 'ts': nowd + 1, 'kind': 'dot1x-lan', 'ip': '',
                      'username': 'host/NB-DOPITAL', 'device': 'sw1rco12np',
                      'port': 'GigabitEthernet1/0/41', 'mac': '00-11-22-33-44-55',
                      'server': 'ise2', 'detail': '{}'})
    store.add_failed({'session': 'door/n2', 'ts': nowd, 'kind': 'mab-lan', 'ip': '',
                      'username': 'b827ebaa0101', 'device': 'swje4np',
                      'port': 'GigabitEthernet2/0/1', 'mac': 'B8-27-EB-AA-01-01',
                      'server': 'ise2', 'reason': 'no such MAC in the register',
                      'detail': '{}'})
    # A window of its own, because the answer to the one above is kept for a
    # few seconds and this is a different question.
    status, data = call('/api/door?door=network&hours=2', session=looker)
    machines = {v['key']: v for v in data['views']}['machines']['rows']
    ok('a machine refused by MAB and then let on by 802.1X is not stuck',
       [r['said'] for r in machines], ['B8-27-EB-AA-01-01'])
    ok('...and how many of them there were is counted and said',
       (data['settled']['machines'], data['settled']['settled']), (2, 1))
    ok('...and the switch it is stuck on is the one that is drawn',
       [r['said'] for r in {v['key']: v for v in data['views']}['places']['rows']],
       ['swje4np'])
    status, data = call('/api/door?door=tacacs&hours=24', session=looker)
    ok('a door with nothing behind it answers rather than failing', status, 200)
    ok('...with nothing in it', (data['totals']['failed']['n'], data['views']), (0, []))
    status, _ = call('/api/door?door=../../etc/passwd', session=looker)
    ok('a door nobody has heard of is a 404, not a statement', status, 404)
    status, _ = call('/api/door?door=eduroam&hours=24')
    ok('...and no door is answered to somebody who has not signed in', status, 401)
    status, data = call('/api/door?door=eduroam&hours=99999', session=looker)
    ok('a window wider than anything is held to a year', data['hours'], 8760)

    print('\nWhat the domain controllers saw')
    # Never an authentication: a whole page of this dashboard is about a
    # system that has nothing to do with the banning.
    isemon.CONFIG.update({'winsec': 1, 'winsec_paths': ['/nowhere'],
                          'winsec_machines': 0})
    winline = (time.strftime('%b %d %H:%M:%S') + ' dcx01 WinSecurity: EventID=4740 | '
               'A user account was locked out.  Subject:  Security ID:  S-1-5-18  '
               'Account Name:  DCX01$  Account Domain:  CORP-EXAMPLE  '
               'Account That Was Locked Out:  Security ID:  S-1-5-21-1-2-3-4  '
               'Account Name:  novak  '
               'Additional Information:  Caller Computer Name:  NB-NOVAK')
    for got in isemon.win_parse_lines([winline]):
        store.note_win_event(got.facts)
    status, data = call('/api/windows?hours=24', session=looker)
    ok('the domain page answers to anybody who has signed in', status, 200)
    ok('...and says it is switched on', data['on'], True)
    ok('...and counts the lockout', data['counts'].get('lockout'), 1)
    ok('...and puts it on the lockouts card',
       [one['account'] for one in data['lockouts']], ['novak'])
    ok('...with the machine the bad password came from',
       data['lockouts'][0]['machine'], 'NB-NOVAK')
    status, data = call('/api/windows/events?hours=24&limit=10', session=looker)
    ok('the events themselves are a page of their own', (status, data['total']), (200, 1))
    ok('...with the filters drawn from what is there',
       ([e['event'] for e in data['events']], data['servers']), ([4740], ['dcx01']))
    ident = data['rows'][0]['ident']
    status, data = call('/api/windows/event?ident=' + ident, session=looker)
    ok('one event answers with every field Windows wrote',
       data['event']['fields'].get('Additional Information / Caller Computer Name'),
       'NB-NOVAK')
    status, data = call('/api/windows/around?account=novak&at=%d' % int(time.time()),
                        session=looker)
    ok('...and what else happened to that account around it',
       [r['event'] for r in data['rows']], [4740])
    status, _ = call('/api/windows?hours=24')
    ok('none of it is answered to somebody who has not signed in', status, 401)
    status, _ = call('/api/windows/event?ident=nonsense', session=looker)
    ok('an event nobody has is a 404', status, 404)
    # ...and none of it reaches the lists the banning is made of.
    status, data = call('/api/failed?hours=24&limit=10&kind=all', session=looker)
    ok('a domain event is never one of the refusals that earn bans',
       all('novak' != (r.get('username') or '') for r in data['rows']), True)
    isemon.CONFIG.update({'winsec': 0})

    print('\nWhat 1.10.93 closed')
    # A session is stored as a hash, and a session written by an earlier
    # version - the token itself - goes on working until it ends.
    row = store.db.execute('SELECT token FROM sessions WHERE name = ?', ('boss',)).fetchone()
    ok('a session is stored as a hash of its token', row['token'].startswith('h1:'), True)
    ok('...never the token itself', admin in row['token'], False)
    with store.db_write() as db:
        db.execute('INSERT INTO sessions (token, name, role, made, seen, ip, agent) '
                   'VALUES (?,?,?,?,?,?,?)', ('old-plain-token-from-1-10-92', 'boss',
                                              'fulladmin', time.time(), time.time(), '', ''))
    status, _ = call('/api/status', session='old-plain-token-from-1-10-92')
    ok('a session from before the upgrade still signs in', status, 200)
    # ...but the stored hash itself is not a way in: it is what a copy of the
    # database holds.
    status, _ = call('/api/status', session=row['token'])
    ok('the hash a copy of the database holds does not sign anybody in', status, 401)
    store.drop_session('old-plain-token-from-1-10-92')
    # A wrong name and a wrong password get the same sentence.
    _, wrong1 = call('/api/auth/login', 'POST', {'name': 'boss', 'password': 'not-it-at-all'})
    _, wrong2 = call('/api/auth/login', 'POST', {'name': 'nobody-of-that-name',
                                                 'password': 'not-it-at-all'})
    ok('a wrong password and a name that does not exist get the same words',
       wrong1.get('error'), wrong2.get('error'))
    ok('...and nothing under them for somebody who has not signed in',
       (wrong1.get('detail') or '', wrong2.get('detail') or ''), ('', ''))
    daemon._login_forget('127.0.0.1')
    daemon._login_forget('user:boss')
    # Things that change the program take a form, not a link.
    for road in ('/api/windows/reread', '/api/windows/directory-read',
                 '/api/windows/directory-watch'):
        status, _ = call(road, session=admin)
        ok('%s by GET is refused' % road, status in (404, 405), True)
    # An account that has to change its password can do that and nothing else.
    store.put_user('newcomer', 'a-first-password', 'readonly', must_change=True)
    status, data = call('/api/auth/login', 'POST', {'name': 'newcomer',
                                                    'password': 'a-first-password'})
    ok('an account that has to change its password signs in', status, 200)
    fresh = data['token']
    status, _ = call('/api/status', session=fresh)
    ok('...but may look at nothing until it does', status, 403)
    status, data = call('/api/auth/password', 'POST', {'old': 'a-first-password',
                                                       'new': 'a-second-password'},
                        session=fresh)
    ok('...and may change it', status, 200)
    status, _ = call('/api/status', session=data['token'])
    ok('...after which everything is there', status, 200)
    store.drop_user('newcomer')
    # A list over the domain events says how far it counted.
    status, data = call('/api/windows/events?hours=24&limit=5', session=admin)
    ok('a list over the domain events says whether its count was cut short',
       'capped' in data, True)

    print('\nThe page can still reach it')
    daemon.api_server = api
    ok('the API answers its own health question the way the page asks it',
       isemon.api_answers('127.0.0.1', PORT, 5.0), (True, ''))
    ok('...and a port nobody listens on is said to be shut',
       isemon.api_answers('127.0.0.1', 1, 1.0)[0], False)
    heard = []
    _was_log = isemon.log
    isemon.log = lambda words, level='info': heard.append(words)
    isemon.TOKEN_FILE.unlink()
    daemon.check_the_door()
    ok('a token file gone from under it is written again, the same token',
       isemon.TOKEN_FILE.read_text().strip() == isemon.API_TOKEN, True)
    isemon.TOKEN_FILE.write_text('somebody-else\n')
    daemon.check_the_door()
    ok('...as is one holding another token', isemon.TOKEN_FILE.read_text().strip(),
       isemon.API_TOKEN)
    isemon.log = _was_log
    ok('...and it is said why', any('the page could not have reached this daemon' in h
                                    for h in heard), True)
    if isemon.web_group_exists() is not None:
        _real = isemon.web_group_id
        try:
            os.chown(str(isemon.TOKEN_FILE), -1, 0)
            isemon.web_group_id = lambda: None
            ok('a token the web group may not read by its group is given to it by an ACL',
               (isemon.token_readable_by_web()[0], isemon.token_to_web_group(),
                isemon.token_readable_by_web()[0]), (False, '', True))
        finally:
            isemon.web_group_id = _real
    status, data = call('/api/status')
    ok('the token still opens the API afterwards', status != 401 or 'sign in' in
       str(data.get('error', '')), True)
    api.httpd.shutdown()
    api.thread.join(5)
    daemon.check_the_door()
    time.sleep(0.3)
    ok('an API whose thread is gone is started again',
       (api.thread.is_alive(), isemon.api_answers('127.0.0.1', PORT, 5.0)[0]), (True, True))

    print('\nHow fast it reads')
    daemon._pace.clear()
    daemon._pace_total = 0
    t0 = time.time() - 120
    for i in range(121):
        daemon._pace.append((t0 + i, i * 50, i * 10, i * 0.01))
    daemon._loop_at = time.time()
    got = daemon.pace()
    ok('events a second now, over a minute and over five, out of memory',
       (round(got['now']), round(got['m1']), round(got['m5'])), (50, 50, 50))
    ok('...the database: statements a second and how long each takes',
       (round(got['db_qps']), round(got['db_ms'])), (10, 1))
    ok('...and keeping up', got['level'], 'ok')
    import collections as _c
    daemon._pace_kinds = _c.deque([(t0 + 60, {'INSERT win_events': (100, 1.0), 'SELECT users': (5, 0.01)}),
                                   (t0 + 120, {'INSERT win_events': (700, 31.0),
                                               'SELECT users': (11, 0.02),
                                               'COMMIT': (60, 0.6)})], maxlen=30)
    top = daemon.pace().get('db_top') or []
    ok('...and where the database\u2019s minute went, by kind of statement, busiest first',
       [(r['kind'], r['per_s'], r['ms'], r['share']) for r in top][:2],
       [('INSERT win_events', 10.0, 50.0, 0.5), ('COMMIT', 1.0, 10.0, 0.01)])
    ok('a statement is counted under what it does to which table',
       [isemon.sql_kind(q) for q in ('INSERT OR IGNORE INTO fw_events (a) VALUES (?)',
                                     'INSERT INTO fw_roll (s) VALUES (?) ON CONFLICT(s) DO UPDATE '
                                     'SET n = 1', 'UPDATE tails SET o = ?',
                                     'SELECT COUNT(*) AS n FROM users',
                                     'SELECT ident FROM fw_events WHERE ident IN (?,?)')],
       ['INSERT OR IGNORE fw_events', 'INSERT fw_roll (upsert)', 'UPDATE tails',
        'SELECT users', 'SELECT fw_events (already here?)'])
    status, data = call('/api/status', session=admin)
    ok('the status the header asks for anyway carries it', 'pace' in data, True)

    import io, contextlib, types
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
        code = isemon.cmd_status(types.SimpleNamespace(json=False), isemon.Palette(False), store)
    out = said.getvalue()
    ok('isemon --status says it too: events a second, the database, keeping up',
       (code, 'events a second' in out and '50.0 now' in out, 'the database' in out,
        'keeping up' in out), (0, True, True, True))

    print('\nUnknown roads')
    status, _ = call('/api/nonsense', session=admin)
    ok('an unknown endpoint is a 404', status, 404)

finally:
    api.stop()
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
