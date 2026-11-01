#!/usr/bin/env python3
"""1.10.277: Settings -> The database -> Move to another database, a wizard.

It asks, step by step, where the database is to go and how to reach it, and
then one job does it all: refused while another isemon uses this database (a
pair in high availability, which moving one of them would split); the
database and its account made with an administrator given for that one
request; a database with something in it refused unless it is to be emptied;
everything carried across; every table counted again there; and only then
the setting written that says which database is opened - nothing changes for
this installation until then.

Every direction, as a chain - the file -> PostgreSQL -> MariaDB -> the file ->
MariaDB -> PostgreSQL -> the file - where servers are given:

    ISEMON_TEST_POSTGRES_ADMIN=host:port:admin:password
    ISEMON_TEST_MARIADB_ADMIN=host:port:admin:password

(each makes databases called isemon_wiz_* and accounts of the same names).
Without them the parts on the file and the refusals are still checked.

    ./test/fixes277_dbwizard.py
"""
import json
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
TAG = 'w%04d' % random.randint(0, 9999)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def server(env):
    said = os.environ.get(env, '')
    if not said:
        return None
    host, port, user, word = (said.split(':', 3) + ['', '', '', ''])[:4]
    return {'host': host or '127.0.0.1', 'port': int(port), 'admin': user, 'password': word}


PG = server('ISEMON_TEST_POSTGRES_ADMIN')
MA = server('ISEMON_TEST_MARIADB_ADMIN')

work = Path(tempfile.mkdtemp(prefix='isemon-277-'))
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
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'block_tries': 3, 'block_window_min': 60,
                      'watch_devices': '', 'read_passed': 1, 'judge_max_age_h': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))

VPN = ('Protocol=Radius, NetworkDeviceName=FTD-VPN, NAS-IP-Address=172.29.14.81, '
       'Calling-Station-ID=%s, NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) %s, '
       'FailureReason=22056 Subject not found in the applicable identity store')
SEQ = [5000]


def line(kind, ip, user):
    SEQ[0] += 1
    cat = 'CISE_Failed_Attempts' if kind == 'failed' else 'CISE_Passed_Authentications'
    said = 'Failed-Attempt: Authentication failed' if kind == 'failed' \
        else 'Passed-Authentication: Authentication succeeded'
    stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime()) + '.500 +00:00'
    head = ('%s 0075245450 5400 NOTICE %s, ConfigVersionId=126, Device IP Address=172.29.2.23, '
            'UserName=%s, %s, AcsSessionID=%s/579122599/%d,'
            % (stamp, said, user, VPN % (ip, ip), TAG, SEQ[0]))
    return '%s %s %s %010d 1 0 %s' % (time.strftime('%b %d %H:%M:%S'), TAG, cat, SEQ[0], head)


def start():
    """isemon started on whatever config.json says, as after a restart."""
    isemon.CONFIG.update(json.loads((state / 'config.json').read_text()))
    store = isemon.open_store()
    return store, isemon.Daemon(store)


def what_is_in(store):
    q = lambda sql: sorted(tuple(r) for r in store.db.execute(sql).fetchall())   # noqa: E731
    return {
        'failed': q('SELECT session, ip, username FROM failed'),
        'passed': q('SELECT session, ip, username FROM passed'),
        'bans': q('SELECT ip, why FROM blocked'),
        'users': q('SELECT name, role FROM users'),
        'events': len(q('SELECT id FROM events')),
        'settings': q("SELECT key, value FROM settings WHERE key IN ('block_tries', "
                      "'site_name')"),
    }


def wait(daemon, jid):
    for _ in range(1200):
        j = [x for x in daemon.jobs() if x['id'] == jid][0]
        if j['done']:
            return j
        time.sleep(0.1)
    return j


def target(engine, srv=None, db=''):
    if engine == 'sqlite':
        return isemon.engine_asked({}, 'sqlite')
    return isemon.engine_asked({'db_host': srv['host'], 'db_port': srv['port'], 'db_name': db,
                                'db_user': db, 'db_password': ''}, engine)


try:
    print('The file, filled')
    store, daemon = start()
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('reader', 'a-long-enough-password', 'readonly', by='test')
    daemon.save_settings({'site_name': 'Wizard site', 'block_tries': 4}, by='boss')
    for n in range(12):
        ip = '203.0.113.%d' % (1 + n % 3)
        daemon.read_records([line('failed', ip, 'user%d' % n)], kind='failed')
        daemon.read_records([line('passed', '198.51.100.%d' % n, 'staff%d' % n)], kind='passed')
    daemon.ban('192.0.2.77', 60, why='by hand, for the wizard', by='boss')
    first = what_is_in(store)
    ok('records, bans, accounts, settings in it', (len(first['failed']), len(first['passed']),
                                                   len(first['bans']) >= 1, len(first['users'])),
       (12, 12, True, 2))

    print('\nHigh availability: another isemon on this database')
    store.set_meta('node:otherbox', json.dumps({'at': time.time(), 'host': 'otherbox.example.cz',
                                                'version': isemon.__version__}))
    isemon.db_node_beat(store)
    ok('this machine said, and the other seen', ([n['name'] for n in isemon.db_nodes(store)],
                                                  isemon.db_node_name() not in
                                                  [n['name'] for n in isemon.db_nodes(store)]),
       (['otherbox'], True))
    why = isemon.db_move_refused(store, target('sqlite'))
    ok('the wizard refused, and says which machine', 'otherbox.example.cz' in why and
       'high availability' in why)
    try:
        isemon.db_migrate(daemon, isemon.engine_asked({'db_host': '127.0.0.1', 'db_port': 1,
                                                       'db_name': 'x', 'db_user': 'x',
                                                       'db_password': 'x'}, 'postgres'), 'boss')
        ok('...and the job itself refuses too', False)
    except isemon.DbMoveError as e:
        ok('...and the job itself refuses too', 'high availability' in str(e))
    store.set_meta('node:otherbox', json.dumps({'at': time.time() - 3600, 'host': 'otherbox'}))
    ok('the other one silent for an hour: not a pair any more', isemon.db_nodes(store), [])

    print('\nThe settings as the page sends them')
    ok('an empty object, which the page\'s relay turns into an empty list: nothing given',
       isemon.engine_asked([], 'sqlite')['engine'], 'sqlite')
    page_ = (ROOT / 'web' / 'index.php').read_text()
    ok('...and the file is asked about with none at all', "if (WIZ.to === 'sqlite') return null;"
       in page_)

    print('\nRefused before anything is done')
    ok('the database in use itself', isemon.db_move_refused(store, target('sqlite')),
       'that is the database everything is already in')
    bad = isemon.engine_asked({'db_host': '127.0.0.1', 'db_port': 9, 'db_name': 'x',
                               'db_user': 'x', 'db_password': 'x'}, 'postgres'
                              if isemon.DIALECTS['postgres'].driver_ready()[0] else 'mariadb')
    try:
        isemon.db_migrate(daemon, bad, 'boss')
        ok('a server that does not answer: refused, and said', False)
    except isemon.DbMoveError as e:
        ok('a server that does not answer: refused, and said', bool(str(e)))
    ok('...and nothing changed: still the file', json.loads(
        (state / 'config.json').read_text()).get('db_engine') or 'sqlite', 'sqlite')

    chain = []
    if PG:
        chain.append(('postgres', PG, 'isemon_wiz_pg_' + TAG))
    if MA:
        chain.append(('mariadb', MA, 'isemon_wiz_ma_' + TAG))
    if PG and MA:
        chain += [('sqlite', None, ''), ('mariadb', MA, 'isemon_wiz_ma_' + TAG),
                  ('postgres', PG, 'isemon_wiz_pg_' + TAG), ('sqlite', None, '')]
    elif chain:
        chain.append(('sqlite', None, ''))
    if not chain:
        print('\n  --    no ISEMON_TEST_POSTGRES_ADMIN / ISEMON_TEST_MARIADB_ADMIN: no server '
              'was moved into')
    made = {}
    for engine, srv, db in chain:
        was = store.engine.get('engine')
        print('\nFrom %s into %s' % (was, engine))
        want = target(engine, srv, db)
        if engine != 'sqlite' and db in made:
            want['password'] = made[db]
        try:
            refused = isemon.db_migrate(daemon, dict(want), 'boss') and None
        except isemon.DbMoveError as e:
            refused = str(e)
        if engine != 'sqlite' and db not in made:
            ok('no administrator, no account there yet: refused', bool(refused))
            got = isemon.db_migrate(daemon, want, 'boss', srv['admin'], srv['password'],
                                    progress=lambda n, w, words: None)
            made[db] = want['password']
            ok('made with the administrator given, a password made for its account',
               (got['switched'], got['password_made'], bool(want['password'])), (True, True, True))
        else:
            ok('something in it already: refused unless it is to be emptied',
               'not empty' in str(refused))
            ok('...and nothing changed meanwhile', json.loads(
                (state / 'config.json').read_text()).get('db_engine') or 'sqlite', was)
            got = isemon.db_migrate(daemon, want, 'boss', empty=True)
            ok('emptied, and carried across', got['switched'])
        conf = json.loads((state / 'config.json').read_text())
        ok('config.json says %s now - and the password of its account is kept only there'
           % engine, (conf.get('db_engine') or 'sqlite', (conf.get('db_password') or '') == (
               made.get(db, '') if engine != 'sqlite' else (conf.get('db_password') or ''))),
           (engine, True))
        old = store
        store, daemon = start()
        ok('started again: on %s, nothing wrong' % engine,
           (store.engine.get('engine'), getattr(store, 'trouble', '')), (engine, ''))
        now = what_is_in(store)
        for key in ('failed', 'passed', 'bans', 'users', 'settings'):
            ok('...%s as they were' % key, now[key], first[key])
        ok('...and the events, with the moves said', now['events'] >= first['events'])
        daemon.read_records([line('failed', '203.0.113.200', 'after-move')], kind='failed')
        ok('...and it writes there', store.db.execute(
            "SELECT COUNT(*) AS n FROM failed WHERE username='after-move'").fetchone()['n'], 1)
        with store.db_write() as db:
            db.execute("DELETE FROM failed WHERE username='after-move'")
        ok('the one it came from is untouched',
           what_is_in(old)['failed'], first['failed'])
        old.close()
        first = what_is_in(store)

    print('\nThrough the API, as the page asks (a job)')
    if PG or MA:
        engine, srv = ('postgres', PG) if PG else ('mariadb', MA)
        db = 'isemon_wiz_api_' + TAG
        want_api = {'db_host': srv['host'], 'db_port': srv['port'], 'db_name': db, 'db_user': db,
                    'db_password': ''}

        class Me(dict):
            pass

        class H(isemon.ApiHandler):
            def __init__(self):
                self.out = None

            def send_json(self, data, status=200):
                self.out = (status, data)

        h = H()
        h.db_engine_do({'act': 'check', 'to': engine, 'settings': want_api}, {'name': 'boss'},
                       store, daemon)
        ok('check: may it, what answers there', (h.out[1]['refused'], h.out[1]['reached']),
           ('', False))
        h.db_engine_do({'act': 'migrate', 'to': engine, 'settings': want_api,
                        'admin_user': srv['admin'], 'admin_password': srv['password']},
                       {'name': 'boss'}, store, daemon)
        j = wait(daemon, h.out[1]['job'])
        ok('migrate: one job, every step, and said', (j['error'], (j['result'] or {}).get(
            'switched'), 'taken up' in (j['result'] or {}).get('message', '')), ('', True, True))
        ok('...the administrator in nothing kept', srv['password'] not in json.dumps(
            daemon.jobs(), default=str) and srv['password'] not in (state / 'config.json')
           .read_text())
        store, daemon = start()
        ok('...and started again on it', store.engine.get('engine'), engine)
    else:
        print('  --    no server given')

    print('\nThe page: a wizard')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('one button opens it; the five old ones are gone', (
        'id="db-wizard-open"' in page, 'id="db-engine-move"' not in page,
        'id="db-engine-use"' not in page), (True, True, True))
    ok('Back and Next, steps asked one after another', ('function dbWizard(' in page,
                                                       "words: 'Back'" in page,
                                                       "words: 'Next'" in page),
       (True, True, True))
    ok('refused on the page in high availability', 'off: !!w.nodes.length' in page)
    ok('the job followed, and the page waits for isemon back on the new one',
       ('function dbWizardFollow(' in page, 'function dbWizardBack(' in page), (True, True))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
