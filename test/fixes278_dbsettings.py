#!/usr/bin/env python3
"""1.10.278: Settings -> The database as the AI app 1.0.57 has it - the
address of the database in the settings again, and the wizard beside it.

- How the database in use is reached (the server, the port, the account, its
  password, the wait) is in Settings -> The database again, saved with the
  save bar: tried first - it must answer, the account must write, and it must
  be this installation's database (another one, empty of isemon, is a move) -
  and isemon starts again on it. A changed server or account wants its
  password typed: the saved one goes only where it was saved for.
- Which engine is reached is Move to another database... alone: refused from
  the save bar, the box not to be changed, the wizard's button beside it.
- The wizard says which database is in use now (a tag on its card, whichever
  engine it is, and a line), its steps are the AI app's (Where to, How to
  reach it, What is there, Go, Moving - the second not asked of the file),
  it starts from the settings above, has Check again, and may stop short of
  switching over; the password made for the account is shown once.

With ISEMON_TEST_POSTGRES_ADMIN=host:port:admin:password the saving is
tried against a real PostgreSQL (databases isemon_set_*).

    ./test/fixes278_dbsettings.py
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
TAG = 's%04d' % random.randint(0, 9999)


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


def refused(store, given):
    try:
        return 'saved' if isemon.db_settings_saved(store, given) is not None else ''
    except ValueError as e:
        return str(e)


PG = server('ISEMON_TEST_POSTGRES_ADMIN')
work = Path(tempfile.mkdtemp(prefix='isemon-278-'))
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
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))


def start():
    isemon.CONFIG.update(json.loads((state / 'config.json').read_text()))
    store = isemon.open_store()
    return store, isemon.Daemon(store)


def wait(daemon, jid):
    for _ in range(1200):
        j = [x for x in daemon.jobs() if x['id'] == jid][0]
        if j['done']:
            return j
        time.sleep(0.1)
    return j


class H(isemon.ApiHandler):
    def __init__(self):
        self.out = None

    def send_json(self, data, status=200):
        self.out = (status, data)

    def fail(self, said, status=400):
        self.out = (status, {'ok': False, 'error': said})


try:
    store, daemon = start()
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')

    print('On the file')
    ok('another engine from the save bar: refused, the wizard named',
       'Move to another database' in refused(store, {'db_engine': 'postgres'}))
    ok('...the same engine sent back as it is: nothing to do', refused(store, {'db_engine': 'sqlite'}),
       'saved')
    ok('the server and the rest, while the file is in use: kept for later, nothing to start again',
       isemon.db_settings_saved(store, {'db_host': '192.0.2.1', 'db_timeout_s': 7}), False)
    ok('...and saved', daemon.save_settings({'db_host': '192.0.2.1', 'db_timeout_s': 7},
                                            by='boss')['changed'], ['db_host', 'db_timeout_s'])
    daemon.save_settings({'db_host': '127.0.0.1', 'db_timeout_s': 10}, by='boss')
    ok('a value that is wrong said by its setting', refused(store, {'db_name': 'no; DROP'})
       .startswith('db_name'))

    if PG:
        db = 'isemon_set_' + TAG
        want = isemon.engine_asked({'db_host': PG['host'], 'db_port': PG['port'], 'db_name': db,
                                    'db_user': db, 'db_password': ''}, 'postgres')
        got = isemon.db_migrate(daemon, want, 'boss', PG['admin'], PG['password'],
                                progress=lambda n, w, words: None)
        ok('moved into PostgreSQL by the wizard, its password made and given back once',
           (got['switched'], bool(got.get('password')), got.get('password') == want['password']),
           (True, True, True))
        store, daemon = start()
        ok('started again on it', store.engine.get('engine'), 'postgres')

        print('\nOn PostgreSQL: how it is reached, from the save bar')
        ok('the wait changed: tried, and isemon starts again on it',
           isemon.db_settings_saved(store, {'db_timeout_s': 12}), True)
        ok('nothing different: nothing to start again', isemon.db_settings_saved(
            store, {'db_host': PG['host'], 'db_password': '••••ab'}), False)
        ok('another server with the saved password: refused, its own to be typed',
           refused(store, {'db_host': 'localhost' if PG['host'] != 'localhost' else '127.0.0.1'})
           .startswith('db_password'))
        ok('a port nothing answers on: refused, nothing changed', (
            refused(store, {'db_port': 9, 'db_password': 'whatever-it-is'}).startswith('db_host'),
            isemon.CONFIG['db_port']), (True, PG['port']))
        ok('a wrong password for the account: refused', refused(
            store, {'db_password': 'not-the-password'}).startswith('db_host'))
        ok('another database there, empty of isemon: a move, not a setting', 'Move to another '
           'database' in refused(store, {'db_name': 'postgres', 'db_user': PG['admin'],
                                         'db_password': PG['password']}))
        ok('...and none of it written', json.loads((state / 'config.json').read_text())
           .get('db_name'), db)
        ok('the engine still the wizard\'s alone', 'Move to another database' in refused(
            store, {'db_engine': 'sqlite'}))

        print('\nThe wizard, not switched over at the end')
        db2 = 'isemon_set2_' + TAG
        h = H()
        h.db_engine_do({'act': 'migrate', 'to': 'postgres', 'switch': False,
                        'settings': {'db_host': PG['host'], 'db_port': PG['port'], 'db_name': db2,
                                     'db_user': db2, 'db_password': ''},
                        'admin_user': PG['admin'], 'admin_password': PG['password']},
                       {'name': 'boss'}, store, daemon)
        j = wait(daemon, h.out[1]['job'])
        r = j['result'] or {}
        ok('carried in and counted, not switched over, and said', (
            j['error'], r.get('switched'), r.get('restarting'), 'not switched over' in
            r.get('message', '')), ('', None, False, True))
        ok('...the password made shown once, in the result of whoever moved it',
           bool(r.get('password')))
        ok('...and config.json as it was', json.loads((state / 'config.json').read_text())
           .get('db_name'), db)
        ok('...the administrator in nothing kept', PG['password'] not in json.dumps(
            daemon.jobs(), default=str) and PG['password'] not in (state / 'config.json')
           .read_text())
        h.db_engine_do({'act': 'migrate', 'to': 'sqlite', 'settings': None, 'empty': True},
                       {'name': 'boss'}, store, daemon)
        j = wait(daemon, h.out[1]['job'])
        ok('and back onto the file by the wizard', (j['error'], (j['result'] or {}).get('switched')),
           ('', True))
        store.close()
    else:
        print('\n  --    no ISEMON_TEST_POSTGRES_ADMIN: nothing saved against a server')

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the address of the database in Settings -> The database again',
       "  db:      ['db_engine', 'db_host', 'db_port', 'db_name', 'db_user', 'db_password',\n"
       "            'db_timeout_s', 'db_split'," in page)
    ok('the engine not changed there, the wizard\'s button beside it', (
        "if (s.key === 'db_engine') input.disabled = true;" in page,
        "if (s.key === 'db_engine') changed = false;" in page,
        "mv.id = 'db-wizard-here';" in page), (True, True, True))
    ok('saved, the page waits for isemon back and loads again', (
        'if (d.restarting) { dbSettingsBack(); return; }' in page,
        'function dbSettingsBack()' in page), (True, True))
    src = (ROOT / 'isemon.py').read_text()
    ok('the API tries it before it is saved', 'again = db_settings_saved(store, given)' in src)
    ok('the AI app\'s steps', "var WIZ_STEPS = ['Where to', 'How to reach it', 'What is there', "
       "'Go', 'Moving'];" in page)
    ok('the database in use now: tagged on its card whichever it is, and a line', (
        "if (name === w.live) {" in page, "'in use now'));" in page,
        "page.appendChild(el('p', 'btnhelp', 'In use now: ' + dbWizardWhere()));" in page,
        "'Another server or another '" in page), (True, True, True, True))
    ok('started from the settings above', "var x = settingByKey(k);" in page)
    ok('Check again, Switch over to it at the end, the password shown once', (
        "words: 'Check again'" in page, "'Switch over to it at the end'" in page,
        'shown this once' in page, "switch: w.switchOver" in page), (True, True, True, True))
    ok('drawn as the AI app draws it: its popup, steps, cards, fields and facts', (
        "$('modal-box').classList.add('mig-box');" in page,
        '  #modal-box.mig-box{width:min(900px,100%);' in page,
        "var steps = el('div', 'mig-steps');" in page, "el('button', 'mig-card'" in page,
        "var one = el('div', 'set-item');" in page, '  .mig .facts .fact.wide{grid-column:span 2}' in page),
       (True,) * 6)
    ok('the file not asked how to reach it', "if (i === 1 && w.to === 'sqlite') return;" in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
