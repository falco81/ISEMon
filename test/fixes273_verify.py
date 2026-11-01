#!/usr/bin/env python3
"""1.10.273: Settings -> Backups as plexmon 2.5.4 has it - a backup tried.

The newest backup of this installation fetched back from a destination,
opened with the password, every file checked against its manifest, and what
it carries read through as putting it back would read it (the database with
a full administrator in it, or the configuration). Nothing is put back; the
try is kept and shown (Tried, Backups tried). By hand (Try the newest), after
every backup, or once a week after the backup (Try the backups). The page is
laid out as plexmon's, with isemon's own What is backed up kept.

    ./test/fixes273_verify.py
"""
import json
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
PORT = 19600 + random.randint(0, 90)
PW = 'Backups-Password-1234'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-273-'))
try:
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
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    dest = work / 'dest'
    t = isemon.rb_save(store, {'kind': 'folder', 'path': str(dest), 'name': 'NAS'}, 'boss')
    isemon.CONFIG['rbackup_password'] = PW

    print('The setting')
    ok('Try the backups: only by hand unless set', isemon.DEFAULTS['rbackup_verify'], 'off')
    ok('...by hand, after every backup, once a week',
       [s for s in daemon.settings_state() if s['key'] == 'rbackup_verify'][0]['choices'],
       ['off', 'after', 'weekly'])

    print('\nNothing to try yet')
    try:
        isemon.rb_verify(store, 'boss')
        v = None
    except ValueError as e:
        v = str(e)
    ok('a destination there and nothing in it: tried, and not good',
       v is None and not isemon.rb_verified(store)[0]['ok'] and
       'no backup of this installation' in isemon.rb_verified(store)[0]['said'])
    isemon.rb_verified_put(store, [])

    print('\nA backup of everything, tried')
    run = isemon.rb_run(store, 'boss')
    ok('sent', run['ok'])
    v = isemon.rb_verify(store, 'boss')
    ok('tried: it can be put back', (v['ok'], v['file'], v['target'], v['what']),
       (True, run['file'], 'NAS', 'all'))
    ok('...every check said', [c['ok'] for c in v['checks']], [True, True, True])
    ok('...opened, the files as made, the database read, a full administrator in it',
       ('opened with the password' in v['checks'][0]['what'],
        'the database read through' in v['checks'][1]['what'],
        v['checks'][2]['what']), (True, True, 'a full administrator in it'))
    ok('...kept, and on the page', (len(isemon.rb_verified(store)),
                                    isemon.rb_page(daemon)['verified'][0]['file']),
       (1, run['file']))
    ok('...and in Events', any('a backup tried' in (e['detail'] or '')
                               for e in store.events(limit=20)[0]))
    ok('nothing left behind where it was tried',
       [p.name for p in Path(isemon.scratch_dir()).glob('isemon-verify-*')], [])

    print('\nNot good')
    isemon.CONFIG['rbackup_password'] = 'another-password-99'
    v = isemon.rb_verify(store, 'boss')
    ok('another password: not good, and said', (v['ok'], 'password' in v['said'].lower()
                                                or 'open' in v['said'].lower()), (False, True))
    isemon.CONFIG['rbackup_password'] = PW
    path = dest / run['file']
    blob = bytearray(path.read_bytes())
    blob[len(blob) // 2] ^= 0xFF
    path.write_bytes(bytes(blob))
    v = isemon.rb_verify(store, 'boss')
    ok('a byte changed in it: not good', v['ok'], False)
    ok('...the newest try first on the list', isemon.rb_verified(store)[0]['ok'], False)

    print('\nThe configuration only')
    isemon.CONFIG['rbackup_what'] = 'config'
    time.sleep(1.1)
    run2 = isemon.rb_run(store, 'boss')
    v = isemon.rb_verify(store, 'boss')
    ok('the newest is tried: the configuration, readable',
       (v['ok'], v['file'], v['what'], 'the configuration:' in v['checks'][1]['what']),
       (True, run2['file'], 'config', True))
    isemon.CONFIG['rbackup_what'] = 'all'
    v = isemon.rb_verify(store, 'boss', t['id'], run['file'])
    ok('one named: that one (the damaged one)', (v['file'], v['ok']), (run['file'], False))

    print('\nWhen it is tried by itself')
    isemon.rb_verified_put(store, [])
    for how, want in (('off', False), ('after', True), ('weekly', True)):
        isemon.CONFIG['rbackup_verify'] = how
        ok('%s: the backup just sent tried as well - %s' % (how, want),
           isemon.rb_verify_due(store), want)
    isemon.rb_verified_put(store, [{'at': time.time() - 86400, 'ok': True}])
    ok('weekly, tried a day ago: not again', isemon.rb_verify_due(store), False)
    isemon.rb_verified_put(store, [{'at': time.time() - 7 * 86400, 'ok': True}])
    ok('weekly, tried a week ago: again', isemon.rb_verify_due(store), True)
    isemon.rb_verified_put(store, [])
    isemon.CONFIG['rbackup_verify'] = 'after'
    time.sleep(1.1)
    job = isemon.rb_job_start(daemon, 'boss')
    for _ in range(600):
        j = isemon.rb_job_view(isemon.rb_job_of(daemon))
        if not j['running']:
            break
        time.sleep(0.1)
    ok('after every backup: sent and tried in the one job',
       (j['error'], (j['result'] or {}).get('verified', {}).get('ok'),
        'tried: it can be put back' in (j['result'] or {}).get('message', '')),
       ('', True, True))
    isemon.CONFIG['rbackup_verify'] = 'off'

    print('\nTried by hand, and the list')
    job = isemon.rb_do(daemon, {'action': 'verify'}, 'boss')
    for _ in range(600):
        j = isemon.rb_job_view(isemon.rb_job_of(daemon))
        if not j['running']:
            break
        time.sleep(0.1)
    ok('Try the newest: a job of its own, said', (job['message'], j['what'], j['error'],
                                                  j['result']['message']),
       ('the backup is being tried', 'verify', '', 'tried: it can be put back'))
    n = len(isemon.rb_verified(store))
    one = isemon.rb_verified(store)[0]
    got = isemon.rb_do(daemon, {'action': 'verified_forget', 'at': one['at']}, 'boss')
    ok('a try taken off the list', len(got['verified']), n - 1)
    got = isemon.rb_do(daemon, {'action': 'verified_forget', 'all': 1}, 'boss')
    ok('the list emptied; the backups stay', (got['verified'], len(list(dest.iterdir())) > 0),
       ([], True))

    print('\nThe page, as plexmon draws it')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the settings in plexmon\'s order, What is backed up last', (
        "backup:  ['rbackup', 'rbackup_at', 'rbackup_every', 'rbackup_day', 'rbackup_keep',\n"
        "            'rbackup_keep_days', 'rbackup_password', 'rbackup_verify', 'rbackup_what'],"
        in page))
    ok('Tried, Try the newest, Backups tried', ("fact('Tried', tried ?" in page,
                                                "cmdButton('Try the newest', 'check', '')" in page,
                                                'id="rb-tried-card"' in page,
                                                'function drawRbTried()' in page),
       (True, True, True, True))
    ok('no red box under the facts: Locked says it', "'The backups have no password, so nothing "
       "is sent" not in page)
    ok('Try the backups over two columns, what is not in use faded whole',
       ("if (s.key === 'rbackup_verify') item.classList.add('wide');" in page,
        '#pane-backup .set-item.asleep{opacity:.45}' in page), (True, True))
    ok('How to put it back with the book', "cmdButton('How to put it back', 'book', '')" in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
