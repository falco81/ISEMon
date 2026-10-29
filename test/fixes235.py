#!/usr/bin/env python3
"""1.10.235: what a backup holds - everything, the logs too (as until now),
or the configuration only (rbackup_what = config).

A backup of the configuration carries no copy of the database: what a
complete export carries (settings, accounts with their passwords, the
whitelist, the bans, the routers' keys), the pages' own settings and the
destinations of the backups, and settings.key, banfeed.key and known_hosts.
Put back - from the page, a destination, or `isemon --restore-bundle` - it
is imported into the database there is, and every log record stays.

    ./test/fixes235.py
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import isemon                                        # noqa: E402

PASS = FAIL = 0
PW = 'Backups-Password-1234'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


work = Path(tempfile.mkdtemp(prefix='isemon-235-'))
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
isemon.CONFIG.update({'geo': 0, 'site_name': 'Test site'})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)


def events(st):
    return st.db.execute('SELECT COUNT(*) AS n FROM events').fetchone()['n']


try:
    print('The setting')
    ok('everything, as until now, unless it is set', isemon.DEFAULTS['rbackup_what'], 'all')
    ok('...and so what is backed up', isemon.rb_what(), 'all')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('on the Backups pane', "'rbackup', 'rbackup_what'" in page)
    ok('a configuration-only backup is told apart on the page',
       page.count("'configuration only'") >= 2)

    print('\nA backup of the configuration only')
    daemon.save_settings({'rbackup_password': PW, 'mikrotik_password': 'router-pw-1',
                          'rbackup_what': 'config'}, by='boss')
    ok('set', isemon.rb_what(), 'config')
    daemon.add_user('boss', 'a-long-password-1', 'fulladmin', by='test')
    store.add_whitelist('192.0.2.7', 'the jump host', by='boss')
    store.set_meta('web_access', json.dumps({'on': True, 'lists': ['x']}))
    store.set_meta('tails', json.dumps({'/var/log/x': 12345}))    # where a log was read to
    for i in range(30):
        store.add_event('test', 'a log record %d' % i)
    before = events(store)
    dest = work / 'nas'
    dest.mkdir()
    t = isemon.rb_save(store, {'kind': 'folder', 'path': str(dest), 'name': 'NAS'}, 'boss')
    isemon.rb_set_fields(store, t['id'], '', '', enabled=1)
    run = isemon.rb_run(store, 'boss', daemon=daemon)
    ok('sent', (run['ok'], run.get('what')), (True, 'config'))
    ok('...its name says it', run['file'].endswith('-config.tar.gz.enc'))
    ok('...and it is one of this machine\'s', isemon.rb_mine(isemon.RB_NAME_RE.match(run['file'])))
    listed = isemon.rb_remote_list(store, t['id'])
    ok('listed as the configuration only', [x['what'] for x in listed], ['config'])
    bundle = dest / run['file']
    about = isemon.rb_peek(str(bundle), PW)
    ok('about.json says it', about.get('what'), 'config')
    plain = work / 'plain.tar.gz'
    got = sh('openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', str(isemon.RB_ITER),
             '-md', 'sha256', '-in', str(bundle), '-out', str(plain), '-pass', 'pass:' + PW)
    ok('opened with openssl alone', got.returncode, 0)
    with tarfile.open(str(plain)) as tf:
        names = sorted(m.name.split('/')[1] for m in tf.getmembers())
        conf = json.loads(tf.extractfile([m for m in tf.getmembers()
                                          if m.name.endswith(isemon.RB_CONF)][0]).read())
    ok('no copy of the database in it', names,
       sorted(['about.json', 'RESTORE.md', isemon.RB_CONF, 'manifest.json']))
    ok('the settings, with their passwords', (conf['export']['settings'].get('mikrotik_password'),
                                              conf['export']['settings'].get('rbackup_what')),
       ('router-pw-1', 'config'))
    ok('the whitelist', [w['ip'] for w in conf['export']['whitelist']], ['192.0.2.7'])
    ok('the pages\' own settings and the destinations', sorted(
        k for k in conf['meta'] if k in ('web_access', 'rbackup:targets')),
       ['rbackup:targets', 'web_access'])
    ok('...never where a log was read to', 'tails' in conf['meta'], False)
    ok('the keys', sorted(conf['carried']), sorted(
        k for k in ('settings.key', 'banfeed.key', 'known_hosts') if (state / k).exists()))
    ok('no log record in it', 'a log record' in json.dumps(conf), False)
    md = (dest / (run['file'].split('.tar.gz')[0] + '-RESTORE.md')).read_text()
    ok('RESTORE.md says what it is', 'the configuration only, without the logs' in md and
       'Every log record the machine has stays' in md)

    print('\nPut back here: the logs stay')
    daemon.save_settings({'mikrotik_password': 'changed-since'}, by='boss')
    store.drop_whitelist('192.0.2.7')
    store.set_meta('web_access', json.dumps({'on': False}))
    store.add_event('test', 'one more record, after the backup')
    n_before = events(store)
    got = isemon.rb_restore(store, str(bundle), PW, 'boss', daemon)
    ok('put back, as the configuration', got.get('what'), 'config')
    ok('...no copy of the database made', got.get('safety'), '')
    ok('...the settings are the backup\'s', isemon.CONFIG.get('mikrotik_password'), 'router-pw-1')
    ok('...the pages\' own too', json.loads(store.get_meta('web_access'))['on'], True)
    ok('...the whitelist', '192.0.2.7' in [w['ip'] for w in store.whitelist()])
    ok('...and every log record stays, the ones after it too', events(store) >= n_before)
    ok('...where the logs were read to untouched', json.loads(store.get_meta('tails')),
       {'/var/log/x': 12345})

    print('\nOn a machine installed from nothing, with --restore-bundle')
    fresh = work / 'fresh'
    fresh.mkdir()
    (fresh / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    env = dict(os.environ, ISEMON_CONFIG=str(fresh / 'config.json'), ISEMON_STATE=str(fresh))
    pf = work / 'pw.txt'
    pf.write_text(PW + '\n')
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(pf), env=env, timeout=120)
    ok('without --yes: says it is the configuration only, the logs stay',
       (got.returncode, 'the configuration only' in got.stdout,
        'every log record there stays' in got.stdout), (0, True, True))
    got = sh(sys.executable, str(ROOT / 'isemon.py'), '--restore-bundle', str(bundle),
             '--passphrase-file', str(pf), '--yes', env=env, timeout=300)
    ok('with --yes: put back', got.returncode, 0)
    if got.returncode:
        print(got.stdout[-1500:], got.stderr[-1500:])
    ok('...the logs left as they are, said', 'the logs this machine has were left' in got.stdout)
    ok('...the key that opens the passwords came with it',
       (fresh / 'settings.key').read_text().strip(), (state / 'settings.key').read_text().strip())
    isemon.Storage._unsealable = set()
    other = isemon.Storage(fresh / 'isemon.db')
    ok('...the passwords open there', other.settings_saved().get('mikrotik_password'),
       'router-pw-1')
    ok('...the destinations came back', [x['name'] for x in isemon.rb_targets(other)], ['NAS'])
    ok('...the accounts, with their passwords', [(u['name'], bool(u.get('hash')))
                                                for u in other.users_with_hashes()],
       [('boss', True)])

    print('\nEverything, as before')
    daemon.save_settings({'rbackup_what': 'all'}, by='boss')
    run2 = isemon.rb_run(store, 'boss', daemon=daemon)
    ok('a whole backup again', (run2['ok'], run2['file'].endswith('-config.tar.gz.enc'),
                                run2.get('what')), (True, False, 'all'))
    ok('...with the copy of the database in it',
       isemon.rb_peek(str(dest / run2['file']), PW).get('copy_bytes', 0) > 0)
    ok('retention counts both kinds as this machine\'s', sorted(
        x['what'] for x in isemon.rb_remote_list(store, t['id'])), ['all', 'config'])

    print('\nUpgrades: This server')
    v = daemon.upgrades.page(True)
    ok('the machine, the version and since when', (bool(v.get('host')), v.get('version'),
                                                   v.get('started') == daemon.started),
       (True, isemon.__version__, True))
    ok('the card is at the top of the pane', page.index('id="up-me-card"') <
       page.index('id="up-web-card"'))
    ok('drawn with the rest of the pane', 'drawUpMe(d);' in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
