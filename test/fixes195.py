#!/usr/bin/env python3
"""1.10.195: where each ban came from on the whole Banned page - the
counting, the history - and letting them back in by source.

from 1.10.193: where the bans come from - a switch a source, every ban saying
what made it, one list carried made of the sources switched on, a source
switched off and on again with its bans kept, every ban of a source let go,
folding that follows the sources, and three new sources counted from the
logs already read: logins to network devices, at the firewall and at the
domain, from the internet only.

    ./test/fixes195.py
"""
import ipaddress
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-195-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'blacklist': 1,
                      'block_tries': 3, 'block_window_min': 10, 'watch_devices': '',
                      'block_ladder': '10, 60, forever', 'fold_least': 2})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)




print('\nThe counting, by source')
now = time.time()
for i in range(2):
    store.add_failed({'session': 'c%d' % i, 'ts': now - 30 + i, 'ip': '45.9.1.1',
                      'username': 'u', 'kind': 'vpn', 'device': 'FTD'})
    store.add_failed({'session': 'd%d' % i, 'ts': now - 30 + i, 'ip': '45.9.1.2',
                      'username': 'u', 'kind': 'nps-vpn', 'device': 'NPS'})
isemon.CONFIG['ban_from_win'] = 1
with store.db_write() as db:
    db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, ip) '
               "VALUES ('w1', ?, 'dc1', 4625, 'logon-failed', 'administrator', '81.7.7.7')",
               (now - 20,))
rows = {r['ip']: r for r in daemon.counting_up(100)['rows']}
ok('each address says which source it is counting for',
   (rows['45.9.1.1']['src'], rows['45.9.1.2']['src'], rows.get('81.7.7.7', {}).get('src')),
   (['ise'], ['nps'], ['win']))
isemon.CONFIG['ban_from_ise'] = 0
rows = {r['ip']: r for r in daemon.counting_up(100)['rows']}
ok('...and whether that source is on', rows['45.9.1.1'].get('src_on'), [])
isemon.CONFIG['ban_from_nps'] = 0
rows = {r['ip']: r for r in daemon.counting_up(100)['rows']}
ok('the VPN through NPS switched off is not counted at all', '45.9.1.2' in rows, False)
isemon.CONFIG.update({'ban_from_ise': 1, 'ban_from_nps': 1, 'ban_from_win': 0})

print('\nThe history, by source')
daemon.ban('198.51.100.9', minutes=None, why='by hand', by='boss')
hist, _n = store.blocked_history(10)
ok('the history keeps where each ban came from', [h['src'] for h in hist
                                                  if h['ip'] == '198.51.100.9'], ['manual'])
ok('...and is sorted by it', 'src' in isemon.Storage.HISTORY_SORTS, True)

print('\nThe sources card adds up')
daemon.ban('198.51.100.9', minutes=None, why='again', by='boss')
store.block('198.51.100.9', None, 'and the VPN', auto=True, src='ise')
st = daemon.ban_sources_state()
by = {one['key']: one for one in st['sources']}
ok('an address banned by two sources is said, and counted under each',
   (st['shared'], by['manual']['bans'], by['manual']['only'], by['ise']['only']),
   (1, 1, 0, 0))
isemon.CONFIG['blacklist'] = 0
st = daemon.ban_sources_state()
ok('banning switched off carries nothing, whatever the sources',
   (st['banning'], st['carried'], by['manual']['carried'] >= 0), (False, 0, True))
isemon.CONFIG['blacklist'] = 1

print('\nThe page')
ok('the history and the counting have a column for it',
   ('<th>Source</th><th>How it ended</th>' in page,
    "{words: 'Names', cls: 'num'}, 'Source', 'Last tried']" in page,
    'function banSourceCell(keys, old)' in page), (True, True, True))
ok('letting them all back in asks from which sources first, with a confirmation',
   ("modal('Let them back in \\u2014 from which sources'" in page,
    "confirmThen('Let the bans of these sources go'" in page,
    'function banClearAll()' in page), (True, True, True))

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
