#!/usr/bin/env python3
"""1.10.194: one switch for the VPN through NPS, the bans of before read
again by what they were, and the sources card put right.

from 1.10.193: where the bans come from - a switch a source, every ban saying
what made it, one list carried made of the sources switched on, a source
switched off and on again with its bans kept, every ban of a source let go,
folding that follows the sources, and three new sources counted from the
logs already read: logins to network devices, at the firewall and at the
domain, from the internet only.

    ./test/fixes194.py
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
folder = tempfile.mkdtemp(prefix='isemon-194-')
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



print('\nOne switch for the VPN through NPS')
isemon.CONFIG['judge_nps_vpn'] = 0
ok('an installation that had the old one off has the source off instead, once',
   (daemon.nps_switch_fold(), isemon.CONFIG.get('ban_from_nps'),
    int(isemon.CONFIG.get('judge_nps_vpn')), daemon.nps_switch_fold()), (True, 'off', 1, False))
ok('...and its refusals are not judged', isemon.judged_doors(), ('vpn',))
daemon.save_settings({'judge_nps_vpn': 1}, by='test')
ok('the old name, given, switches the source', (isemon.CONFIG['ban_from_nps'],
                                                isemon.judged_doors()), ('on', ('vpn', 'nps-vpn')))
ok('the old switch is no longer drawn', "'block_over_max', 'judge_nps_vpn']" in page, False)
ok('the command line takes the old name as the new',
   "key = 'ban_from_nps' if key.strip() == 'judge_nps_vpn' else key" in source, True)

print('\nThe bans of before, read again')
isemon.CONFIG.update({'ise': 0, 'nps': 1})
now = time.time()
with store.db_write() as db:
    for ip, src in (('203.0.113.60', 'ise'), ('203.0.113.61', 'ise'), ('203.0.113.62', None)):
        db.execute('INSERT INTO blocked (ip, since, until, why, hits, auto, by, src) '
                   "VALUES (?, ?, NULL, 'old', 0, 1, '', ?)", (ip, now, src))
store.add_failed({'session': 'x1', 'ts': now - 50, 'ip': '203.0.113.61', 'username': 'u',
                  'kind': 'vpn', 'device': 'FTD'})
store.block('91.1.1.0/24', None, 'folded', auto=True, src='ise')
store.set_meta('blocked_members_91.1.1.0/24', json.dumps(
    [{'ip': '91.1.1.1', 'auto': True}, {'ip': '91.1.1.2', 'auto': False}]))
store.set_meta('ban_src_filled', '1')          # as 1.10.193 left it
daemon.ban_sources_fill()
got = {r['ip']: r['src'] for r in store.blocked_all()}
ok('no refusal left and the ISE logs not read: the VPN through NPS',
   (got['203.0.113.60'], got['203.0.113.62']), ('nps', 'nps'))
ok('one that really failed at ISE’s VPN stays ISE’s', got['203.0.113.61'], 'ise')
ok('a folded subnet is what its addresses were, each written down',
   (got['91.1.1.0/24'], sorted(m['src'] for m in daemon.fold_members('91.1.1.0/24'))),
   ('nps,manual', ['manual', 'nps']))
ok('...once', daemon.ban_sources_fill(), 0)

print('\nThe card')
ok('the numbers under headings that say so, and the buttons said whole',
   # (three numbers since 1.10.195)
   ("head.appendChild(el('th', i >= 2 && i <= 4 ? 'num' : '', h));" in page,
    "cmdButton('Let every ban of this source go'" in page), (True, True))
ok('no setting says any more that nothing of the domain or the firewall earns a ban',
   ('Nothing here is ever judged and nothing here can earn anybody a ban.">Domain' in page,
    'Nothing read here is ever judged</b> and nothing here can earn anybody a' in source),
   (False, False))

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
