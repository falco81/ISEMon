#!/usr/bin/env python3
"""1.10.193: where the bans come from - a switch a source, every ban saying
what made it, one list carried made of the sources switched on, a source
switched off and on again with its bans kept, every ban of a source let go,
folding that follows the sources, and three new sources counted from the
logs already read: logins to network devices, at the firewall and at the
domain, from the internet only.

    ./test/fixes193.py
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
folder = tempfile.mkdtemp(prefix='isemon-193-')
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


def carried():
    return sorted(isemon.same_address(r['ip']) for r in daemon._blocked_for_router())


def feed():
    daemon._banfeed_cache = {}
    return sorted(w for w, _r in daemon.banfeed_entries())


now = time.time()
print('\nThe sources')
ok('the two that always were are on, the new ones off',
   sorted(isemon.ban_sources_on()), ['ise', 'manual', 'nps'])
ok('every source has a switch, a name and words',
   [k for k in isemon.BAN_SOURCES if not all(
       ('ban_from_%s' % k) in t for t in (daemon.TUNABLE, daemon.NAMES, daemon.SAYS))], [])

print('\nA ban from before there were sources')
with store.db_write() as db:
    db.execute("INSERT INTO blocked (ip, since, until, why, hits, auto, by) "
               "VALUES ('203.0.113.50', ?, NULL, 'old', 0, 1, '')", (now,))
    db.execute("INSERT INTO blocked (ip, since, until, why, hits, auto, by) "
               "VALUES ('203.0.113.51', ?, NULL, 'old', 0, 0, 'boss')", (now,))
    db.execute("INSERT INTO blocked (ip, since, until, why, hits, auto, by) "
               "VALUES ('203.0.113.52', ?, NULL, 'old', 0, 1, '')", (now,))
store.add_failed({'session': 'n1', 'ts': now - 50, 'ip': '203.0.113.52', 'username': 'u',
                  'kind': 'nps-vpn', 'device': 'NPS'})
ok('is read as what it was until it is written down',
   [isemon.ban_src_of(r) for r in store.blocked_all() if r['ip'].startswith('203.0.113.5')],
   [('ise',), ('manual',), ('ise',)])
daemon.ban_sources_fill()
ok('...and written down once: the counting, by hand, the VPN through NPS',
   {r['ip']: r['src'] for r in store.blocked_all()},
   {'203.0.113.50': 'ise', '203.0.113.51': 'manual', '203.0.113.52': 'nps'})
for ip in ('203.0.113.50', '203.0.113.51', '203.0.113.52'):
    store.unblock(ip)

print('\nThe VPN, counted as before')
for i in range(3):
    store.add_failed({'session': 'v%d' % i, 'ts': now - 30 + i, 'ip': '45.9.148.9',
                      'username': 'admin', 'kind': 'vpn', 'device': 'FTD'})
daemon.maybe_block('45.9.148.9', isemon._AtTime(now), door='ise')
ok('banned, from the VPN through ISE', (store.blocked_one('45.9.148.9') or {}).get('src'), 'ise')
daemon.ban('198.51.100.7', minutes=None, why='by hand', by='boss')
ok('a ban by hand is by hand', (store.blocked_one('198.51.100.7') or {}).get('src'), 'manual')
daemon.ban('45.9.148.9', minutes=None, why='and by hand', by='boss')
ok('a ban by hand over the counting’s is both',
   (store.blocked_one('45.9.148.9') or {}).get('src'), 'ise,manual')
ok('everything is carried', carried(), ['198.51.100.7', '45.9.148.9'])

print('\nA source switched off, and on again')
daemon.save_settings({'ban_from_manual': 0}, by='test')
ok('what only it stood behind is carried nowhere',
   (carried(), feed()), (['45.9.148.9'], ['45.9.148.9']))
ok('...but is kept', sorted(r['ip'] for r in store.blocked_all()),
   ['198.51.100.7', '45.9.148.9'])
rows = {r['ip']: r for r in daemon._blocked_list_now()}
ok('the Banned page says so, and why', (rows['198.51.100.7']['src_off'],
                                        rows['45.9.148.9']['src_off'],
                                        rows['45.9.148.9']['src_on']),
   (True, False, ['ise']))
ok('the access list leaves it out too', '198.51.100.7' in daemon.ios_acl(), False)
daemon.save_settings({'ban_from_manual': 1}, by='test')
ok('switched on again, it is carried again', carried(), ['198.51.100.7', '45.9.148.9'])
daemon.save_settings({'ban_from_ise': 0}, by='test')
for i in range(3):
    store.add_failed({'session': 'w%d' % i, 'ts': now - 20 + i, 'ip': '45.9.148.10',
                      'username': 'admin', 'kind': 'vpn', 'device': 'FTD'})
ok('a source switched off makes no new bans',
   daemon.maybe_block('45.9.148.10', isemon._AtTime(now), door='ise'), None)
ok('...nor the pass over what is over the bar', (daemon.judge_anything_missed(),
                                                 store.blocked_one('45.9.148.10')), (0, None))
daemon.save_settings({'ban_from_ise': 1}, by='test')

print('\nEvery ban of one source let go')
said = daemon.ban_release_source('manual', by='boss')
ok('the ones it alone stood behind go, the others stay for their other source',
   (said['let_go'], said['kept'], sorted(r['ip'] for r in store.blocked_all()),
    (store.blocked_one('45.9.148.9') or {}).get('src')),
   (1, 1, ['45.9.148.9'], 'ise'))

print('\nThe sources counted by a pass of their own')
isemon.CONFIG.update({'ban_from_fw': 1, 'ban_from_win': 1, 'ban_from_tacacs': 1})
with store.db_write() as db:
    for i in range(4):
        for ip in ('81.200.10.5', '10.1.2.3'):
            db.execute("INSERT INTO fw_events (ident, ts, verdict, srcip, usr, type, sub, action, "
                       "brief) VALUES (?, ?, 'fail', ?, 'root', 'event', 'vpn', 'login-fail', 0)",
                       ('f%s%d' % (ip, i), now - 60 + i, ip))
            # ...and a tunnel that would not come up, which is not a sign-in.
            db.execute("INSERT INTO fw_events (ident, ts, verdict, srcip, type, sub, action, "
                       "area, brief) VALUES (?, ?, 'fail', '81.200.14.1', 'event', 'vpn', "
                       "'tunnel-fail', 's2s-vpn', 0)", ('s%d' % i if ip == '10.1.2.3' else
                                                        's%dx' % i, now - 60 + i))
        db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, ip) '
                   "VALUES (?, ?, 'dc1', 4625, 'logon-failed', 'administrator', ?)",
                   ('w%d' % i, now - 60 + i, '81.200.11.7'))
for i in range(4):
    store.add_failed({'session': 't%d' % i, 'ts': now - 40 + i, 'ip': '81.200.12.9',
                      'username': 'cisco', 'kind': 'tacacs', 'device': 'SW1'})
store.add_failed({'session': 't9', 'ts': now - 39, 'ip': '45.9.148.9', 'username': 'cisco',
                  'kind': 'tacacs', 'device': 'SW1'})
for i in range(3):
    store.add_failed({'session': 'tt%d' % i, 'ts': now - 38 + i, 'ip': '45.9.148.9',
                      'username': 'cisco', 'kind': 'tacacs', 'device': 'SW1'})
made = daemon.judge_sources()
src = {r['ip']: r['src'] for r in store.blocked_all()}
ok('the firewall, the domain and the devices each ban what reached the bar',
   (made, src.get('81.200.10.5'), src.get('81.200.11.7'), src.get('81.200.12.9')),
   (3, 'fw', 'win', 'tacacs'))
ok('...never an address inside the network', '10.1.2.3' in src, False)
ok('...nor a site-to-site partner whose tunnel would not come up', '81.200.14.1' in src, False)
ok('an address already banned is written down as banned by it as well',
   src.get('45.9.148.9'), 'ise,tacacs')
ok('...and the same attempts are not charged again', daemon.judge_sources(), 0)
daemon.save_settings({'ban_from_ise': 0}, by='test')
ok('so switching the VPN off still carries it, for the devices',
   '45.9.148.9' in carried(), True)
daemon.save_settings({'ban_from_ise': 1}, by='test')

print('\nFolding follows the sources')
for ip, s in (('91.92.93.1', 'win'), ('91.92.93.2', 'win'), ('91.92.93.3', 'fw')):
    store.block(ip, None, 'x', auto=True, src=s)
plan = daemon.fold_plan(24)
grp = [g for g in plan['groups'] if g['net'] == '91.92.93.0/24']
ok('the members carry their sources into the plan',
   sorted(m['src'] for m in grp[0]['members']) if grp else None, ['fw', 'win', 'win'])
daemon.fold_apply(24, by='test')
ok('the subnet is from all of them', (store.blocked_one('91.92.93.0/24') or {}).get('src'),
   'fw,win')
isemon.CONFIG['ban_from_fw'] = 0
ok('one of three off, two still enough for the street (fold_least 2)',
   '91.92.93.0/24' in carried(), True)
isemon.CONFIG['ban_from_win'] = 0
isemon.CONFIG['ban_from_fw'] = 1
ok('two of three off: the one left is carried as itself, not the street',
   ('91.92.93.0/24' in carried(), '91.92.93.3' in carried(),
    '91.92.93.1' in carried()), (False, True, False))
isemon.CONFIG['ban_from_fw'] = 0
ok('all off: nothing of it', [a for a in carried() if a.startswith('91.92.93.')], [])
isemon.CONFIG.update({'ban_from_fw': 1, 'ban_from_win': 1})
ok('all on again: the street', '91.92.93.0/24' in carried(), True)
said = daemon.ban_release_source('win', by='boss')
ok('letting the domain’s go takes its addresses out, and one left is too few for '
   'the street: it is banned as itself, with its own source',
   (said['let_go'], store.blocked_one('91.92.93.0/24'),
    (store.blocked_one('91.92.93.3') or {}).get('src'), '91.92.93.1' in carried()),
   (3, None, 'fw', False))      # .1, .2 and the domain's own 81.200.11.7
isemon.CONFIG.update({'ban_from_fw': 0, 'ban_from_win': 0, 'ban_from_tacacs': 0})

print('\nCarried with the configuration')
out = daemon.export_config() if hasattr(daemon, 'export_config') else None
if out is None:
    out = {'blocked': [{'ip': r['ip'], 'src': isemon.ban_src_join(isemon.ban_src_of(r))}
                       for r in store.blocked_all()]}
ok('an export says where each ban came from',
   {r['ip']: r.get('src') for r in out['blocked']}.get('81.200.10.5'), 'fw')

print('\nWhat a review of it found')
isemon.CONFIG['ban_from_manual'] = 0
daemon.ban('45.1.1.1', minutes=None, why='by hand', by='boss')
for i in range(3):
    store.add_failed({'session': 'r%d' % i, 'ts': time.time() - 5 + i, 'ip': '45.1.1.1',
                      'username': 'x', 'kind': 'vpn', 'device': 'FTD'})
    daemon.judge_refusal('45.1.1.1', isemon._AtTime(time.time()), ['FTD'], door='ise')
ok('banned by hand with that switched off, and attacking the VPN: carried, for the VPN',
   ((store.blocked_one('45.1.1.1') or {}).get('src'), '45.1.1.1' in carried()),
   ('ise,manual', True))
isemon.CONFIG['ban_from_manual'] = 1
with store.db_write() as db:
    db.execute("INSERT INTO blocked (ip, since, until, why, hits, auto, by, src) "
               "VALUES ('45.2.2.2', ?, ?, 'ran out', 0, 1, '', 'fw')", (now - 900, now - 60))
store.block('45.2.2.2', None, 'again', auto=True, src='ise')
ok('a ban that ran out, not swept yet, does not lend its sources to the next',
   (store.blocked_one('45.2.2.2') or {}).get('src'), 'ise')
ok('a new subnet folded is said among the subnets made',
   "                made.append(net)\n            else:" in source, True)
ok('a source switched by the command line is followed at once',
   'if sources_were != (ban_sources_on(), ban_sources_watched()):' in source, True)
ok('the marks of the counted sources are not swept away as addresses',
   ("'srccharged_%s_%s' % (source, ip)" in source,
    "'blocked_charged_%s_%s' % (source, ip)" in source), (True, False))
ok('the firewall\u2019s source: sign-ins only, never a tunnel, within an hour',
   ("COALESCE(area, '') <> 's2s-vpn'" in source,
    'window = min(3600, max(60,' in source), (True, True))

print('\nThe API, the page and the command line')
state = daemon.ban_sources_state()
ok('each source with its bans and how many are carried',
   {one['key']: (one['on'], one['bans'], one['carried']) for one in state['sources']}['fw'],
   (False, 2, 0))
isemon.CONFIG['ban_from_ise'] = 1
ok('an address already banned, trying through a door that is on, is that door’s too',
   (daemon.ban_add_source('91.92.93.3', 'ise'),
    (store.blocked_one('91.92.93.3') or {}).get('src')), (True, 'ise,fw'))
ok('the page has the card, the switches and the group of bans not carried',
   ("sources: ['ban_from_ise'" in page, 'function drawSources()' in page,
    "'Not carried: their source is switched off'" in page,
    "['source', 'where the ban came from" in page), (True, True, True, True))
ok('the command line', ("'--ban-sources'" in source, "'--unban-source'" in source,
                        '(args.ban_sources, cmd_ban_sources)' in source), (True, True, True))

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
