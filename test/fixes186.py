#!/usr/bin/env python3
"""1.10.186: a host setting that cannot hang the check, the live database told
apart from another however it is spelled, a list name the router will really
use, accounts changed one at a time, the refusals counted through an index,
and the busiest jobs of the night made cheaper.

    ./test/fixes186.py
"""
import shutil
import socket
import sys
import tempfile
import threading
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


def refused(fn, *args):
    try:
        fn(*args)
    except (ValueError, isemon.StorageError):
        return True
    return False


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-186-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nA host name is checked in a moment, however it is typed')
began = time.time()
for bad in ('a' * 60 + '-' * 30 + '!', ('a-' * 40000) + '!', 'a' + '.a' * 3000 + '-'):
    refused(isemon.check_setting, 'mikrotik_host', bad)
ok('names built to make a pattern go back and forth for ever are refused at once',
   time.time() - began < 1.0)
ok('an ordinary name, an address and a bracketed IPv6 are let through',
   [isemon.check_setting('mikrotik_host', h) for h in
    ('router.example.org', '192.0.2.1', '[2001:db8::1]')],
   ['router.example.org', '192.0.2.1', '[2001:db8::1]'])
ok('...and a dash in front, a dot at the end or a space are not',
   [refused(isemon.check_setting, 'mikrotik_host', h)
    for h in ('-oProxyCommand=x', 'router.', 'a b')], [True, True, True])

print('\nThe database in use, however its server is spelled')
live = {'engine': 'postgres', 'name': 'isemon', 'host': 'localhost'}
ok('127.1, 127.0.0.2, [::1], ::ffff:127.0.0.1, localhost.localdomain and this '
   'machine’s own name are the server right here',
   [isemon.same_database(dict(live, host=h), live)
    for h in ('127.1', '127.0.0.2', '[::1]', '::ffff:127.0.0.1', 'localhost.localdomain',
              socket.gethostname())], [True] * 6)
ok('another server is another server', isemon.same_database(dict(live, host='192.0.2.9'), live),
   False)
ok('the same words are the same server', isemon.same_database(
    dict(live, host='192.0.2.9'), dict(live, host='192.0.2.9')), True)
ok('another database on the same server is another database',
   isemon.same_database(dict(live, name='spare'), live), False)

print('\nThe name of the address list')
ok('one the router would be given differently is said at once',
   [refused(isemon.check_setting, k, v) for k, v in
    (('mikrotik_list', 'isemon bans'), ('geolist_name', 'geo;x'), ('mikrotik_list', 'x' * 41))],
   [True, True, True])
ok('...an ordinary one, and an empty country list, are not',
   (isemon.check_setting('mikrotik_list', 'isemon-bans'), isemon.check_setting('geolist_name', '')),
   ('isemon-bans', ''))
isemon.CONFIG['mikrotik_list'] = 'old name'
ok('...and one already in use is not stopped from being saved again',
   isemon.check_setting('mikrotik_list', 'old name'), 'old name')
isemon.CONFIG['mikrotik_list'] = isemon.DEFAULTS['mikrotik_list']

print('\nWhat the router holds, with only the second router in use')
ok('asked for whenever any router is written to, not only the first',
   "if not daemon.firewalls():\n" in source and
   source.index("if not daemon.firewalls():\n") < source.index("'router-picture', 15"), True)

print('\nAccounts changed one at a time')
store.put_user('one', password='x' * 12, role='fulladmin', by='t')
store.put_user('two', password='x' * 12, role='fulladmin', by='t')
for u in store.users():
    if u.get('role') == 'fulladmin' and u.get('name') not in ('one', 'two'):
        store.put_user(u['name'], role='readonly')
errors = []
gate = threading.Barrier(2)


def demote(name):
    gate.wait()
    try:
        daemon.set_role(name, 'readonly', by='t')
    except isemon.StorageError as e:
        errors.append(str(e))


pair = [threading.Thread(target=demote, args=(n,)) for n in ('one', 'two')]
for t in pair:
    t.start()
for t in pair:
    t.join()
ok('two full administrators demoting each other at once leave one of them',
   store.admin_count() >= 1, True)
ok('...and the other is told why', len(errors), 1)
ok('switching off, a role and removing all wait their turn',
   source.count('        with self.ACCOUNTS_LOCK:') >= 3, True)

print('\nRefusals counted through an index')
isemon.CONFIG['judge_nps_vpn'] = 0
ok('the VPN as two plain comparisons, not a function of the column',
   isemon.judged_sql(), "(kind='vpn' OR kind IS NULL)")
isemon.CONFIG['judge_nps_vpn'] = 1
ok('...the same with the VPN through NPS', isemon.judged_sql(),
   "(kind='vpn' OR kind IS NULL OR (kind='nps-vpn' AND COALESCE(code,'')<>'abandoned'))")
now = time.time()
for n, kind in enumerate(['vpn', None, 'dot1x-lan', 'nps-vpn', 'vpn']):
    store.add_failed({'session': 's186-%d' % n, 'ts': now - 30 + n, 'ip': '198.51.100.%d' % (n + 1),
                      'username': 'u%d' % (n % 2), 'kind': kind, 'device': 'D'})
with store.db_write() as db:
    db.execute("UPDATE failed SET kind = NULL WHERE session = 's186-1'")
got = sorted(r['ip'] for r in store.counting_now(now - 600))
ok('the same addresses counted: the VPN, the ones with no door written, NPS, never a socket',
   got, ['198.51.100.1', '198.51.100.2', '198.51.100.4', '198.51.100.5'])
ok('the names being tried are counted the same way',
   sorted((r['username'], r['tries']) for r in store.top_users(now - 600, 10, 'failed')),
   [('u0', 2), ('u1', 2)])

print('\nThe night’s work')
ok('the firewall’s gauges are read from the one day they are in',
   "fw_get(r['ident'], r.get('ts') or 0)" in source, True)
ok('the counted domain answers are summed over three days once a day, six hours otherwise',
   ('ROLL_RECENT_S = 6 * 3600' in source, "store.set_meta('win_roll_whole_at'" in source),
   (True, True))
ok('yesterday frozen and counted once, on PostgreSQL, behind the daemon',
   ("self.behind('settle', self.store.settle_yesterday" in source,
    store.settle_yesterday()), (True, ''))
ok('...by the name its day really has',
   isemon.Storage.split_day_name('fw_events', 86400 * 3), 'fw_events_p19700104')

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
