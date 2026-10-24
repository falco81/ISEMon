#!/usr/bin/env python3
"""1.10.197: a review of the whole program. Bans only watched that a door
that bans carried at the first refusal, or lengthened from a door switched
off; a source let go twice in the history; watched bans made again from the
attempts they were made for; the header going below nought; addresses written
in capitals never banned; a pfSense whose apply failed never applied; ended
bans kept on a pf table with the blacklist off; an access list written under
another name; a domain account switched off under one name signing in under
the other; a ban admin letting everybody in a source at a time; and the page
saying "kept out" of a ban nobody carries.

    ./test/fixes197.py
"""
import json
import shutil
import sys
import tempfile
import time
import types
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
installer = (HERE.parent / 'install.sh').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-197-')
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


def events(ip):
    with store.db_write() as db:
        return [r['what'] for r in db.execute(
            'SELECT what FROM block_events WHERE ip=? ORDER BY ts', (ip,))]


def winfails(ip, tag, n=4):
    t = time.time()
    with store.db_write() as db:
        for i in range(n):
            db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, ip) '
                       "VALUES (?, ?, 'dc1', 4625, 'logon-failed', 'administrator', ?)",
                       ('%s%d' % (tag, i), t - 60 + i, ip))


SEQ = [0]


def vpnfail(ip, ts=None, kind='vpn'):
    ts = ts or time.time()
    with store.db_write() as db:
        SEQ[0] += 1
        db.execute('INSERT INTO failed (session, ts, ip, username, device, kind, reason, code) '
                   'VALUES (?,?,?,?,?,?,?,?)', ('t197-%d' % SEQ[0], ts, ip, 'bob', 'ftd1', kind,
                                                'bad pw', '24408'))
    return types.SimpleNamespace(ts=ts)


def modes(**kw):
    daemon.save_settings({'ban_from_%s' % k: v for k, v in kw.items()}, by='test')


print('\nA ban nobody carries is no closed door to a door that bans')
modes(win='watch')
ip = '81.200.11.7'
winfails(ip, 'a')
daemon.judge_sources()
daemon.judge_refusal(ip, vpnfail(ip), ['ftd1'], door='ise')
row = store.blocked_one(ip)
ok('one refusal at the VPN does not carry a watched ban', (row['src'], ip in carried(),
                                                            ip in feed()), ('win', False, False))
for _ in range(2):
    daemon.judge_refusal(ip, vpnfail(ip), ['ftd1'], door='ise')
row = store.blocked_one(ip)
ok('...the bar reached there does, and the ladder counts it',
   (row['src'], ip in carried(), store.blocked_before(ip)), ('ise,win', True, 1))

modes(win='on')
for n, one in enumerate(('81.200.12.1', '81.200.12.2', '81.200.12.3')):
    store.block(one, None, 'x', auto=True, src='win')
daemon.fold_apply(24, by='test')
modes(win='watch')
ok('a folded subnet only watched', '81.200.12.0/24' in [r['ip'] for r in store.blocked_all()]
   and '81.200.12.0/24' not in carried())
daemon.judge_refusal('81.200.12.200', vpnfail('81.200.12.200'), ['ftd1'], door='ise')
ok('a neighbour failing once does not carry the street',
   ('81.200.12.0/24' in carried(), (store.blocked_one('81.200.12.0/24') or {}).get('src')),
   (False, 'win'))
winfails('81.200.12.201', 'n')
modes(win='on')
modes(win='watch')
isemon.CONFIG['ban_from_fw'] = 'on'
with store.db_write() as db:
    for i in range(4):
        db.execute("INSERT INTO fw_events (ident, ts, verdict, srcip, usr, type, sub, action, "
                   "brief) VALUES (?, ?, 'fail', '81.200.12.202', 'root', 'event', 'vpn', "
                   "'login-fail', 0)", ('nb%d' % i, time.time() - 30 + i))
daemon.judge_sources()
ok('...and a source that bans bans the neighbour as itself, not the street',
   ('81.200.12.202' in carried(), '81.200.12.0/24' in carried(),
    (store.blocked_one('81.200.12.202') or {}).get('src')), (True, False, 'fw'))
isemon.CONFIG['ban_from_fw'] = 'off'

ip = '81.200.13.5'
isemon.CONFIG['ban_from_manual'] = 'off'
store.block(ip, None, 'by hand: known attacker', auto=False, by='admin', src='manual')
for _ in range(3):
    daemon.judge_refusal(ip, vpnfail(ip), ['ftd1'], door='ise')
row = store.blocked_one(ip)
ok('a ban by hand nobody carried, earned at the VPN: carried, and kept as it was made',
   (row['src'], row['until'], row['auto'], row['by'], ip in carried()),
   ('ise,manual', None, 0, 'admin', True))
isemon.CONFIG['ban_from_manual'] = 'on'

print('\nOne tally for a door that bans, another for one only watched')
modes(win='off', ise='watch', nps='on')
ip = '81.200.14.1'
t = time.time()
for i, kind in enumerate(('nps-vpn', 'nps-vpn')):
    daemon.judge_refusal(ip, vpnfail(ip, t - 30 + i, kind), ['ftd1'], door='nps',
                         watched_list=False)
daemon.judge_refusal(ip, vpnfail(ip, t - 20), ['ftd1'], door='ise')
row = store.blocked_one(ip) or {}
ok('two at a door that bans and one only watched are not three: a ban only watched',
   (row.get('src'), ip in carried(), events(ip)), ('ise', False, ['watched']))
ip = '81.200.14.2'
for i in range(3):
    daemon.judge_refusal(ip, vpnfail(ip, t - 30 + i, 'nps-vpn'), ['ftd1'], door='nps',
                         watched_list=False)
ok('three at the door that bans: carried, as before', (store.blocked_one(ip) or {}).get('src'),
   'nps')

print('\nA door switched off lengthens nothing')
modes(ise='off', nps='on')
ip = '81.200.15.1'
for i in range(3):
    daemon.judge_refusal(ip, vpnfail(ip, t - 60 + i, 'nps-vpn'), ['ftd1'], door='nps',
                         watched_list=False)
until = store.blocked_one(ip)['until']
for i in range(3):
    daemon.judge_refusal(ip, vpnfail(ip, t + i + 1), ['ftd1'], door='ise')
ok('three refusals at a door switched off', (store.blocked_one(ip)['until'], events(ip)),
   (until, ['blocked']))
modes(ise='on', nps='on')

print('\nThe history of a source let go')
modes(win='watch')
winfails('81.200.16.1', 'r')
daemon.judge_sources()
daemon.ban('81.200.16.2', minutes=60, why='x', by='boss')
daemon.ban_release_source('win', by='boss')
daemon.ban_release_source('manual', by='boss')
ok('one line for each, as it was', (events('81.200.16.1'), events('81.200.16.2')),
   (['watched', 'watch ended'], ['blocked', 'let back in']))
ok('...and a watched one moves no floor', store.let_back_in_at('81.200.16.1'), 0.0)

print('\nA watched ban that ran out is not made again from the same attempts')
isemon.CONFIG['block_window_min'] = 60
modes(ise='watch')
ip = '81.200.18.2'
for i in range(3):
    rec = vpnfail(ip, time.time() - 1200 + i)
daemon.maybe_block(ip, rec, door='ise')
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (time.time() - 1, ip))
store.sweep_expired()
daemon.judge_refusal(ip, vpnfail(ip), ['ftd1'], door='ise')
ok('one attempt after it ran out', (store.blocked_one(ip), sorted(events(ip))),
   (None, ['watch ended', 'watched']))
isemon.CONFIG['block_window_min'] = 10

print('\nSwitched on: carried from now, on the ladder and as the floor')
ip = '81.200.19.1'
for i in range(3):
    rec = vpnfail(ip, time.time() - 30 + i)
daemon.maybe_block(ip, rec, door='ise')
modes(ise='on')
ok('a watched ban carried from the moment its source is on', (ip in carried(), events(ip),
                                                              store.blocked_before(ip)),
   (True, ['watched', 'blocked'], 1))
store.unblock(ip, by='boss')
ok('...and its end is a ban let go', events(ip)[-1], 'let back in')
modes(ise='watch')
ip = '81.200.19.2'
store.block(ip, None, 'x', auto=True, src='nps')
modes(nps='watch')
store.unblock(ip, by='boss')
ok('a ban carried and then watched ended a real one', events(ip), ['blocked', 'let back in'])
modes(ise='on', nps='on')

print('\nThe header and the states')
isemon.CONFIG['ban_from_win'] = 'watch'
store.block('81.200.20.1', None, 'x', auto=True, src='win', watch=True)
store.block('81.200.20.2', None, 'x', auto=True, src='win', watch=True)
st = daemon.status()['blocked']
ok('for good is counted out of what is carried: never below nought', st['temporary'] >= 0)
got = store.blocked_states(['81.200.20.1', '81.200.14.2'])
ok('each state says whether it is carried',
   [(got.get(a) or {}).get('carried') for a in ('81.200.20.1', '81.200.14.2')], [False, True])
ok('...and whether it is only watched', (got.get('81.200.20.1') or {}).get('watched'), True)
ok('the page draws a ban nobody carries without the red bar',
   "state.carried !== false" in page and "'only watched' : 'not carried'" in page)
ok('...and the history does not say it cannot reach the VPN',
   "'still on, only watched'" in page)

print('\nAddresses as the log wrote them')
isemon.CONFIG['ban_from_fw'] = 'on'
with store.db_write() as db:
    for i in range(4):
        for one in ('::ffff:81.200.21.5', '2A01:430:17::5'):
            db.execute("INSERT INTO fw_events (ident, ts, verdict, srcip, usr, type, sub, "
                       "action, brief) VALUES (?, ?, 'fail', ?, 'root', 'event', 'vpn', "
                       "'ssl-login-fail', 0)", ('%s%d' % (one, i), time.time() - 30 + i, one))
daemon.judge_sources()
ok('banned under the tidy spelling', (store.blocked_one('81.200.21.5') is not None,
                                      store.blocked_one('2a01:430:17::5') is not None),
   (True, True))
isemon.CONFIG['ban_from_fw'] = 'off'
store.set_meta('srccharged_fw_81.200.99.9', repr(time.time() - 30 * 86400))
store.tidy_ban_marks()
ok('old source charge marks are let go', store.get_meta('srccharged_fw_81.200.99.9') or None,
   None)
ok('a change of what is watched read from the file follows',
   'sources_were != (ban_sources_on(), ban_sources_watched())' in source)

print('\nFirewalls')
isemon.PfrestApi._owed_apply.clear()


class FakePf(isemon.PfrestApi):
    calls = []
    fail_apply = [True]
    config = ['192.0.2.1']

    def __init__(self):
        self.base = 'https://pf.test'

    def call(self, method, path, body=None):
        FakePf.calls.append((method, path))
        if path.endswith('/aliases?limit=0'):
            return [{'id': 1, 'name': 'isemon_ban', 'address': list(FakePf.config)}]
        if method == 'PATCH':
            FakePf.config = list(body['address'])
            return {}
        if path.endswith('/apply'):
            if FakePf.fail_apply[0]:
                raise RuntimeError('filter reload timed out')
            return {}
        return {}


pf = FakePf()
try:
    pf.change('isemon_ban', [], ['45.9.148.9'])
except RuntimeError:
    pass
FakePf.fail_apply[0] = False
FakePf.calls.clear()
pf.apply_owed()
ok('a pfSense whose apply failed is applied at the next sync',
   [c for c in FakePf.calls if c[1].endswith('/apply')], [('POST', '/api/v2/firewall/apply')])
FakePf.calls.clear()
pf.apply_owed()
ok('...once', FakePf.calls, [])
ok('the sync asks for it when nothing changed', "driver.apply_owed()" in source)
ok('ended bans leave a pf table with the blacklist off too',
   "if int(CONFIG.get('mikrotik_sync') or 0):\n            return\n        walls = [fw for fw"
   in source)
isemon.CONFIG['ios_acl_name'] = 'EDGE.IN-v4'
said = daemon.ios_acl('EDGE.IN-v4')
text = said if isinstance(said, str) else json.dumps(said)
ok('the access list is written under the name saved', 'EDGE.IN-v4' in text and
   'EDGEIN-v4' not in text)
ok('an IPv6 host in brackets reaches ssh without them',
   isemon._ssh_argv({'ssh_user': 'root'}, '[2001:db8::1]')[-1], '2001:db8::1')
ok('a busy flag never stays set when its thread cannot start',
   source.count("self._pf_letting_go = False\n            raise") == 1
   and source.count("self._clearing_owed = False\n            raise") == 1)

print('\nAccounts')
daemon.add_user('boss', 'password123', 'fulladmin')
daemon.add_user('banner', 'password123', 'banadmin')
isemon.CONFIG.update({'directory': 1, 'directory_host': 'dc.example', 'directory_base': 'dc=corp'})
daemon.directory_on = lambda which='directory': True


def fake_sign_in(name, password):
    name = name.strip().lower()
    if name in ('jnovak', 'jnovak@corp.example') and password == 'Domain-Pass1':
        return {'dn': 'CN=Jan Novak,DC=corp', 'name': name, 'role': 'fulladmin',
                'display': 'Jan', 'mail': '', 'groups': ['admins']}
    return None


daemon.directory_sign_in = fake_sign_in
daemon.login('jnovak', 'Domain-Pass1', ip='10.0.0.6')
daemon.login('jnovak@corp.example', 'Domain-Pass1', ip='10.0.0.6')
daemon.switch_user('jnovak', True, by='boss', me='boss')
refused = []
for name in ('jnovak', 'jnovak@corp.example'):
    try:
        daemon.login(name, 'Domain-Pass1', ip='10.0.0.7')
        refused.append(False)
    except isemon.Refused:
        refused.append(True)
ok('a domain account switched off is off under both its names', refused, [True, True])
ok('...and both rows say so', [bool((store.user(n) or {}).get('disabled'))
                               for n in ('jnovak', 'jnovak@corp.example')], [True, True])
daemon.switch_user('jnovak', False, by='boss', me='boss')
ok('...and on again under both', daemon.login('jnovak@corp.example', 'Domain-Pass1',
                                               ip='10.0.0.8').get('role'), 'fulladmin')
ok('letting a source go is a full administrator\'s',
   "me = self.need_admin()\n            if not me:\n                return None\n"
   "            data = self.body()\n            source = str(data.get('release')" in source
   and 'b.disabled = !one.bans || !ADMIN;' in page)

print('\nThe page, the installer, the database')
ok('a list of firewalls compared as what it is when saved',
   'JSON.stringify(DIRTY[k]) === JSON.stringify(want[k])' in page)
ok('...and as drawn when edited', 'box._initial = JSON.stringify(box._get());' in page)
ok('bans by hand read "watch" as on, as the daemon does',
   "return m === 'watch' && modes.indexOf('on') >= 0 ? 'on' : 'off';" in page)
ok('the sources asked again on the Banned page', 'Date.now() - (SOURCES_AT || 0) > 60000' in page)
ok('MariaDB indexes a long text column by its first characters', "(\\\\1(191), ts)" in source
   or "r'(\\1(191), ts)'" in source)
ok('a restore writes down where its bans came from',
   "where the restored bans came from" in source)
ok('Debian: the ssh client by its name there', 'ssh_pkg="openssh-client"' in installer)
ok('Debian: its php-fpm restarted and its socket in the vhost',
   'php_fpm_units()' in installer and '/run/php/php*-fpm.sock' in installer)
ok('a short --admin-password said at once',
   '--admin-password needs at least eight characters' in installer)
rot = (HERE.parent / 'deploy' / 'remote-logs.logrotate').read_text(encoding='utf-8')
ok('rsyslog told to reopen on Debian too', 'kill -s HUP --kill-who=main rsyslog.service' in rot)

print('\nThe core')
before = isemon.CONFIG.get('block_tries')
store.settings_write({'block_tries': 8}) if hasattr(store, 'settings_write') else None
daemon._settings_serial = None
daemon._config_stamp = isemon.config_file_stamp()
isemon.FILE_CONFIG['block_tries'] = 5
try:
    daemon._settings_read_again()
except Exception as e:                                  # noqa: BLE001
    print('    (%s)' % e)
ok('a setting taken out underneath falls back to the file, not to what ran',
   'whole = dict(FILE_CONFIG)\n            _lay_saved(whole, saved)' in source)
bad = Path(folder) / 'broken.json'
bad.write_text('{"db_host": "db1", "db_password": "x",}\n', encoding='utf-8')
try:
    isemon.write_file_settings({'db_timeout_s': 20}, path=bad)
    refused = False
except isemon.StorageError:
    refused = True
ok('a config.json that does not read is not written over', (refused, bad.read_text(
    encoding='utf-8')), (True, '{"db_host": "db1", "db_password": "x",}\n'))
isemon.CONFIG['ban_from_win'] = 'on'
winfails('81.200.30.1', 'c')
store.clear_counting()
ok('the counting started again holds for the sources counted apart',
   (daemon.judge_sources(), store.blocked_one('81.200.30.1')), (0, None))
ok('a HUP leaves the files being followed where they are',
   'self.restore_tails(keep_live=True)' in source)
line = 'date=2024-01-01 time=10:00:00 devname="fw1" msg="abc' + 'x' * 60000
t0 = time.time()
isemon.FG_PAIRS.findall(line)
ok('a FortiGate line with a value cut short is read in no time', time.time() - t0 < 0.5)
ok('an option without its command does not start a daemon',
   "says how to do something, and nothing was asked for" in source)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
