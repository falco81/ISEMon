#!/usr/bin/env python3
"""1.10.228: Settings → Time, after otp's (1.0.120) - the clock as chrony
sees it, read by root every minute; a step now; and the time servers, when
isemon is to set them, put into /etc/chrony.conf between marks (the file's
own lines commented out, and put back when switched off). chronyc and
timedatectl are small scripts here, so nothing of this machine's clock is
read or touched.

    ./test/fixes228_ntp.py
"""
import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19700 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-228-ntp-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
stub = work / 'stub'
stub.mkdir()
CALLS = stub / 'calls'
CONF = work / 'chrony.conf'
OWN = ('# Use public servers from the pool.ntp.org project.\n'
       'pool 2.almalinux.pool.ntp.org iburst\n'
       'sourcedir /run/chrony-dhcp\n'
       'driftfile /var/lib/chrony/drift\n'
       'makestep 1.0 3\n'
       'rtcsync\n'
       '#allow 192.168.0.0/16\n'
       'keyfile /etc/chrony.keys\n'
       'logdir /var/log/chrony\n')
CONF.write_text(OWN)
TRACK_OK = ('A29FC87B,time.cloudflare.com,3,1761650000.123456789,-0.000012345,0.000003000,'
            '0.000100000,-12.345,0.001,0.050,0.010500,0.001200,64.5,Normal\n')
TRACK_BAD = ('00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,'
             '1.000000,1.000000,0.0,Not synchronised\n')
(stub / 'tracking').write_text(TRACK_OK)
(stub / 'sources').write_text(
    '^,*,time.cloudflare.com,3,6,377,23,-0.000012000,-0.000013000,0.012345000\n'
    '^,+,tik.cesnet.cz,1,6,17,40,0.000200000,0.000210000,0.002000000\n'
    '^,?,10.9.9.9,0,6,0,-,0.000000000,0.000000000,0.000000000\n'
    'a line that is not one\n')
chronyc = stub / 'chronyc'
chronyc.write_text('#!/bin/sh\necho "chronyc $*" >> %s\n'
                   'case "$*" in\n'
                   '  "-c tracking"|"-n -c tracking") cat %s;;\n'
                   '  "-c sources"|"-n -c sources") cat %s;;\n'
                   '  makestep) echo "200 OK";;\n'
                   '  *) echo "200 OK";;\n'
                   'esac\n' % (CALLS, stub / 'tracking', stub / 'sources'))
timedatectl = stub / 'timedatectl'
timedatectl.write_text('#!/bin/sh\necho "timedatectl $*" >> %s\n'
                       'case "$1" in\n'
                       '  show) if [ "$2" = "-p" ]; then cat %s; else\n'
                       '        echo "Timezone=$(cat %s)"; echo NTP=yes; echo NTPSynchronized=yes;\n'
                       '        echo LocalRTC=no; echo CanNTP=yes; fi;;\n'
                       '  list-timezones) printf "Africa/Abidjan\\nEurope/Prague\\nUTC\\n'
                       'bad;zone\\n";;\n'
                       '  set-timezone) echo "$2" > %s;;\n'
                       'esac\n' % (CALLS, stub / 'tz', stub / 'tz', stub / 'tz'))
(stub / 'tz').write_text('Europe/Prague\n')
for f in (chronyc, timedatectl):
    f.chmod(0o755)
ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
           ISEMON_NTP_NO_SERVICE='1', ISEMON_CHRONYC=str(chronyc),
           ISEMON_TIMEDATECTL=str(timedatectl), ISEMON_CHRONY_CONF=str(CONF),
           ISEMON_NGINX_CONF=str(work / 'none.conf'))
HELPER = ROOT / 'deploy' / 'isemon_web.py'


def calls():
    try:
        return CALLS.read_text()
    except OSError:
        return ''


def root_runs():
    """isemon-web.service, as isemon-web.path starts it."""
    return subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True,
                          text=True)


def ask(req):
    (state / 'web' / 'ntp.ask').write_text(json.dumps(req))
    got = root_runs()
    if got.returncode:
        print(got.stderr)
    return json.loads((state / 'web' / 'ntp.json').read_text())


# The helper's own functions, loaded with the stubs in its environment.
for k, v in ENV.items():
    if k.startswith('ISEMON_'):
        os.environ[k] = v
spec = importlib.util.spec_from_file_location('isemon_web', str(HELPER))
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
os.environ.pop('ISEMON_STATE', None)

try:
    print('\nRoot: what chrony says, read')
    r = web.ntp_read()
    t = r['tracking']
    ok('chrony is there (the stub)', r['chrony'])
    ok('tracking: the source it follows, stratum, offset, leap',
       (t['ref'], t['stratum'], t['offset'], t['leap']),
       ('time.cloudflare.com', 3, -0.000012345, 'Normal'))
    ok('...frequency, root delay and dispersion, last correction',
       (t['freq'], t['root_delay'], t['root_disp'], t['last_offset']),
       (-12.345, 0.0105, 0.0012, 0.000003))
    ok('sources: three read, the line that is not one left out', len(r['sources']), 3)
    s0, s2 = r['sources'][0], r['sources'][2]
    ok('...state, name, stratum, poll, reach (octal 377 = 255), last heard',
       (s0['state'], s0['name'], s0['stratum'], s0['poll'], s0['reach'], s0['last_rx']),
       ('*', 'time.cloudflare.com', 3, 6, 255, 23))
    ok('...one never heard is None, not a number', (s2['state'], s2['last_rx'], s2['reach']),
       ('?', None, 0))
    ok('timedatectl: the zone and whether it is synchronised',
       (r['timezone'], r['ntpsynchronized']), ('Europe/Prague', 'yes'))
    ok('the file\'s own servers shown, not marked as isemon\'s',
       (r['managed'], r['own']), (False, ['pool 2.almalinux.pool.ntp.org iburst']))
    ok('nothing but reading was run', [l for l in calls().splitlines()
                                       if 'makestep' in l or 'set-' in l], [])

    print('\nRoot: the settings checked again')
    good = {'manage': True, 'servers': [{'host': 'time.cloudflare.com', 'nts': True},
                                        {'host': 'cz.pool.ntp.org', 'pool': True},
                                        {'host': '192.0.2.10', 'iburst': False, 'prefer': True}],
            'allow': ['192.0.2.0/24', '2001:db8::/32'], 'makestep': [1.0, 3], 'minsources': 2,
            'timezone': 'Europe/Prague'}
    n = web.ntp_checked(good)
    ok('a good request taken as it is', ([x['host'] for x in n['servers']], n['allow'],
                                         n['minsources']),
       (['time.cloudflare.com', 'cz.pool.ntp.org', '192.0.2.10'],
        ['192.0.2.0/24', '2001:db8::/32'], 2))
    for what, bad in (('a host with a newline', {'servers': [{'host': 'a.cz\nallow all'}]}),
                      ('a host with a space', {'servers': [{'host': 'a.cz allow'}]}),
                      ('a server that is not an object', {'servers': ['a.cz']}),
                      ('a network that is not one', {'allow': ['all']}),
                      ('a network with a scope id', {'allow': ['fe80::1%eth0']}),
                      ('a network with a newline', {'allow': ['10.0.0.0/8\nallow all']}),
                      ('makestep out of range', {'makestep': [0, 3]}),
                      ('makestep not numbers', {'makestep': ['x', 3]}),
                      ('a time zone with a ;', {'timezone': 'Europe/Prague;reboot'}),
                      ('a time zone with ..', {'timezone': '../../etc/passwd'}),
                      ('on, and no server at all', {'manage': True, 'servers': []})):
        try:
            web.ntp_checked(bad)
            ok('refused: %s' % what, 'taken', 'refused')
        except web.Refused:
            ok('refused: %s' % what, True)

    print('\nRoot: chrony.conf in and out')
    new = web.ntp_conf_text(OWN, n)
    lines = new.splitlines()
    ok('the file\'s own pool, sourcedir and makestep commented out with #isemon#',
       ('#isemon# pool 2.almalinux.pool.ntp.org iburst' in lines,
        '#isemon# sourcedir /run/chrony-dhcp' in lines, '#isemon# makestep 1.0 3' in lines),
       (True, True, True))
    ok('...and what is not about the servers kept as it was',
       ('driftfile /var/lib/chrony/drift' in lines, 'rtcsync' in lines,
        '#allow 192.168.0.0/16' in lines), (True, True, True))
    block = lines[lines.index(web.NTP_BEGIN):lines.index(web.NTP_END) + 1]
    ok('isemon\'s block between the marks, at the end', block, [
        '# ---- isemon: the time servers, set on its pages (Settings - Time) ----',
        'server time.cloudflare.com iburst nts',
        'pool cz.pool.ntp.org iburst',
        'server 192.0.2.10 prefer',
        'allow 192.0.2.0/24', 'allow 2001:db8::/32',
        'makestep 1 3', 'minsources 2',
        '# ---- isemon: end ----'])
    ok('...and the end mark is the last line', lines[-1], web.NTP_END)
    ok('the same again is the same file (idempotent)', web.ntp_conf_text(new, n), new)
    n2 = dict(n, servers=[{'host': 'tik.cesnet.cz', 'pool': False, 'iburst': True,
                           'prefer': False, 'nts': False}], allow=[], minsources=1)
    other = web.ntp_conf_text(new, n2)
    ok('other servers: one block, never two, and nothing commented twice',
       (other.count(web.NTP_BEGIN), '#isemon# #isemon#' in other,
        'server tik.cesnet.cz iburst' in other, 'time.cloudflare.com' in other),
       (1, False, True, False))
    off = web.ntp_conf_text(new, dict(n, manage=False))
    ok('switched off: the file exactly as it was before', off, OWN)
    ok('...and off again is the same (idempotent)', web.ntp_conf_text(off, dict(n, manage=False)),
       OWN)

    print('\nRoot: through ntp.ask, as the path unit starts it')
    got = ask({'id': 'r1', 'do': 'read', 'zones': True})
    ok('read: answered with the same id, ok', (got['id'], got['ok']), ('r1', True))
    ok('...the zones with it, a bad one left out', got['data'].get('zones'),
       ['Africa/Abidjan', 'Europe/Prague', 'UTC'])
    ok('the asking file is gone', (state / 'web' / 'ntp.ask').exists(), False)
    ok('nothing else was asked of root by it', (state / 'web' / 'status.json').exists(), False)
    got = ask({'id': 'b1', 'do': 'apply', 'manage': True, 'servers': [{'host': 'x y'}]})
    ok('a bad apply refused, and said', (got['ok'], 'not a host name' in got.get('said', '')),
       (False, True))
    ok('...the file untouched', CONF.read_text(), OWN)
    got = ask({'id': 'b2', 'do': 'reboot'})
    ok('anything else refused', (got['ok'], got.get('said')), (False, 'read, apply or sync'))
    (state / 'web' / 'ntp.ask').write_text('not json')
    root_runs()
    got = json.loads((state / 'web' / 'ntp.json').read_text())
    ok('a request that does not read is said, not a crash', (got['ok'], bool(got.get('said'))),
       (False, True))
    (state / 'web' / 'ntp.ask').mkdir()
    root_runs()
    ok('a folder in the asking file\'s place is taken away',
       (state / 'web' / 'ntp.ask').exists(), False)
    got = ask(dict(good, id='a1', do='apply', timezone='UTC'))
    ok('apply: done', (got['ok'], bool(got['data']['said'])), (True, True))
    text = CONF.read_text()
    ok('...chrony.conf has the block', (web.NTP_BEGIN in text, 'pool cz.pool.ntp.org iburst' in text),
       (True, True))
    ok('...the file as it was kept beside it', Path(str(CONF) + '.isemon-before').read_text(), OWN)
    ok('...the time zone set', ((stub / 'tz').read_text().strip(),
                                'timedatectl set-timezone UTC' in calls()), ('UTC', True))
    got = ask(dict(good, id='a2', do='apply', timezone='UTC'))
    ok('the same apply again changes nothing', (got['ok'], got['data']['said']), (True, []))
    got = ask({'id': 'r2', 'do': 'read'})
    ok('read: marked as isemon\'s now', got['data']['managed'], True)
    Path(str(CONF) + '.isemon-before').write_text('somebody changed it')
    got = ask(dict(good, id='a3', do='apply', manage=False, servers=[]))
    ok('switched off: the file\'s own lines back', CONF.read_text(), OWN)
    ok('...the copy from before is not written over by a file that had the block',
       Path(str(CONF) + '.isemon-before').read_text(), 'somebody changed it')
    got = ask({'id': 's1', 'do': 'sync'})
    ok('sync: chronyc makestep, and a burst', (got['ok'], got['data']['said'],
                                               'chronyc makestep' in calls(),
                                               'chronyc burst 4/4' in calls()),
       (True, ['200 OK'], True, True))
    ok('nothing asked: the helper does nothing and says nothing',
       (root_runs().returncode, (state / 'web' / 'ntp.ask').exists()), (0, False))

    # ------------------------------------------------------------------------
    print('\nThe daemon')
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'backups'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'api-token'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    wr = daemon.webroot
    CONF.write_text(OWN)
    ok('nothing kept: off, nothing asked to be applied',
       (isemon.ntp_conf(wr)['manage'], isemon.ntp_view(wr)['hash']), (False, ''))
    ok('the firewall has no NTP rule while nothing is served',
       [a['key'] for a in wr.auto_rules(look={})], ['ssh', 'icmp', 'dhcpv6', 'web', 'logs'])

    # Root, as isemon-web.path would start it: whenever ntp.ask is there.
    stop = threading.Event()

    def path_unit():
        while not stop.is_set():
            if (state / 'web' / 'ntp.ask').exists():
                root_runs()
            time.sleep(0.1)
    th = threading.Thread(target=path_unit, daemon=True)
    th.start()

    def settle(cond, s=20):
        end = time.time() + s
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    isemon.ntp_tick(wr)
    ok('the minute\'s pass reads the clock behind (and the zones the first time)',
       settle(lambda: (isemon.NTP_WORK['last'].get('data') or {}).get('tracking') and
              not isemon.NTP_WORK['busy'] and isemon.WebRoot._meta(wr, 'ntp_zones', [])))
    v = isemon.ntp_view(wr, True)
    ok('the view: the clock, its sources, the zones',
       (v['now']['data']['tracking']['ref'], len(v['now']['data']['sources']), 'UTC' in v['zones']),
       ('time.cloudflare.com', 3, True))
    ok('...nothing wrong with it', (v['problem'], isemon.ntp_problem()), ('', ''))
    ok('...and /etc/chrony.conf untouched while isemon does not set the servers',
       CONF.read_text(), OWN)
    before = isemon.NTP_WORK['read_at']
    isemon.ntp_tick(wr)
    time.sleep(0.5)
    ok('read again only after a minute', isemon.NTP_WORK['read_at'], before)

    print('\nA clock that is not to be trusted')
    (stub / 'tracking').write_text(TRACK_BAD)
    isemon.ntp_ask(wr, 'read')
    ok('read again at once when asked', settle(lambda: isemon.NTP_WORK['read_at'] > before and
                                               not isemon.NTP_WORK['busy']))
    ok('not synchronised is a problem', isemon.ntp_problem(),
       'the clock is not synchronised to a time server (chrony) - every record is filed by it: '
       'Settings → Time')
    ok('...said in the status, for the page and isemon --status',
       daemon.status()['clock_trouble'], isemon.ntp_problem())
    tails = [{'kind': 'failed', 'there': True, 'error': '', 'looked': time.time(),
              'records': 5, 'source': 'ise'}]
    daemon.started = time.time()
    isemon.CONFIG['watch_devices'] = ''
    h = daemon.health(tails)
    ok('...and as the header\'s verdict, when nothing worse is wrong',
       h, {'level': 'warn', 'says': 'the clock is not synchronised'})
    off_track = TRACK_OK.replace('-0.000012345', '2.5')
    (stub / 'tracking').write_text(off_track)
    before = isemon.NTP_WORK['read_at']
    isemon.ntp_ask(wr, 'read')
    settle(lambda: isemon.NTP_WORK['read_at'] > before and not isemon.NTP_WORK['busy'])
    ok('more than a second off is a problem', isemon.ntp_problem(short=True),
       'the clock is 2.5 s off')
    old = dict(isemon.NTP_WORK['last'])
    isemon.NTP_WORK['last'] = dict(old, at=time.time() - 3600)
    ok('a reading an hour old says nothing either way', isemon.ntp_problem(), '')
    isemon.NTP_WORK['last'] = old
    (stub / 'tracking').write_text(TRACK_OK)

    print('\nThe time servers, saved and put in')
    for bad in ({'manage': True, 'servers': []}, {'manage': True, 'servers': [{'host': 'a b'}]},
                {'allow': 'not-a-net'}, {'step_s': 0}, {'timezone': 'x;y'},
                {'allow': 'fe80::1%eth0'}):
        try:
            isemon.ntp_checked(bad)
            ok('the daemon refuses %r' % bad, 'taken', 'refused')
        except isemon.WebRootError:
            ok('the daemon refuses %r' % bad, True)
    page = {'manage': True, 'servers': [{'host': 'Time.Cloudflare.com.', 'nts': True},
                                        {'host': 'cz.pool.ntp.org', 'pool': True},
                                        {'host': ''}],
            'allow': '192.0.2.0/24, 2001:db8::/32', 'step_s': '1', 'step_n': '3',
            'minsources': '1', 'timezone': ''}
    c = isemon.ntp_checked(page)
    ok('the page\'s settings made whole: lower case, the empty row left out, the networks a list',
       ([x['host'] for x in c['servers']], c['allow'], c['makestep']),
       (['time.cloudflare.com', 'cz.pool.ntp.org'], ['192.0.2.0/24', '2001:db8::/32'], [1.0, 3]))
    isemon.ntp_save(wr, page, 'boss')
    ok('kept in the database the way the firewall is (meta ntp_conf)',
       json.loads(store.get_meta('ntp_conf'))['manage'], True)
    ok('put in by root within seconds', settle(lambda: isemon.WebRoot._meta(
        wr, 'ntp_applied', {}).get('hash') == isemon.ntp_hash(isemon.ntp_desired(wr))
        and not isemon.NTP_WORK['busy']))
    v = isemon.ntp_view(wr, True)
    ok('...and the result shown', (v['applied']['ok'], 'time.cloudflare.com' in v['applied']['said'],
                                   v['hash'] == v['applied']['hash']), (True, True, True))
    ok('chrony.conf has isemon\'s block',
       'server time.cloudflare.com iburst nts' in CONF.read_text())
    ok('an event says who set it', 'the time was set' in json.dumps(
        [dict(r) for r in store.db.execute('SELECT detail, who FROM events').fetchall()]))
    auto = {a['key']: a for a in wr.auto_rules(look={})}
    ok('the firewall: NTP (time served), udp 123 from each network',
       ('ntp' in auto, auto['ntp']['title'],
        [(r['family'], r['proto'], r['port'], r['source']) for r in auto['ntp']['rules']]),
       (True, 'NTP (time served)', [(4, 'udp', '123', '192.0.2.0/24'),
                                    (6, 'udp', '123', '2001:db8::/32')]))
    ok('...the existing automatic rules as they were',
       [a['key'] for a in wr.auto_rules(look={})][:5], ['ssh', 'icmp', 'dhcpv6', 'web', 'logs'])
    ok('...and it can be turned off on the firewall pane like the others', 'ntp' in wr.AUTO)
    ok('...in the chain when isemon looks after the firewall',
       any(r['port'] == '123' for r in wr.fw_lines(dict(wr.fw_conf(), on=True), {})))
    wr.firewall_save({'off': ['ntp']}, 'boss')
    ok('...and not when turned off there',
       any(r['port'] == '123' for r in wr.fw_lines(None, {})), False)
    applied_at = isemon.WebRoot._meta(wr, 'ntp_applied', {}).get('at')
    isemon.ntp_tick(wr)
    time.sleep(0.5)
    ok('not put in again while nothing changed',
       isemon.WebRoot._meta(wr, 'ntp_applied', {}).get('at'), applied_at)
    isemon.ntp_save(wr, dict(page, manage=False, servers=[]), 'boss')
    ok('switched off: the file\'s own lines back', settle(lambda: CONF.read_text() == OWN))
    settle(lambda: not isemon.NTP_WORK['busy'])
    ok('...and the NTP rule gone with it', 'ntp' in [a['key'] for a in wr.auto_rules(look={})],
       False)

    # ------------------------------------------------------------------------
    print('\nThrough the API')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(payload).encode() if payload is not None
                                     else None, method='POST' if payload is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    st, v = call('/api/ntp', session=tok['watcher'])
    ok('read only may look', (st, v['may'], bool(v['now'].get('data'))), (200, False, True))
    st, v = call('/api/ntp', session=tok['boss'])
    ok('a full admin may change', (st, v['may']), (200, True))
    ok('nobody signed in may not look', call('/api/ntp')[0], 401)
    for act in ('read', 'sync', 'save'):
        ok('read only may not %s' % act, call('/api/ntp', {'action': act, 'conf': {}},
                                              tok['watcher'])[0], 403)
    st, said = call('/api/ntp', {'action': 'save', 'conf': {'manage': True, 'servers': []}},
                    tok['boss'])
    ok('a bad save: 400 and why', (st, 'at least one' in said.get('error', '')), (400, True))
    ok('anything else: 400', call('/api/ntp', {'action': 'reboot'}, tok['boss'])[0], 400)
    st, said = call('/api/ntp', {'action': 'save', 'conf': dict(page, allow='')}, tok['boss'])
    ok('a save', (st, said.get('ok')), (200, True))
    ok('...put in by root', settle(lambda: 'server time.cloudflare.com' in CONF.read_text()))
    settle(lambda: not isemon.NTP_WORK['busy'])
    n_before = calls().count('makestep')
    st, said = call('/api/ntp', {'action': 'sync'}, tok['boss'])
    ok('step it now: asked', (st, said.get('ok')), (200, True))
    ok('...chronyc makestep run by root', settle(lambda: calls().count('makestep') > n_before))
    st, said = call('/api/ntp', {'action': 'read'}, tok['boss'])
    ok('read it again: asked', (st, said.get('ok')), (200, True))
    ok('the status carries the clock\'s trouble (none now)',
       call('/api/status', session=tok['boss'])[1].get('clock_trouble'), '')
    settle(lambda: not isemon.NTP_WORK['busy'])
    stop.set()

    print('\nThe page, the command line, install.sh, the docs')
    src = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('loadNtp fills #ntp-body', ('function loadNtp()' in src, "$('ntp-body')" in src),
       (True, True))
    ok('the servers wait for the save bar', ("extraPending('ntp'" in src, "extraDone('ntp')" in src),
       (True, True))
    ok('the ready-made servers', all(x in src for x in ("'cz.pool.ntp.org'", "'pool.ntp.org'",
                                                        "'time.cloudflare.com'", "'tik.cesnet.cz'",
                                                        "'tak.cesnet.cz'")))
    ok('nothing of a cluster on it', ('The nodes take each other too' in src,
                                      'Between the two nodes' in src), (False, False))
    out = subprocess.run(['python3', str(ROOT / 'isemon.py'), '--help'], capture_output=True,
                         text=True).stdout
    ok('isemon --time and --time-step', ('--time ' in out, '--time-step' in out), (True, True))
    ok('the offset as the page says it', (isemon.ntp_ms(-0.000012345), isemon.ntp_ms(2.5),
                                         isemon.ntp_ms(0.0123)), ('-0.012 ms', '+2.50 s', '+12.3 ms'))
    inst = (ROOT / 'install.sh').read_text()
    fn = inst[inst.index('chrony_check() {'):inst.index('not_a_link() {')]
    # 1.10.236: chrony put in whenever it is missing (ensure_packages, on an
    # install and on an upgrade); chronyd started only where nothing else
    # keeps the time and it was never set up.
    ok('install.sh: chrony put in when missing, on an install and an upgrade',
       ('tool_add chronyc    chrony chrony' in inst, 'ensure_packages upgrade' in inst,
        'ensure_packages fresh' in inst, 'chrony_check upgrade' in inst,
        'chrony_check fresh' in inst), (True, True, True, True, True))
    ok('...chronyd started only where nothing else keeps the time',
       'systemd-timesyncd ntpd ntp ntpsec openntpd' in inst and 'enable --now chronyd' in fn
       and 'set-ntp' not in fn and '/etc/chrony.conf' not in fn)
    doc = (ROOT / 'docs' / 'time.md').read_text()
    ok('docs/time.md', all(x in doc for x in ('#isemon#', '/etc/chrony.conf.isemon-before',
                                              'isemon --time', 'NTP (time served)')))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
