#!/usr/bin/env python3
"""1.10.228: Settings - Network, Settings - Restart and power off, and the
changes on trial, as otp 1.0.119 and 1.0.137 have them, for one server.

Root's half (isemon_web.py) is run here for real, with nmcli, hostnamectl,
ip and the power command played by small scripts in a folder of the test's
own (ISEMON_NMCLI, ISEMON_HOSTNAMECTL, ISEMON_IP, ISEMON_POWER_CMD, ...).
A thread plays the path unit: whatever the daemon lays down in the web
folder is handed to the helper at once. A reboot is a new boot time
(ISEMON_BTIME_FILE) and the addresses the fake `ip` says the machine has.

    ./test/fixes228_net.py
"""
import argparse
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

work = Path(tempfile.mkdtemp(prefix='isemon-228net-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
fake = work / 'bin'
fake.mkdir()
NM_STATE = work / 'nm.json'
POWER = work / 'power.log'
BTIME = work / 'btime'
HOSTS = work / 'hosts'
RESOLV = work / 'resolv.conf'
NGINX = work / 'nginx' / 'isemon.conf'
CERTS = work / 'certs'
NGINX.parent.mkdir()
CERTS.mkdir()
shutil.copy(str(ROOT / 'deploy' / 'nginx-isemon.conf'), str(NGINX))
NGINX.write_text(NGINX.read_text().replace('/etc/nginx/certs', str(CERTS)))
BTIME.write_text('1000\n')
RESOLV.write_text('nameserver 192.0.2.53\n')
HOSTS.write_text('127.0.0.1 localhost localhost.localdomain\n::1 localhost\n'
                 '192.0.2.10 old.example.cz old\n198.51.100.9 other.example.cz other\n')

os.environ.update(ISEMON_WEB_HELPER='1', ISEMON_BTIME_FILE=str(BTIME))
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_NGINX_CONF=str(NGINX), ISEMON_CERT_DIR=str(CERTS),
                  ISEMON_FW_FILE4=str(work / 'fw4'), ISEMON_FW_FILE6=str(work / 'fw6'),
                  ISEMON_RSYSLOG=str(work / 'none'),
                  ISEMON_NMCLI=str(fake / 'nmcli'), ISEMON_HOSTNAMECTL=str(fake / 'hostnamectl'),
                  ISEMON_IP=str(fake / 'ip'), ISEMON_HOSTS_FILE=str(HOSTS),
                  ISEMON_POWER_CMD=str(POWER), ISEMON_RESOLV=str(RESOLV),
                  ISEMON_SYSCTL_IPV6=str(work / 'sysctl-ipv6.conf'))

# ---- the fakes ---------------------------------------------------------------
NM = {'con': 'System eth0', 'dev': 'eth0', 'hostname': 'old.example.cz',
      'live4': ['192.0.2.10/24'], 'gw_live': '192.0.2.1',
      'f': {'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.10/24',
            'ipv4.gateway': '192.0.2.1', 'ipv4.dns': '192.0.2.53',
            'ipv4.dns-search': 'example.cz', 'ipv6.method': 'disabled', 'ipv6.addresses': '',
            'ipv6.gateway': '', 'ipv6.dns': ''},
      'modify': []}
NM_STATE.write_text(json.dumps(NM))
PY = sys.executable
(fake / 'nmcli').write_text('''#!%s
import json, sys
p = %r
s = json.load(open(p))
a = sys.argv[1:]
if a[:4] == ['-t', '-f', 'DEVICE,TYPE,STATE,CONNECTION', 'device']:
    print('%%s:ethernet:connected:%%s' %% (s['dev'], s['con']))
    print('lo:loopback:connected (externally):lo')
elif a[:3] == ['-t', '-g', 'NAME'] and a[3:] == ['connection', 'show']:
    print(s['con'])
elif a[:2] == ['-t', '-g'] and a[3:5] == ['connection', 'show']:
    if a[5] != s['con']:
        sys.stderr.write('Error: no such connection profile.\\n'); sys.exit(10)
    for k in a[2].split(','):
        print(s['f'].get(k, '').replace(':', '\\\\:'))
elif a[:2] == ['connection', 'modify']:
    if s.get('refuse'):
        sys.stderr.write('Error: failed to modify connection: invalid gateway.\\n'); sys.exit(1)
    s['modify'].append(a[2:])
    rest = a[3:]
    for k, v in zip(rest[::2], rest[1::2]):
        if k in s['f']:
            s['f'][k] = v
    json.dump(s, open(p, 'w'))
else:
    sys.stderr.write('fake nmcli: %%r\\n' %% a); sys.exit(2)
''' % (PY, str(NM_STATE)))
(fake / 'hostnamectl').write_text('''#!%s
import json, sys
p = %r
s = json.load(open(p))
a = sys.argv[1:]
if a == ['--static']:
    print(s['hostname'])
elif a[:1] == ['set-hostname']:
    s['hostname'] = a[1]
    json.dump(s, open(p, 'w'))
else:
    sys.exit(2)
''' % (PY, str(NM_STATE)))
(fake / 'ip').write_text('''#!%s
import json, sys
s = json.load(open(%r))
a = sys.argv[1:]
if a == ['-o', 'addr', 'show']:
    print('1: lo    inet 127.0.0.1/8 scope host lo')
    for x in s['live4']:
        print('2: %%s    inet %%s brd + scope global %%s' %% (s['dev'], x, s['dev']))
elif a == ['-4', 'route', 'show', 'default']:
    print('default via %%s dev %%s proto static' %% (s['gw_live'], s['dev']))
elif a == ['-6', 'route', 'show', 'default']:
    pass
else:
    sys.exit(2)
''' % (PY, str(NM_STATE)))
for f in fake.iterdir():
    f.chmod(0o755)


def nm():
    return json.loads(NM_STATE.read_text())


def nm_set(**kw):
    s = nm()
    s.update(kw)
    NM_STATE.write_text(json.dumps(s))


def reboot(up_with=None):
    """The machine restarted: a new boot time, and the addresses NetworkManager
    was told (or the ones given) on the interface."""
    BTIME.write_text(str(float(BTIME.read_text()) + 100) + '\n')
    s = nm()
    s['live4'] = up_with if up_with is not None else [s['f']['ipv4.addresses']]
    s['gw_live'] = s['f']['ipv4.gateway']
    NM_STATE.write_text(json.dumps(s))


def run_helper():
    return subprocess.run(['python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py')],
                          capture_output=True, text=True, env=HELPER_ENV)


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


def wait_for(fn, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.1)
    return False


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
np = daemon.netpower

# The path unit, played by a thread: net.ask and request.json handed to root.
STOP = threading.Event()


def path_unit():
    while not STOP.is_set():
        if (state / 'web' / 'net.ask').exists() or (state / 'web' / 'request.json').exists():
            run_helper()
        time.sleep(0.05)


try:
    # ------------------------------------------------------------------------
    print('\nThe defaults: nothing changes until somebody asks')
    ok('net_confirm_min is 10, fw_confirm_min 5', (isemon.DEFAULTS['net_confirm_min'],
                                                   isemon.DEFAULTS['fw_confirm_min']), (10, 5))
    ok('...both with limits, a name and words', all(
        k in isemon.Daemon.TUNABLE and k in isemon.Daemon.NAMES and k in isemon.Daemon.SAYS
        for k in ('net_confirm_min', 'fw_confirm_min')))
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('...and shown on the page: the network\u2019s on Network, the firewall\u2019s on '
       'Firewall and access', ("nettrial: ['net_confirm_min']" in page,
                               "fwtrial: ['fw_confirm_min']" in page,
                               'id="sect-nettrial"' in page, 'id="sect-fwtrial"' in page),
       (True, True, True, True))
    ok('nothing waits to be kept', np.trials(), [])
    ok('the daemon\'s pass asks root nothing while nobody has looked', (np.tick(), (
        state / 'web' / 'net.ask').exists()), (None, False))

    # ------------------------------------------------------------------------
    print('\nRoot reads the network')
    (state / 'web' / 'net.ask').write_text(json.dumps({'do': 'read', 'id': 'r1'}))
    got = run_helper()
    ans = json.loads((state / 'web' / 'net.json').read_text())
    d = ans.get('data') or {}
    ok('answered, under the id asked', (ans.get('ok'), ans.get('id')), (True, 'r1'))
    ok('...the asking file taken away', (state / 'web' / 'net.ask').exists(), False)
    ok('NetworkManager, its connection and device', (d.get('nm'), d.get('con'), d.get('dev')),
       (True, 'System eth0', 'eth0'))
    ok('...what it is told', (d['conf']['ipv4_method'], d['conf']['ipv4_addresses'],
                              d['conf']['ipv4_gateway'], d['conf']['ipv4_dns'],
                              d['conf']['ipv4_search']),
       ('manual', ['192.0.2.10/24'], '192.0.2.1', ['192.0.2.53'], ['example.cz']))
    ok('...what the kernel has, loopback left out', d['live']['addrs4'],
       [{'addr': '192.0.2.10/24', 'dev': 'eth0'}])
    ok('...the host name and the DNS of resolv.conf', (d.get('hostname'), d['live']['dns']),
       ('old.example.cz', ['192.0.2.53']))
    (state / 'web' / 'net.ask').write_text(json.dumps({'do': 'format the disk', 'id': 'r2'}))
    run_helper()
    ans = json.loads((state / 'web' / 'net.json').read_text())
    ok('anything else asked is refused', (ans.get('ok'), ans.get('said')),
       (False, 'read, apply, power or console'))
    os.symlink('/etc/passwd', str(state / 'web' / 'net.ask'))
    run_helper()
    ok('a link in its place is taken away, never followed',
       (os.path.lexists(str(state / 'web' / 'net.ask')),
        json.loads((state / 'web' / 'net.json').read_text()).get('id')), (False, 'r2'))

    # ------------------------------------------------------------------------
    print('\nWhat root is asked to put in is checked again as root')
    spec = importlib.util.spec_from_file_location('isemon_web_t', str(ROOT / 'deploy' /
                                                                      'isemon_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    good = {'con': 'System eth0', 'ipv4': {'addr': '192.0.2.20/24', 'gw': '192.0.2.1',
                                           'dns': ['192.0.2.53'], 'search': ['example.cz']},
            'ipv6': {'mode': 'off'}, 'hostname': 'new.example.cz', 'old': ['192.0.2.10'],
            'old_hostname': 'old.example.cz', 'reboot_in': 8}
    n = W.net_checked(good)
    ok('a good one in its one shape', (n['addr4'], n['gw4'], n['dns4'], n['hostname'],
                                       n['reboot_in']),
       ('192.0.2.20/24', '192.0.2.1', ['192.0.2.53'], 'new.example.cz', 8))
    for change, why in ((('ipv4', {'addr': '192.0.2.20'}), 'an address without its prefix'),
                        (('ipv4', {'addr': '192.0.2.20/24\nX'}), 'a newline in the address'),
                        (('ipv4', {'addr': '192.0.2.20/24', 'gw': '10.0.0.1'}),
                         'a gateway outside the network'),
                        (('ipv4', {'addr': '192.0.2.20/24', 'dns': ['1.1.1.1;reboot']}),
                         'a DNS server that is not an address'),
                        (('ipv4', {'addr': '192.0.2.20/24', 'search': ['ex ample']}),
                         'a search domain that is not one'),
                        (('ipv6', {'mode': 'manual', 'addr': 'fe80::1/64'}),
                         'a link-local IPv6 address'),
                        (('ipv6', {'mode': 'sometimes'}), 'an IPv6 mode there is not'),
                        (('hostname', 'evil;name.cz'), 'a host name with a semicolon'),
                        (('hostname', 'single'), 'a host name that is not the whole name'),
                        (('con', 'eth0\nipv4.method'), 'a newline in the connection')):
        bad = json.loads(json.dumps(good))
        bad[change[0]] = change[1]
        try:
            W.net_checked(bad)
            ok('refused: ' + why, False)
        except W.Refused:
            ok('refused: ' + why, True)
    hl = W.hosts_lines(HOSTS.read_text(), n)
    ok('/etc/hosts: the old lines of this machine out, the new one in, the others kept',
       hl, '127.0.0.1 localhost localhost.localdomain\n::1 localhost\n'
           '198.51.100.9 other.example.cz other\n'
           '192.0.2.20 new.example.cz new    # this machine - written by isemon\n')
    ok('...and the same file again is the same file', W.hosts_lines(hl, n), hl)

    # ------------------------------------------------------------------------
    print('\nRoot puts a network in')
    (state / 'web' / 'net.ask').write_text(json.dumps(dict(good, do='apply', id='a1')))
    run_helper()
    ans = json.loads((state / 'web' / 'net.json').read_text())
    ok('put in', (ans.get('ok'), ans.get('id')), (True, 'a1'))
    s = nm()
    ok('NetworkManager told the new address, by hand, with its gateway and DNS',
       (s['f']['ipv4.method'], s['f']['ipv4.addresses'], s['f']['ipv4.gateway'],
        s['f']['ipv6.method']), ('manual', '192.0.2.20/24', '192.0.2.1', 'disabled'))
    ok('...and what it had before handed back, for going back',
       ans['data']['before']['ipv4.addresses'], '192.0.2.10/24')
    ok('the host name set', s['hostname'], 'new.example.cz')
    ok('/etc/hosts written, the old one kept beside it',
       ('new.example.cz' in HOSTS.read_text(),
        'old.example.cz' in Path(str(HOSTS) + '.isemon-before').read_text()), (True, True))
    ok('...and the reboot asked for, 8 s later', POWER.read_text().split()[:2], ['reboot', '8'])
    (state / 'web' / 'net.ask').write_text(json.dumps({'do': 'power', 'how': 'poweroff',
                                                       'in': 5, 'id': 'p1'}))
    run_helper()
    ok('a power-off asked of root', POWER.read_text().strip().split('\n')[-1].split()[:2],
       ['poweroff', '5'])
    (state / 'web' / 'net.ask').write_text(json.dumps({'do': 'power', 'how': 'halt; rm',
                                                       'id': 'p2'}))
    run_helper()
    ok('...and nothing but a reboot or a power-off',
       json.loads((state / 'web' / 'net.json').read_text()).get('ok'), False)
    # Back as it was for the daemon's part.
    NM_STATE.write_text(json.dumps(NM))
    HOSTS.write_text('127.0.0.1 localhost\n192.0.2.10 old.example.cz old\n')
    POWER.write_text('')

    # ------------------------------------------------------------------------
    print('\nThe daemon asks root, and checks what the page asks for')
    unit = threading.Thread(target=path_unit, daemon=True)
    unit.start()
    try:
        np.check({'ipv4': {'addr': '192.0.2.20/24'}, 'hostname': 'new.example.cz'})
        ok('nothing can be checked before the network was read', False)
    except isemon.WebRootError as e:
        ok('nothing can be checked before the network was read', 'not been read' in str(e))
    now = np.publish()
    ok('read through root, kept for the page', (np.now()['data']['con'],
                                                 np.view(True)['now']['data']['hostname']),
       ('System eth0', 'old.example.cz'))
    want = {'hostname': 'new.example.cz',
            'ipv4': {'addr': '192.0.2.20/24', 'gw': '192.0.2.1', 'dns': '192.0.2.53, 192.0.2.54',
                     'search': 'example.cz'}, 'ipv6': {'on': False}}
    for bad, why in (({'ipv4': {'addr': '192.0.2.20/24', 'gw': '198.51.100.1'}},
                      'a gateway outside the network'),
                     ({'ipv4': {'addr': '192.0.2.0/24'}}, 'the network\'s own address'),
                     ({'ipv4': {'addr': '192.0.2.20'}}, 'no prefix'),
                     ({'hostname': 'new'}, 'a host name that is not whole'),
                     ({'con': 'Wired 2'}, 'a connection there is not'),
                     ({'ipv6': {'on': True, 'mode': 'manual', 'addr': 'fe80::5/64'}},
                      'a link-local IPv6 address')):
        w2 = json.loads(json.dumps(want))
        w2.update(bad)
        try:
            np.check(w2)
            ok('refused on the page: ' + why, False)
        except isemon.WebRootError:
            ok('refused on the page: ' + why, True)
    isemon.CONFIG['site_name'] = 'old'
    isemon.CONFIG['directory_host'] = '192.0.2.10'      # somebody else's? never touched
    wr.tls_do({'action': 'selfsigned', 'cn': 'old.example.cz', 'san': 'old 192.0.2.10'}, 'boss')
    w = np.check(want)
    ok('the plan says what happens, in order', [p.split(' ')[0] for p in w['plan']],
       ['this', 'its', 'the', 'NetworkManager', 'a'])
    ok('...this server\'s own settings that named its old name', w['plan'][0],
       'this server\'s settings that name the old address or name: site_name = new')
    ok('...its certificate made again', 'is made again for 192.0.2.20, new.example.cz, new'
       in w['plan'][1])
    ok('...and on trial for net_confirm_min', 'within 10 min' in w['plan'][-1])

    # ------------------------------------------------------------------------
    print('\nThe change: a job with its steps, through the reboot')
    job = np.ask(want, 'boss')
    ok('a job, asked', job['state'], 'asked')
    ok('...run behind until the restart', wait_for(
        lambda: np._get('net:job').get('state') in ('rebooting', 'failed') and not np.busy))
    job = np._get('net:job')
    steps = [x['what'] for x in job['steps']]
    ok('rebooting, every step good', (job['state'], all(x['ok'] for x in job['steps'])),
       ('rebooting', True))
    ok('...on trial for 10 min', any('on trial: unless it is kept within 10 min' in x
                                     for x in steps))
    ok('...the old network kept to go back to', (job['back']['ipv4']['addr'],
                                                 job['back']['hostname']),
       ('192.0.2.10/24', 'old.example.cz'))
    ok('...what NetworkManager had, from root', job['before']['ipv4.addresses'], '192.0.2.10/24')
    ok('...the name of the installation followed the host name', isemon.CONFIG['site_name'],
       'new')
    ok('...an address of another machine left as it was', isemon.CONFIG['directory_host'],
       '192.0.2.10')
    names = isemon.cert_facts(wr.tls_conf()['cert'])['names']
    ok('...the certificate that signs itself made again with the new name and address',
       sorted(names), sorted(['new.example.cz', 'new', '192.0.2.20']))
    ok('...NetworkManager told, and a reboot asked for',
       (nm()['f']['ipv4.addresses'], POWER.read_text().split()[:2]),
       ('192.0.2.20/24', ['reboot', '8']))
    try:
        np.ask(want, 'boss')
        ok('another change meanwhile is refused', False)
    except isemon.WebRootError:
        ok('another change meanwhile is refused', True)
    try:
        np.power_ask('reboot', 'boss')
        ok('...and so is a restart', False)
    except isemon.WebRootError:
        ok('...and so is a restart', True)
    np.tick()
    ok('no reboot yet: the job waits', np._get('net:job')['state'], 'rebooting')
    reboot()
    np.tick()
    ok('back up at its new address: it waits to be kept', wait_for(
        lambda: np._get('net:job').get('state') == 'trial' and not np.busy))
    job = np._get('net:job')
    ok('...for 10 min', 590 < job['trial_until'] - time.time() <= 600)
    tr = np.trials()
    ok('the banner has it', [(t['kind'], t['new'], t['back']) for t in tr],
       [('net', '192.0.2.20', '192.0.2.10')])
    ok('...and so has the status the page polls', daemon.status()['trials'][0]['kind'], 'net')
    ok('...and isemon --status says it', 'isemon --change-keep net' in
       isemon.NetPower.trial_words(tr)[0])
    try:
        np.answer('net', 'perhaps', 'boss')
        ok('an answer that is neither keep nor back is refused', False)
    except isemon.WebRootError:
        ok('an answer that is neither keep nor back is refused', True)
    np.answer('net', 'keep', 'boss')
    ok('kept', wait_for(lambda: np._get('net:job').get('state') == 'done' and not np.busy))
    ok('...nothing waits any more', np.trials(), [])
    ok('...and it is in the events', wait_for(lambda: any(
        'kept the new network' in (r.get('detail') or '') for r in store.events(limit=50)[0])))
    np.hide()
    ok('Hide this: the finished change is gone from the page', np.view(True)['job'], {})

    # ------------------------------------------------------------------------
    print('\nNot kept in time: the old network comes back by itself')
    want2 = json.loads(json.dumps(want))
    want2['ipv4']['addr'] = '192.0.2.30/24'
    np.publish()
    np.ask(want2, 'boss')
    wait_for(lambda: np._get('net:job').get('state') == 'rebooting' and not np.busy)
    reboot()
    np.tick()
    wait_for(lambda: np._get('net:job').get('state') == 'trial' and not np.busy)
    job = np._get('net:job')
    ok('on trial at the second address', (job['state'], job['want']['new_ip'], job['back']
                                          ['ipv4']['addr']), ('trial', '192.0.2.30', '192.0.2.20/24'))
    job['trial_until'] = time.time() - 1
    np._put('net:job', job)
    POWER.write_text('')
    np.tick()
    ok('out of time: the old network asked for, and a reboot', wait_for(
        lambda: np._get('net:job').get('state') == 'rebooting' and not np.busy))
    job = np._get('net:job')
    ok('...as a job going back, not on trial again', (job['rollback'], job.get('trial_min'),
                                                      job['want']['new_ip']),
       (True, None, '192.0.2.20'))
    ok('...NetworkManager told the old address again', nm()['f']['ipv4.addresses'],
       '192.0.2.20/24')
    ok('...and the reboot asked for', POWER.read_text().split()[:1], ['reboot'])
    reboot()
    np.tick()
    ok('back up at the old address: done, nothing waits', wait_for(
        lambda: np._get('net:job').get('state') == 'done' and not np.busy) and np.trials() == [])
    ok('...all of it in the events', all(any(w in (r.get('detail') or '')
                                              for r in store.events(limit=200)[0])
                                          for w in ('asked for a new network', 'is on trial',
                                                    'was not kept', 'went back to what it was')))

    # ------------------------------------------------------------------------
    print('\nPut the old back now')
    np.publish()
    np.ask(want2, 'boss')
    wait_for(lambda: np._get('net:job').get('state') == 'rebooting' and not np.busy)
    reboot()
    np.tick()
    wait_for(lambda: np._get('net:job').get('state') == 'trial' and not np.busy)
    np.answer('net', 'back', 'boss')
    ok('asked back: the old network is put in', wait_for(
        lambda: np._get('net:job').get('rollback') and
        np._get('net:job').get('state') == 'rebooting' and not np.busy))
    ok('...the old address', nm()['f']['ipv4.addresses'], '192.0.2.20/24')
    reboot()
    np.tick()
    wait_for(lambda: np._get('net:job').get('state') == 'done' and not np.busy)

    # ------------------------------------------------------------------------
    print('\nCome up without the new address: back at once')
    np.publish()
    np.ask(want2, 'boss')
    wait_for(lambda: np._get('net:job').get('state') == 'rebooting' and not np.busy)
    reboot(up_with=['192.0.2.20/24'])           # NetworkManager did not take it
    np.tick()
    ok('the old network asked for at once, not after the trial', wait_for(
        lambda: np._get('net:job').get('rollback') and
        np._get('net:job').get('state') == 'rebooting' and not np.busy))
    reboot()
    np.tick()
    wait_for(lambda: np._get('net:job').get('state') == 'done' and not np.busy)

    # ------------------------------------------------------------------------
    print('\nA network from DHCP cannot be put back by itself')
    s = nm()
    s['f']['ipv4.method'] = 'auto'
    NM_STATE.write_text(json.dumps(s))
    np.publish()
    w = np.check(want2)
    ok('the plan says so', 'not set by hand' in w['plan'][-1])
    np.ask(want2, 'boss')
    wait_for(lambda: np._get('net:job').get('state') == 'rebooting' and not np.busy)
    job = np._get('net:job')
    ok('...the job says so, and is not on trial', (any(
        'not set by hand' in x['what'] for x in job['steps']), job.get('trial_min')), (True, 0))
    reboot()
    np.tick()
    ok('...and back up it is done at once', wait_for(
        lambda: np._get('net:job').get('state') == 'done' and not np.busy))
    # ------------------------------------------------------------------------
    print('\nRoot says no: nothing of this server is left half changed')
    s = nm()
    s['f']['ipv4.method'] = 'manual'
    s['refuse'] = True
    NM_STATE.write_text(json.dumps(s))
    np.publish()
    site_was, cert_was = isemon.CONFIG['site_name'], wr.tls_conf()['cert']
    want3 = json.loads(json.dumps(want2))
    want3['hostname'] = 'third.example.cz'
    POWER.write_text('')
    np.ask(want3, 'boss')
    ok('the job failed, and says what NetworkManager said', wait_for(
        lambda: np._get('net:job').get('state') == 'failed' and not np.busy) and
        'invalid gateway' in np._get('net:job')['steps'][-1]['what'])
    ok('...the name of the installation and the certificate as they were',
       (isemon.CONFIG['site_name'], wr.tls_conf()['cert'] == cert_was), (site_was, True))
    ok('...and no reboot', POWER.read_text(), '')
    s = nm()
    s['refuse'] = False
    NM_STATE.write_text(json.dumps(s))
    isemon.CONFIG['net_confirm_min'] = 0
    np.publish()
    ok('net_confirm_min 0: kept at once', 'kept at once' in np.check(want)['plan'][-1])
    isemon.CONFIG['net_confirm_min'] = 10

    # ------------------------------------------------------------------------
    print('\nThe firewall on trial')
    isemon.CONFIG['fw_confirm_min'] = 5
    was_fw = wr.fw_conf()
    said = wr.firewall_save({'on': True, 'rules': [{'proto': 'tcp', 'port': '10050',
                                                    'source': '10.9.9.9'}]}, 'boss')
    tr = np._get('fw:trial')
    ok('saved on trial: what was there before kept', (tr['was']['on'], bool(tr.get('done'))),
       (was_fw['on'], False))
    ok('...the page is told', 'unless it is kept within 5 min' in said['message'])
    ok('...the banner has it', [t['kind'] for t in np.trials()], ['fw'])
    first_until, first_id = tr['until'], tr['id']
    time.sleep(0.05)
    wr.firewall_save({'on': True, 'rules': []}, 'boss')
    tr = np._get('fw:trial')
    ok('a second change in the trial moves its deadline on, and keeps what was before',
       (tr['id'] == first_id, tr['until'] > first_until, tr['was']['on']),
       (True, True, was_fw['on']))
    tr['until'] = time.time() - 1
    np._put('fw:trial', tr)
    (state / 'web' / 'status.json').unlink() if (state / 'web' / 'status.json').exists() else None
    np.tick()
    ok('not kept in time: the old state is back', (wr.fw_conf()['on'], np._get('fw:trial')
                                                   ['done']), (False, 'back'))
    ok('...and root put it in', wait_for(lambda: (wr.read('status.json') or {}).get('state')
                                         in ('done', 'failed')))
    req_off = (wr.request() or {}).get('fw') or {}
    ok('...isemon\'s chain asked off', req_off.get('on'), False)
    wr.firewall_save({'on': True}, 'boss')
    np.answer('fw', 'keep', 'boss')
    ok('kept: the change stays, nothing waits', (wr.fw_conf()['on'], np.trials()), (True, []))
    try:
        np.answer('fw', 'keep', 'boss')
        ok('nothing to keep twice', False)
    except isemon.WebRootError:
        ok('nothing to keep twice', True)
    wr.firewall_save({'on': False, 'access': {'dashboard': {'any': False,
                                                             'from': '10.0.0.0/8'}}}, 'boss')
    np.answer('fw', 'back', 'boss')
    ok('put back now: the chain and the lists as they were',
       (wr.fw_conf()['on'], np._get('fw:trial')['done']), (True, 'back'))
    isemon.CONFIG['fw_confirm_min'] = 0
    wr.firewall_save({'on': False}, 'boss')
    ok('fw_confirm_min 0: kept at once, nothing on trial', np.trials(), [])
    isemon.CONFIG['fw_confirm_min'] = 5

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
            with urllib.request.urlopen(req, timeout=120) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    st, v = call('/api/net', session=tok['watcher'])
    ok('read only may look at the network', (st, v['may'], v['now']['data']['con']),
       (200, False, 'System eth0'))
    for path, body in (('/api/net', {'action': 'read'}), ('/api/net', {'action': 'apply',
                                                                        'want': want}),
                       ('/api/power', {'how': 'reboot'}),
                       ('/api/trial', {'kind': 'fw', 'action': 'back'})):
        ok('...and may not %s %s' % (body.get('action') or body.get('how'), path),
           call(path, body, tok['watcher'])[0], 403)
    ok('nobody signed out may look', call('/api/net')[0], 401)
    st, v = call('/api/net', {'action': 'read'}, tok['boss'])
    ok('read again on the page', (st, v['now']['data']['hostname']), (200, 'new.example.cz'))
    st, v = call('/api/net', {'action': 'check', 'want': want2}, tok['boss'])
    ok('Check it', (st, v['plan'][-2].startswith('NetworkManager')), (200, True))
    st, v = call('/api/net', {'action': 'check', 'want': {'ipv4': {'addr': 'x'}}}, tok['boss'])
    ok('...a wrong one said', (st, 'prefix' in v.get('error', '')), (400, True))
    st, v = call('/api/trial', {'kind': 'net', 'action': 'keep'}, tok['boss'])
    ok('nothing to keep: said so', (st, 'not waiting' in v.get('error', '')), (400, True))
    wr.firewall_save({'on': True}, 'boss')
    st, v = call('/api/trial', session=tok['watcher'])
    ok('the trials listed', (st, [t['kind'] for t in v['trials']]), (200, ['fw']))
    st, v = call('/api/status', session=tok['watcher'])
    ok('...and on the status every page polls', [t['kind'] for t in v.get('trials') or []],
       ['fw'])
    st, v = call('/api/trial', {'kind': 'fw', 'action': 'keep'}, tok['boss'])
    ok('kept on the banner', (st, v['message'], v['trials']), (200, 'kept', []))
    st, v = call('/api/power', session=tok['watcher'])
    ok('Restart and power off: this server\'s card', (st, v['may'], v['me']['version'],
                                                      v['plan']), (200, False, isemon.__version__,
                                                                   {}))
    POWER.write_text('')
    st, v = call('/api/power', {'how': 'reboot'}, tok['boss'])
    ok('a restart asked: root does it 5 s later', (st, v['plan']['state'],
                                                    POWER.read_text().split()[:2]),
       (200, 'going', ['reboot', '5']))
    ok('...a second one meanwhile is refused', call('/api/power', {'how': 'reboot'},
                                                    tok['boss'])[0], 400)
    ok('...nor a change of the network', call('/api/net', {'action': 'apply', 'want': want2},
                                              tok['boss'])[0], 400)
    reboot()
    np.tick()
    st, v = call('/api/power', session=tok['boss'])
    ok('up again after the reboot', v['plan']['state'], 'back')
    st, v = call('/api/power', {'action': 'hide'}, tok['boss'])
    ok('...and hidden', v['plan'], {})
    ok('a power-off that is neither is refused', call('/api/power', {'how': 'halt'},
                                                      tok['boss'])[0], 400)

    # ------------------------------------------------------------------------
    print('\nThe command line')
    pal = isemon.Palette(False)
    (state / 'api-token').write_text(isemon.API_TOKEN)
    args = argparse.Namespace(json=True, change_keep='fw', change_back=None, reboot=False,
                              poweroff=False, yes=False)
    ok('isemon --change-keep fw with nothing waiting says so', isemon.cmd_change(args, pal, store),
       1)
    wr.firewall_save({'on': False}, 'boss')
    ok('...and with something waiting keeps it', (isemon.cmd_change(args, pal, store),
                                                  np.trials()), (0, []))
    args.json = False
    ok('isemon --net shows the network', isemon.cmd_net(args, pal, store), 0)
    import builtins
    was_input = builtins.input
    builtins.input = lambda *a: 'no'
    args.reboot = True
    POWER.write_text('')
    ok('isemon --reboot asks first, and no is no', (isemon.cmd_power(args, pal, store),
                                                    POWER.read_text()), (1, ''))
    builtins.input = was_input
    args.yes = True
    ok('...with --yes it restarts', (isemon.cmd_power(args, pal, store),
                                     POWER.read_text().split()[:1]), (0, ['reboot']))
    help_text = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                               capture_output=True, text=True).stdout
    ok('--net, --reboot, --poweroff, --change-keep and --change-back in --help',
       all(x in help_text for x in ('--net ', '--reboot', '--poweroff', '--change-keep',
                                    '--change-back')))

    # ------------------------------------------------------------------------
    print('\nThe page and the installer')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the banner on every page, drawn from the status',
       ('<div id="trials" class="trials" hidden></div>' in page,
        "if (typeof drawTrials === 'function') drawTrials(data);" in page), (True, True))
    ok('the two panes filled', ('function loadNet()' in page, 'function loadPower()' in page,
                                "$('net-body')" in page, "$('power-body')" in page),
       (True, True, True, True))
    ok('...the page goes to the new address when it was opened at the old one',
       'function netNewHost()' in page)
    inst = (ROOT / 'install.sh').read_text()
    ok('install.sh does not install NetworkManager', 'NetworkManager' not in inst.replace(
        '# NetworkManager', ''))
    helper = (ROOT / 'deploy' / 'isemon_web.py').read_text()
    ok('root reads net.ask before request.json', helper.index('        net_part()') <
       helper.index("os.replace('request.json', 'request.taken'"))
    ok('...and every binary it calls can be stood in for', all(
        x in helper for x in ('ISEMON_NMCLI', 'ISEMON_HOSTNAMECTL', 'ISEMON_HOSTS_FILE',
                              'ISEMON_POWER_CMD')))
finally:
    STOP.set()
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
