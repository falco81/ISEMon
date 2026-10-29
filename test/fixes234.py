#!/usr/bin/env python3
"""1.10.234: what three reviews of 1.10.228-1.10.233 found.

- The network on trial: a second change refused while one waits to be kept;
  Keep pressed as the trial runs out never answered "kept" for a network
  that goes back; going back with the connection down, with an old host name
  of one word, and every NetworkManager setting as it was (all addresses,
  dns-search, ignore-auto-dns); a machine that never restarted put back.
- Root's /etc/hosts: other names on this machine's lines kept, other
  machines' lines untouched, hosts.isemon-before written once; a time zone
  never begins with '-'; chrony.conf lines with tabs; isemon's IPv6 sysctl
  file away when IPv6 goes off.
- Going back: root keeps the highest floor it has seen (two steps never get
  below it), and the console's profile is only taken away once install.sh
  went through.
- Upgrades online: four-part versions, a size that is not a number, every
  redirect https.
- The console: the log opened without following a link or waiting on a FIFO,
  and no escape sequence from a file reaching root's terminal.
- Remote backups: only this installation's own files taken away, never the
  one just sent; a damaged file said, not a traceback; a key's passphrase
  and a password both used; folders left behind by a stopped service taken
  away.

    ./test/fixes234.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
work = Path(tempfile.mkdtemp(prefix='isemon-234-'))
BTIME = work / 'btime'
BTIME.write_text('1000\n')
os.environ.update(ISEMON_WEB_HELPER='1', ISEMON_BTIME_FILE=str(BTIME),
                  ISEMON_STATE=str(work / 'state'), ISEMON_FLOOR_FILE=str(work / 'floor'))
(work / 'state').mkdir()

import isemon  # noqa: E402

PASSED = []
FAILED = []


def ok(what, got, want=True):
    if got == want:
        PASSED.append(what)
        print('  ok    %s' % what)
    else:
        FAILED.append(what)
        print('  FAIL  %s\n        got  %r\n        want %r' % (what, got, want))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
print('Root: the network')
W = load('isemon_web_234', ROOT / 'deploy' / 'isemon_web.py')
req = {'do': 'apply', 'con': 'System eth0',
       'ipv4': {'addr': '192.0.2.10/24', 'gw': '192.0.2.1', 'dns': ['192.0.2.53'], 'search': []},
       'ipv6': {'mode': 'off'}, 'hostname': 'isemon', 'old': ['198.51.100.7'],
       'old_hostname': 'isemon.new.cz', 'reboot_in': 8}
try:
    W.net_checked(req)
    ok('a host name of one word refused for a change', False)
except W.Refused:
    ok('a host name of one word refused for a change', True)
ok('...and taken going back', W.net_checked(dict(req, rollback=True))['hostname'], 'isemon')
n = W.net_checked(dict(req, hostname='isemon.new.cz', old=['192.0.2.10', '2001:db8::10'],
                       old_hostname='isemon.example.cz',
                       ipv4={'addr': '198.51.100.7/24', 'gw': '', 'dns': [], 'search': []}))
hosts = ('127.0.0.1 localhost\n::1 localhost\n'
         '192.0.2.10 isemon.example.cz isemon ntp.example.cz  # by hand\n'
         '2001:db8::10 isemon.example.cz isemon\n'
         '192.0.2.30 isemon.lab.cz isemon\n'
         '192.0.2.99 old.lab.cz    # this machine - written by isemon\n')
got = W.hosts_lines(hosts, n).splitlines()
ok('hosts: other names on its old line kept, its own taken out',
   '192.0.2.10 ntp.example.cz # by hand' in got, True)
ok('hosts: a line left with no name goes', any(x.startswith('2001:db8::10') for x in got), False)
ok('hosts: another machine\'s line untouched', '192.0.2.30 isemon.lab.cz isemon' in got, True)
ok('hosts: a line isemon wrote goes', any('192.0.2.99' in x for x in got), False)
ok('hosts: its new line', got[-1].startswith('198.51.100.7 isemon.new.cz isemon'), True)

ex = W.nm_exact({'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.10/24, 192.0.2.11/24',
                 'ipv4.gateway': '192.0.2.1', 'ipv4.dns': '192.0.2.53', 'ipv4.dns-search':
                 'example.cz', 'ipv6.method': 'auto', 'ipv6.addresses': '', 'ipv6.gateway': '--',
                 'ipv6.dns': '', 'ipv4.ignore-auto-dns': 'no'})
ok('what it had: every address', ex['ipv4.addresses'], '192.0.2.10/24,192.0.2.11/24')
ok('...ignore-auto-dns as it was', ex['ipv4.ignore-auto-dns'], 'no')
ok('...a setting not read before is left out', 'ipv6.ignore-auto-dns' in ex, False)
for bad in ({'ipv4.method': 'manual; rm', 'ipv6.method': 'auto'},
            {'ipv4.method': 'manual', 'ipv6.method': 'auto', 'ipv4.addresses': '-x'},
            {'ipv4.method': 'manual', 'ipv6.method': 'auto', 'ipv4.dns': '1.2.3.4\nx'}):
    try:
        W.nm_exact(bad)
        ok('a wrong value put back refused: %r' % sorted(bad.items())[0:1], False)
    except W.Refused:
        ok('a wrong value put back refused', True)
ok('a time zone never begins with -', bool(W.TZ_RE.match('-h')), False)
ok('...Europe/Prague still one', bool(W.TZ_RE.match('Europe/Prague')), True)
ok('...UTC still one', bool(W.TZ_RE.match('UTC')), True)

# The apply, with nmcli and hostnamectl played by scripts.
fake = work / 'bin'
fake.mkdir()
NM = work / 'nm.json'
NM.write_text(json.dumps({'con': 'eth0c', 'f': {
    'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.10/24', 'ipv4.gateway': '192.0.2.1',
    'ipv4.dns': '192.0.2.53', 'ipv4.dns-search': '', 'ipv6.method': 'disabled',
    'ipv6.addresses': '', 'ipv6.gateway': '', 'ipv6.dns': '', 'ipv4.ignore-auto-dns': 'no',
    'ipv6.dns-search': '', 'ipv6.ignore-auto-dns': 'no'}, 'modify': [], 'hostname': 'a.b.cz'}))
(fake / 'nmcli').write_text('''#!%s
import json, sys
p = %r
s = json.load(open(p))
a = sys.argv[1:]
if a[:3] == ['-t', '-g', 'NAME']:
    print(s['con'])
elif a[:2] == ['-t', '-g']:
    for k in a[2].split(','):
        print(s['f'].get(k, ''))
elif a[:2] == ['connection', 'modify']:
    s['modify'].append(a[3:])
    for k, v in zip(a[3::2], a[4::2]):
        s['f'][k] = v
    json.dump(s, open(p, 'w'))
''' % (sys.executable, str(NM)))
(fake / 'hostnamectl').write_text('#!/bin/sh\nexit 0\n')
for f in fake.iterdir():
    f.chmod(0o755)
W.NMCLI = str(fake / 'nmcli')
W.HOSTNAMECTL = str(fake / 'hostnamectl')
W.HOSTS_FILE = str(work / 'hosts')
W.SYSCTL_IPV6 = str(work / 'sysctl-ipv6.conf')
Path(W.HOSTS_FILE).write_text('127.0.0.1 localhost\n192.0.2.10 a.b.cz a\n')
W.write_root = lambda path, text, mode: Path(path).write_text(text)
on = W.net_checked({'con': 'eth0c', 'ipv4': {'addr': '192.0.2.20/24', 'gw': '192.0.2.1',
                                            'dns': ['192.0.2.53']},
                    'ipv6': {'mode': 'auto'}, 'hostname': 'c.b.cz', 'old': ['192.0.2.10'],
                    'old_hostname': 'a.b.cz'})
got = W.net_apply(on)
before = got['before']
ok('apply: what it had handed back, all of it', (before['ipv4.addresses'],
                                                 before['ipv4.ignore-auto-dns']),
   ('192.0.2.10/24', 'no'))
ok('IPv6 on: isemon\'s sysctl file', Path(W.SYSCTL_IPV6).exists(), True)
ok('hosts.isemon-before written', Path(W.HOSTS_FILE + '.isemon-before').read_text(),
   '127.0.0.1 localhost\n192.0.2.10 a.b.cz a\n')
back = W.net_checked({'con': 'eth0c', 'ipv4': {'addr': '192.0.2.10/24', 'gw': '192.0.2.1'},
                      'ipv6': {'mode': 'off'}, 'hostname': 'a', 'rollback': True,
                      'old': ['192.0.2.20'], 'old_hostname': 'c.b.cz', 'exact': before})
W.net_apply(back)
f = json.loads(NM.read_text())['f']
ok('going back: every setting as it was', {k: f[k] for k in before}, before)
ok('IPv6 off again: isemon\'s sysctl file away', Path(W.SYSCTL_IPV6).exists(), False)
ok('hosts.isemon-before not written over',
   Path(W.HOSTS_FILE + '.isemon-before').read_text(), '127.0.0.1 localhost\n192.0.2.10 a.b.cz a\n')
CH = work / 'chrony.conf'
CH.write_text('pool\t2.almalinux.pool.ntp.org iburst\nserver  ntp.x.cz\n')
W.CHRONY_CONF = str(CH)
W.CHRONYC = W.TIMEDATECTL = '/bin/true'
try:
    own = W.ntp_read().get('own')
except Exception as e:              # noqa: BLE001
    own = str(e)
ok('chrony.conf: a line with a tab is one of its servers', len(own or []), 2)

# ---------------------------------------------------------------------------
print('\nThe daemon: the network on trial')


class Store(object):
    def __init__(self):
        self.m = {}

    def get_meta(self, k, d=''):
        return self.m.get(k, d)

    def set_meta(self, k, v):
        self.m[k] = v

    def drop_meta(self, k):
        self.m.pop(k, None)

    def add_event(self, *a, **k):
        pass

    def release(self):
        pass


class D(object):
    pass


class WR(object):
    def tls_conf(self):
        return {}


d = D()
d.store = Store()
d.webroot = WR()
d.save_settings = lambda *a, **k: None
np_ = isemon.NetPower(d)
calls = []
NOW = {'nm': True, 'con': 'eth0c', 'dev': 'eth0', 'hostname': 'old.example.cz',
       'devices': [{'dev': 'eth0', 'type': 'ethernet', 'state': 'connected', 'con': 'eth0c'}],
       'conf': {'ipv4_method': 'manual', 'ipv4_addresses': ['192.0.2.10/24'],
                'ipv4_gateway': '192.0.2.1', 'ipv4_dns': ['192.0.2.53'], 'ipv4_search': [],
                'ipv6_method': 'disabled'},
       'live': {'addrs4': [{'addr': '192.0.2.10/24', 'dev': 'eth0'}], 'addrs6': []}}
NOW_ = {'v': NOW}


def fake_root(data, wait=60):
    calls.append(data)
    if data['do'] == 'read':
        return NOW_['v']
    return {'said': ['ok'], 'before': {'ipv4.method': 'manual', 'ipv4.addresses':
                                       '192.0.2.10/24,192.0.2.11/24', 'ipv6.method': 'disabled'}}


np_.root = fake_root
np_._thread = lambda fn, *a: (fn(*a), True)[1]
np_.cert_again = lambda w, by: ''
np_.cert_swap = lambda w: ({}, None, {})
isemon.CONFIG['net_confirm_min'] = 10
np_.publish()
want = {'con': 'eth0c', 'hostname': 'new.example.cz',
        'ipv4': {'addr': '192.0.2.20/24', 'gw': '192.0.2.1', 'dns': '192.0.2.53'}}
np_.ask(want, 'admin')
BTIME.write_text('2000\n')
NOW2 = json.loads(json.dumps(NOW))
NOW2['hostname'] = 'new.example.cz'
NOW2['conf']['ipv4_addresses'] = ['192.0.2.20/24']
NOW2['live']['addrs4'] = [{'addr': '192.0.2.20/24', 'dev': 'eth0'}]
NOW2['devices'] = []                        # the connection is down just now
NOW_['v'] = NOW2
np_.tick()
ok('back up: on trial', np_._get('net:job')['state'], 'trial')
try:
    np_.ask(dict(want, ipv4={'addr': '192.0.2.30/24', 'gw': '192.0.2.1'}), 'admin')
    ok('a second change while one is on trial refused', False)
except isemon.WebRootError:
    ok('a second change while one is on trial refused', True)
try:
    np_.power_ask('reboot', 'admin')
    ok('...and a restart', False)
except isemon.WebRootError:
    ok('...and a restart', True)
# Keep as the trial runs out: the tick going back holds the job first.
j = np_._get('net:job')
j['trial_until'] = time.time() - 1
np_._put('net:job', j)
orig_publish = np_.publish
said = {}


def publish_and_keep():
    try:
        said['keep'] = np_.answer('net', 'keep', 'admin')
    except isemon.WebRootError as e:
        said['keep'] = 'refused: %s' % e
    return orig_publish()


np_.publish = publish_and_keep
np_.tick()
np_.publish = orig_publish
ok('Keep pressed as it ran out: not told "kept"', said['keep'].startswith('refused'), True)
j = np_._get('net:job')
ok('going back with the connection down', (j['state'], j.get('rollback')), ('rebooting', True))
last = calls[-1]
ok('...root asked with every setting it had', last.get('exact', {}).get('ipv4.addresses'),
   '192.0.2.10/24,192.0.2.11/24')
ok('...as going back (a host name of one word allowed)', last.get('rollback'), True)

# Keep pressed before the tick: kept.
calls[:] = []
d.store.m.clear()
NOW_['v'] = NOW
BTIME.write_text('3000\n')
np_.publish()
np_.ask(want, 'admin')
BTIME.write_text('4000\n')
NOW_['v'] = NOW2
np_.tick()
ok('kept: on trial first', np_._get('net:job')['state'], 'trial')
np_.answer('net', 'keep', 'admin')
ok('kept', np_._get('net:job')['state'], 'done')

# Never restarted while on trial: what it had goes back in.
d.store.m.clear()
NOW_['v'] = NOW
BTIME.write_text('5000\n')
np_.publish()
np_.ask(want, 'admin')
j = np_._get('net:job')
j['moved'] = time.time() - 1000
np_._put('net:job', j)
np_.busy = False
np_.tick()
j = np_._get('net:job')
ok('it never restarted: the old network asked for again', (j.get('rollback'), j['state']),
   (True, 'rebooting'))

# ---------------------------------------------------------------------------
print('\nGoing back: root\'s floor')
keys = work / 'keys'
keys.mkdir()
lib = work / 'lib'
lib.mkdir()
subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(keys / 'r.key')],
               check=True, capture_output=True)
subprocess.run(['openssl', 'pkey', '-in', str(keys / 'r.key'), '-pubout', '-out',
                str(keys / 'test.pub')], check=True, capture_output=True)
os.environ.update(ISEMON_RELEASE_KEYS=str(keys), ISEMON_LIB=str(lib),
                  ISEMON_CONSOLE_PROFILE=str(work / 'prof.sh'))
os.environ.pop('ISEMON_FLOOR_FILE', None)
U = load('isemon_upgrade_234', ROOT / 'deploy' / 'isemon_upgrade.py')


def installed(v, floor=None):
    (lib / 'isemon.py').write_text("__version__ = '%s'\n%s" % (
        v, ("DOWNGRADE_FLOOR = '%s'\n" % floor) if floor else ''))


def package(v, rc=0, console=True):
    top = work / 'pk' / ('isemon-%s' % v)
    shutil.rmtree(str(top.parent), ignore_errors=True)
    (top / 'deploy' / 'release-keys').mkdir(parents=True)
    shutil.copy(str(keys / 'test.pub'), str(top / 'deploy' / 'release-keys'))
    if console:
        (top / 'deploy' / 'isemon-console-login.sh').write_text('#\n')
    (top / 'isemon.py').write_text("__version__ = '%s'\n" % v)
    (top / 'install.sh').write_text('#!/bin/bash\necho fake\nexit %d\n' % rc)
    out = work / ('isemon-%s.tar.gz' % v)
    subprocess.run([sys.executable, str(ROOT / 'tools' / 'release.py'), str(top),
                    str(keys / 'r.key'), str(out)], check=True, capture_output=True)
    return str(out)


if os.geteuid() == 0:
    installed('1.10.240', '1.10.238')
    ok('one step back, above the floor', U.put_in(package('1.10.238'), downgrade=True)[0], 0)
    ok('...the floor kept by root', (lib / 'downgrade-floor').read_text().strip(), '1.10.238')
    installed('1.10.238', '1.10.226')
    try:
        U.put_in(package('1.10.230'), downgrade=True)
        ok('a second step below the floor the first one had: refused', False)
    except U.Refused:
        ok('a second step below the floor the first one had: refused', True)
    (work / 'prof.sh').write_text('# console\n')
    installed('1.10.240', '1.10.226')
    (lib / 'downgrade-floor').unlink()
    rc = U.put_in(package('1.10.239', rc=1, console=False), downgrade=True)[0]
    ok('install.sh failed: the console\'s profile is still there', (rc, (work / 'prof.sh').exists()),
       (1, True))
    rc = U.put_in(package('1.10.239', rc=0, console=False), downgrade=True)[0]
    ok('...went through: taken away', (rc, (work / 'prof.sh').exists()), (0, False))
else:
    print('  (not root: put_in is skipped)')
ok('the floor file never goes down', U.FLOOR_RE.match('1.10.226') is not None, True)

# ---------------------------------------------------------------------------
print('\nUpgrades online')
m = isemon.Upgrades.ONLINE_PKG_RE.search('/isemon-1.10.233.1.tar.gz')
ok('a four-part version found', m and m.group(2), '1.10.233.1')


class FakeUp(isemon.Upgrades):
    def __init__(self):
        pass


up = FakeUp()
up.online_get = lambda url, **k: (json.dumps([
    {'name': 'isemon-1.10.233.tar.gz', 'download_url': 'https://x.cz/isemon-1.10.233.tar.gz',
     'size': 'big'},
    {'name': 'isemon-1.10.233.1.tar.gz', 'download_url': 'https://x.cz/isemon-1.10.233.1.tar.gz',
     'size': 1000}]).encode(), 'application/json', url)
got = up.online_list('https://x.cz/list.json')
ok('the newest first, four parts', [x['version'] for x in got], ['1.10.233.1', '1.10.233'])
ok('a size that is not a number: none', [x['bytes'] for x in got], [1000, None])
try:
    isemon.Upgrades.online_get('http://x.cz/')
    ok('http refused', False)
except ValueError:
    ok('http refused', True)

# ---------------------------------------------------------------------------
print('\nThe console')
C = isemon.Console
ln = 'x evil\x1b]0;PWNED\x07\x1b[2J\x1bP+q\x1b\\ y\x9b1m z \x1b[31mred\x1b[0m'
ok('escapes from a file taken out', C._term_safe(ln), 'x evil y1m z red')
ok('...isemon\'s own colours kept where asked', C._term_safe(ln, sgr=True),
   'x evil y1m z \x1b[31mred\x1b[0m')
fifo = work / 'fifo'
os.mkfifo(str(fifo))
try:
    C._log_open(fifo)
    ok('a FIFO for the log: not read', False)
except OSError:
    ok('a FIFO for the log: not read', True)
link = work / 'link'
link.symlink_to('/etc/hostname')
try:
    C._log_open(link)
    ok('a link for the log: not followed', False)
except OSError:
    ok('a link for the log: not followed', True)
(work / 'real.log').write_text('one\n')
with C._log_open(work / 'real.log') as f:
    ok('a plain log read', f.read(), 'one\n')

# ---------------------------------------------------------------------------
print('\nRemote backups')


class Tr(object):
    def __init__(self, names):
        self.names = list(names)
        self.gone = []

    def list(self):
        return [{'name': n, 'size': 1} for n in self.names]

    def delete(self, n):
        self.gone.append(n)
        self.names.remove(n)


site, host = isemon.rb_site(), isemon.rb_host()
fut = 'isemon-backup-%s-%s-20270101-000000.tar.gz.enc' % (site, host)
new = 'isemon-backup-%s-%s-20261029-041500.tar.gz.enc' % (site, host)
twin = 'isemon-backup-%s-%s-20261028-041500.tar.gz.enc' % (site, host)
tr = Tr([fut, new, twin])
gone = isemon.rb_retain(tr, 1, 0, just=new, sent=[fut, new])
ok('the one just sent is never taken away', new in tr.names, True)
ok('...a name from a clock once ahead is', gone, [fut])
ok('...one it never sent (another machine of the same name) left alone', twin in tr.names, True)
store = Store()
store.m['rbackup:runs'] = json.dumps([{'file': 'a.enc'}, {'file': 'b.enc'}])
ok('what it sent: first from its history', isemon.rb_sent(store), ['a.enc', 'b.enc'])
isemon.rb_sent_add(store, 'c.enc')
ok('...then kept as it sends', isemon.rb_sent(store), ['a.enc', 'b.enc', 'c.enc'])
ask = isemon.rb_askpass(str(work))
for prompt, want_ in (("Enter passphrase for key '/x':", 'KEYPASS'),
                      ("u@h's password:", 'PASSWORD')):
    got = subprocess.run([ask, prompt], capture_output=True, text=True, env=dict(
        os.environ, ISEMON_RB_SECRET='PASSWORD', ISEMON_RB_KEYPASS='KEYPASS')).stdout.strip()
    ok('askpass: %s' % want_.lower(), got, want_)
# A damaged file.
pk = work / 'b.tar.gz'
with tarfile.open(str(pk), 'w:gz') as t:
    one = work / 'about.json'
    one.write_text(json.dumps({'x': 1}) + ' ' * 200000)
    t.add(str(one), arcname='isemon-backup-x/about.json')
    big = work / 'big'
    big.write_bytes(os.urandom(300000))
    t.add(str(big), arcname='isemon-backup-x/' + isemon.RB_DB)
data = pk.read_bytes()
cut = work / 'cut.tar.gz'
cut.write_bytes(data[:len(data) // 2])
try:
    (work / 'w').mkdir()
    isemon.rb_open(str(cut), '', str(work / 'w'))
    ok('a backup cut short: said', False)
except isemon.RbError as e:
    ok('a backup cut short: said (%s)' % e, 'damaged' in str(e) or 'cut short' in str(e))
except Exception as e:              # noqa: BLE001
    ok('a backup cut short: said, not %s' % e.__class__.__name__, False)
# A folder left behind.
sc = Path(isemon.scratch_dir())
old = sc / 'isemon-rbackup-left'
old.mkdir(exist_ok=True)
(old / 'isemon-x-rbackup.db').write_text('x')
fresh = sc / 'isemon-putback-now'
fresh.mkdir(exist_ok=True)
(fresh / 'x').write_text('x')
t0 = time.time() - 2 * 86400
os.utime(str(old / 'isemon-x-rbackup.db'), (t0, t0))
os.utime(str(old), (t0, t0))
isemon.rb_tidy_work()
ok('a backup\'s folder left behind a day: taken away', old.exists(), False)
ok('...one in use: left', fresh.exists(), True)
shutil.rmtree(str(fresh), ignore_errors=True)

shutil.rmtree(str(work), ignore_errors=True)
print('\n%d ok, %d failed' % (len(PASSED), len(FAILED)))
sys.exit(1 if FAILED else 0)
