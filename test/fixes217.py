#!/usr/bin/env python3
"""1.10.217: what a look over the whole of it found - the MikroTik reader's
thread, its clock, IPv6, its sessions' memory; the NAT page, searches by
page, suggestions, the kept answers; and the Router page and its settings."""
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.argv = ['isemon']
import isemon  # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


src = (HERE / 'isemon.py').read_text(encoding='utf-8')
page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')

print('\nOver ssh: asked again without its fields, without waiting on itself')
calls = []
real = isemon.ssh_run


def fake(cfg, host, command):
    calls.append((command, cfg.get('timeout')))
    if 'proplist' in command:
        raise RuntimeError('expected end of command (line 1 column 40)')
    return 'name=gw\n'


isemon.ssh_run = fake
try:
    s = isemon.RosSsh('192.0.2.1', 22, 'isemon-read', '', 'KEY')
    s.sock = True
    done = []
    th = threading.Thread(target=lambda: done.append(s.talk('/system/identity/print', None,
                                                            'name')), daemon=True)
    th.start()
    th.join(5)
    ok('answered, not stuck on its own lock', (th.is_alive(), done and done[0]),
       (False, [{'name': 'gw'}]))
    ok('...the second time without the fields', ('proplist' in calls[0][0],
                                                 'proplist' in calls[-1][0]), (True, False))
    ok('...and with its own time to answer, longer than a command\'s',
       calls[0][1] == float(isemon.ROSSSH_TIMEOUT) and isemon.ROSSSH_TIMEOUT > 45, True)
    probe = isemon.rosapi_session({'mode': 'ssh', 'host': 'x', 'user': 'u'}, timeout=15.0)
    ok('...but a try from the page waits no longer than the page does', probe.timeout, 15.0)
finally:
    isemon.ssh_run = real


class Store(object):
    def __init__(self):
        self.meta = {}

    def get_meta(self, k, d=None):
        return self.meta.get(k, d)

    def set_meta(self, k, v):
        self.meta[k] = v


class Daemon(object):
    def __init__(self):
        self.store = Store()
        self.handed = []

    def fw_hand_in(self, many):
        self.handed.extend(many)


class Session(object):
    sock = True

    def __init__(self, menus):
        self.menus = menus

    def talk(self, command, args=None, proplist=None, query=None):
        got = self.menus.get(command)
        if isinstance(got, Exception):
            raise got
        if got is None:
            raise isemon.RosApiError('no such command')
        return [dict(r) for r in got]

    def count(self, command, query=None):
        got = self.menus.get(command)
        return len(got) if isinstance(got, list) else None


print('\nIPv6\'s connections not ended by a round that could not read them')
d = Daemon()
r = isemon.RosReader(d, 'gw', {'host': 'gw', 'every': 30, 'mode': 'pin'})
menus = {'/ip/firewall/connection/tracking/print': [{'total-entries': '1'}],
         '/ip/firewall/connection/print': [{'.id': '*1', 'src-address': '10.0.0.1:1',
                                            'dst-address': '8.8.8.8:53', 'protocol': 'udp'}],
         '/ipv6/firewall/connection/print': [{'.id': '*1', 'src-address': '[2001:db8::1]:5',
                                              'dst-address': '[2001:db8::2]:443',
                                              'protocol': 'tcp', 'orig-bytes': '10'}]}
s = Session(menus)
now = time.time()
r.read_connections(s, now)
ok('both read', sorted(r.conns), ['*1', '6*1'])
menus['/ipv6/firewall/connection/print'] = isemon.RosApiError('timed out')
r.read_connections(s, now + 30)
ok('IPv6\'s read failed: its connections kept, nothing written as ended',
   (sorted(r.conns), d.handed), (['*1', '6*1'], []))
menus['/ipv6/firewall/connection/print'] = []
r.read_connections(s, now + 60)
ok('...read again, the one gone ends once', [f['srcip'] for f in d.handed], ['2001:db8::1'])

print('\nThe router\'s clock')
r.clock_skew = 0.0
s = Session({'/system/clock/print': [{'date': time.strftime('%Y-%m-%d',
                                                         time.localtime(time.time() - 7200)),
                                      'time': time.strftime('%H:%M:%S',
                                                            time.localtime(time.time() - 7200))}]})
r.read_clock(s)
ok('two hours behind this machine\'s: its zone learnt', r.clock_skew, -7200.0)
said = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 7200 - 600))
ok('...and its times read as this machine\'s', abs(r.when(said) - (time.time() - 600)) < 5, True)
ok('...never later than now', r.when(time.strftime('%Y-%m-%d %H:%M:%S',
                                                   time.localtime(time.time() + 3600)))
   <= time.time() + 1, True)

print('\nIts interfaces\' day, and what the page is given while it reads')
r.if_hist = {'gone': [[now - 90000, 1, 1]], 'lan': [[now - 90000, 1, 1], [now, 2, 2]]}
r.read_interfaces(Session({'/interface/print': []}), now)
ok('a day and no more: an interface gone a day forgotten', (sorted(r.if_hist),
                                                            len(r.if_hist['lan'])), (['lan'], 1))
readers = isemon.RosReaders(d)
readers.readers['gw'] = r
stop = threading.Event()


def grow():
    i = 0
    while not stop.is_set():
        k = i % 400
        r.router['k%d' % k] = i
        r.if_hist['x%d' % k] = [[now, 1, 1]]
        if k == 399:
            for j in range(400):
                r.router.pop('k%d' % j, None)
                r.if_hist.pop('x%d' % j, None)
        i += 1


th = threading.Thread(target=grow, daemon=True)
th.start()
bad = 0
for _ in range(300):
    try:
        readers.snapshot('gw')
    except RuntimeError:
        bad += 1
stop.set()
th.join(2)
ok('a snapshot while the reader adds to it never fails', bad, 0)
readers.readers.clear()
ok('an interface is looked up once a round, not through every route each time',
   'cache[key] = found' in src and 'self._intf_cache = {}' in src)
ok('a session is shut, not closed, under a read of it',
   'def abort(self):' in src and 'session.abort()' in src)
ok('the API read through a buffer', "self.sock.makefile('rb', buffering=65536)" in src)

print('\nKept answers')


class Held(object):
    HELD_WAIT_S = 2
    HELD_FAILED_S = 30
    REFRESH_MOST = 4
    HELD_MOST = 2000
    HELD_STAMPED = isemon.Daemon.HELD_STAMPED

    def __init__(self):
        self._slow, self._slow_busy, self._slow_wait, self._slow_cost = {}, set(), {}, {}
        self._slow_lock = threading.RLock()
        self._slow_gen = {}


for name in ('held', 'kept_for', 'slow_gen', '_held_only_newest', '_held_again'):
    if hasattr(isemon.Daemon, name):
        setattr(Held, name, getattr(isemon.Daemon, name))
h = Held()
runs = []
gate = threading.Event()


def slow():
    runs.append(1)
    if len(runs) == 1:
        gate.wait(1)
        raise isemon.AskedToStop()
    time.sleep(0.3)
    return 'answer'


got, errs = [], []


def ask():
    try:
        got.append(h.held('k', 30, slow))
    except Exception as e:                      # noqa: BLE001
        errs.append(type(e).__name__)


first = threading.Thread(target=ask)
first.start()
time.sleep(0.1)
others = [threading.Thread(target=ask) for _ in range(5)]
for one in others:
    one.start()
time.sleep(0.1)
gate.set()
first.join(5)
for one in others:
    one.join(5)
ok('whoever worked it out stopped: one waiter takes it over, not all of them at once',
   len(runs), 2)
ok('the firewalls\' marks are kept as the newest only', 'fw-marks/' in isemon.Daemon.HELD_STAMPED)
ok('the names of addresses counted once a minute, not at every opening of Settings',
   "self.daemon.held('ptr-count', 60" in src)
ok('a list nobody has kept is worked out once for everybody asking it at once',
   "waiting = self.__dict__.setdefault('_lists_wait', {})" in src)
ok('the overview does not wait for the VPN to be put together after a start',
   'raise VpnStillBuilding()' in src and 'except VpnStillBuilding:' in src)

print('\nThe firewall\'s lines')
q = isemon.FwQuery('area:nat')
sql = q.sql()[0] if hasattr(q, 'sql') else ''
ok('a page asked for by its name uses its index', 'area = ?' in str(sql) or
   "else 'area = ?' if c == 'area'" in src)
ok('the NAT page is kept and worked out behind the page, not read back at every poll',
   "and not (asked['area'] == 'nat' and fw_nat_in_sessions())" in src)
ok('a line is read apart only when the search asks something of what is inside it',
   "if not inside_keys:" in src and "if any(k in low for k in inside_keys):" in src)
ok('a field that is not counted: read once and what is typed picked out of it',
   "[str(field), '', since, str(one('fw') or ''), area, 'all']" in src)

print('\nThe page')
ok('the Router page narrowed a quarter of a second after the last key, not at every one',
   "window._trTyping = setTimeout(drawRouter, 250);" in page)
ok('...its day of an interface asked once for each look at the router',
   "if (TR_HIST_DATA[hkey]) {" in page)
ok('...an answer that came after a later question is not drawn',
   "if (mine !== TR_ASKED) return;" in page)
ok('...nor asked again within a quarter of a minute',
   "if (quiet && TROUTER && key === TR_KEY && Date.now() - TR_AT < 15000) return;" in page)
ok('...opened straight on it, drawn once the routers are known',
   "if (TPAGE === 'router') loadRouter(true);" in page)
ok('a row made a MikroTik shows its API at once',
   "kind.onchange = function () { rows[index].type = kind.value; settle(); paint(); };" in page)
ok('the name a row has when a button is pressed', "var nameNow = function () {" in page
   and "name: nameNow()" in page)
ok('a password\'s dots chosen whole when pressed, so typing replaces them',
   page.count("if (input.value.indexOf('\\u2022') === 0) input.select();") == 2)
ok('over ssh an emptied port is 22', "(one.api.mode === 'ssh' ? 22 : 8729)" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
