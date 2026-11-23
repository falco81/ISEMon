#!/usr/bin/env python3
"""1.10.374: bug hunt, round 3 of 10 - time (the days the clocks change, a
clock that was ahead), the token, acme and TACACS+ readers.

    TZ=Europe/Prague ./test/fixes374_hunt.py
"""
import os
import sys
import time as _t
import types
from pathlib import Path

os.environ['TZ'] = 'Europe/Prague'
_t.tzset()
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
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


print('A daily fetch at a chosen hour, on the days the clocks change')
real = isemon.time
NOW = [0.0]
fake = types.SimpleNamespace(**{k: getattr(_t, k) for k in dir(_t) if not k.startswith('__')})
fake.time = lambda: NOW[0]
fake.localtime = lambda s=None: _t.localtime(NOW[0] if s is None else s)
isemon.time = fake
try:
    for start, end, at in (((2026, 3, 27), (2026, 4, 1), '02:00'),
                           ((2026, 3, 27), (2026, 4, 1), '22:00'),
                           ((2026, 10, 23), (2026, 10, 28), '02:30')):
        isemon.CONFIG.update({'update_when': 'at_time', 'update_at': at})
        NOW[0] = _t.mktime(start + (int(at[:2]), int(at[3:]) + 5, 0, 0, 0, -1))
        last, days = NOW[0], set()
        stop = _t.mktime(end + (0, 0, 0, 0, 0, -1))
        while NOW[0] < stop:
            overdue = isemon.Daemon.fetch_overdue(last, 86400)
            if overdue >= 0 and isemon.Daemon.update_window_open(overdue, 86400):
                last = NOW[0]
                days.add(_t.strftime('%F', _t.localtime(NOW[0])))
            NOW[0] += 900
        ok('at %s every day after %s up to %s, the day the clocks change too'
           % (at, start, end), len(days), 4)
    NOW[0] = real.time()
    ok('a fetch "in the future" (the clock was ahead) is no fetch',
       isemon.Daemon.fetch_overdue(NOW[0] + 400 * 86400, 86400) >= 0)
finally:
    isemon.time = real

print('acme: the hour said twice')
ok('the BSD time of acme read as every other reader reads it',
   'otp_when(bits[0], bits[1], bits[2], now=now, zone=\'\')' in (ROOT / 'isemon.py').read_text())

print('TACACS+ commands')
f = isemon.tacplus_pairs(['cmd=enable', 'cmd-arg=secret', 'cmd-arg=S3cr3tPw'])
ok('cmd and its cmd-args one command', f['Command'], ['enable secret S3cr3tPw'])
ok('...whose secret is then not kept', isemon.command_field_kept(f['Command']),
   ['enable secret (hidden)'])
ok('enable password level 15 X', isemon.command_kept('enable password level 15 MyPw'),
   'enable password level 15 (hidden)')
ok('an SNMP community', isemon.command_kept('snmp-server host 10.0.0.1 version 2c Comm'),
   'snmp-server host 10.0.0.1 version 2c (hidden)')
ok('...and without a version', isemon.command_kept('snmp-server host 10.0.0.1 Comm'),
   'snmp-server host 10.0.0.1 (hidden)')
ok('what has no secret left as it is', isemon.command_kept('no password'), 'no password')

print('The log')
import tempfile                                       # noqa: E402
d = Path(tempfile.mkdtemp(prefix='isemon-374-'))
os.symlink(d / 'victim', d / 'isemon.log')
ok('never written through a link put where the log is', (isemon.open_log(d / 'isemon.log'),
                                                         (d / 'victim').exists()), (None, False))
os.unlink(d / 'isemon.log')
got = isemon.open_log(d / 'isemon.log')
got.write('a line\n')
got.close()
ok('...a file of its own as ever', (d / 'isemon.log').read_text(), 'a line\n')

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
