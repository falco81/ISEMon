#!/usr/bin/env python3
"""1.10.209: names of addresses everywhere they belong - the translated
addresses on the NAT page and in the popup, an IPv6 address with a port, and
the site's own machines asked about as their records arrive.

    ./test/fixes209.py
"""
import sys
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


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)

print('\nAsked as the records arrive')
r = isemon.ros_record_from(
    'Oct 19 18:00:00 gw firewall,info accept forward: in:VLAN108 out:DMZ, connection-state:new,dnat '
    'proto TCP (SYN), 94.154.20.57:15023->192.168.43.17:443, NAT 94.154.20.57:15023->'
    '(195.189.0.26:443->192.168.43.17:443), len 60', 1792430000, {}, {})
ok('a firewall line: where it came from, and the site\'s own server it went to',
   sorted(set(isemon.names_wanted_of(r))), ['192.168.43.17', '94.154.20.57'])
r = isemon.ros_record_from(
    'Oct 19 18:00:00 gw firewall,info accept forward: in:LAN out:VLAN108, connection-state:new '
    'proto TCP (SYN), 192.168.40.12:50000->8.8.8.8:443, len 60', 1792430000, {}, {})
ok('...but not the internet\'s addresses it went to', isemon.names_wanted_of(r),
   ['192.168.40.12'])


class Rec(object):
    ip = '185.1.1.1'
    fields = {'Address it was given': ['192.168.40.100'], 'Framed-IP-Address': ['10.9.9.9']}


ok('a sign-in: where it came from and the address the machine was given',
   sorted(set(isemon.names_wanted_of(Rec()))), ['10.9.9.9', '185.1.1.1', '192.168.40.100'])
ok('...both roads records arrive by ask for them',
   src.count('here.update(names_wanted_of(record))'), 2)
ok('the pass that fills names in goes over the machines\' addresses too',
   "('failed', 'client'), ('passed', 'client')" in src)

print('\nThe page')
ok('a translated address is drawn as an address, so it is given its name',
   'function tNatEnd(text, lead, cls, about)' in page
   and 'var box = tAddress(end.ip, end.port, \'\', \'\');' in page)
ok('...and in the popup, the address a span of its own beside its port',
   'if (T_END_FIELDS[one[2]]) {' in page)
ok('an IPv6 address with a port: the brackets beside it, not around it',
   "if (port && v6) line.appendChild(el('span', 'mono', '['));" in page
   and "port && v6 ? '[' + ip + ']'" not in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
