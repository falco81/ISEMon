#!/usr/bin/env python3
"""1.10.216: the service of a line whose protocol has no ports - ICMP by its
message, GRE, ESP, OSPF... - for every firewall."""
import sys
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


S = isemon.fw_proto_service
print('\nThe service by the protocol')
ok('ICMP and ICMPv6 by their message, the rest by name, an unknown one by its number',
   [S(1, {'icmp_type': '8'}), S(1, {'icmptype': '0x00'}), S(58, {'icmp_type': '135'}),
    S(1, {}), S(47), S(50), S(51), S(89), S(112), S(115), S(1, {'icmp_type': '42'})],
   ['icmp/echo-request', 'icmp/echo-reply', 'icmpv6/neighbor-solicitation', 'icmp', 'gre',
    'esp', 'ah', 'ospf', 'vrrp', 'proto/115', 'icmp/42'])
ok('...and nothing for TCP, UDP and SCTP, whose service is their port', [S(6), S(17), S(132), S(0),
                                                                        S('x')],
   ['', '', '', '', ''])
lines = [{'type': 'traffic', 'proto': 47, 'service': ''},
         {'type': 'traffic', 'proto': 1, 'service': 'PING'},
         {'type': 'traffic', 'proto': 6, 'service': ''},
         {'type': 'event', 'proto': 1, 'service': ''}]
isemon.fw_service_filled(lines)
ok('filled where none was written, on traffic only; a firewall\'s own word kept',
   [f['service'] for f in lines], ['gre', 'PING', '', ''])

print('\nA MikroTik\'s ICMP line')
import time  # noqa: E402
from datetime import datetime  # noqa: E402
NOW = time.time()
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(
    datetime.fromtimestamp(NOW - 120))
said = isemon.ros_parse_lines([
    STAMP + ' gw firewall,info drop input: in:VLAN108 out:(unknown 0), connection-state:new '
    'src-mac 44:31:92:3e:5e:ca, proto ICMP (type 8, code 0), 89.1.2.3->195.189.0.26, len 84'],
    {}, now=NOW)
f = said[0].facts if said else {}
ok('its message read from the line', ((f.get('fields') or {}).get('icmp_type'),
                                      (f.get('fields') or {}).get('icmp_code'), f.get('proto')),
   ('8', '0', 1))
isemon.fw_service_filled([f])
ok('...and its service said by it', f.get('service'), 'icmp/echo-request')

page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE / 'isemon.py').read_text(encoding='utf-8')
print('\nWhere')
ok('every line is given it before it is written, whatever the firewall',
   '        fw_service_filled(many)\n        if not any(\'msgid\'' in src)
ok('a line written before says its protocol on the page',
   'function tServiceOf(r)' in page and page.count('tServiceOf(r)') >= 6)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
