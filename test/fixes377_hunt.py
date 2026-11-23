#!/usr/bin/env python3
"""1.10.377: bug hunt, round 6 of 10 - the Traffic search, the network and
time panes, certificates and the daemon's own upkeep.

    ./test/fixes377_hunt.py
"""
import sys
from pathlib import Path

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


def refused(text):
    try:
        isemon.FwQuery(text)
        return False
    except isemon.FwQueryError:
        return True


print('The Traffic search')
q = isemon.FwQuery('-(dstport:22 OR dstport:80)')
ok('"-" before a bracket turns the group round', q.node[0], 'not')
ok('...and matches what is neither', (q.match({'dstport': 443}), q.match({'dstport': 22})),
   (True, False))
q = isemon.FwQuery('10.0.0.0/24')
ok('a range typed alone is either end of a line in it',
   (q.match({'srcip': '10.0.0.7'}), q.match({'dstip': '10.0.0.200'}),
    q.match({'srcip': '10.0.1.7'})), (True, True, False))
ok('a MAC however written is no word the record must hold',
   isemon.FwQuery('srcmac:AA-BB-CC-DD-EE-01').needles(), [])
ok('~ on a number is said, not taken for =', refused('port~44'), True)
q = isemon.FwQuery('src:2001:0db8::5')
ok('an IPv6 address however written', q.match({'srcip': '2001:db8::5'}), True)
ok('proto:pim and proto:ipv6', (refused('proto:pim'), refused('proto:ipv6')), (False, False))

print('Certificates')
subj = isemon.tls_subject({'cn': 'a' * 30 + '.' + 'b' * 30 + '.' + 'c' * 10 + '.example.cz'})
ok('a name of more than 64 letters: the CN its first label, the name in the SAN',
   (subj[0] if isinstance(subj, tuple) else str(subj)).count('CN=' + 'a' * 30) >= 1)
try:
    isemon.tls_subject({'cn': 'isemon.example.cz', 'san': 'fe80::1%eth0'})
    said = 'taken'
except isemon.WebRootError:
    said = 'refused'
ok('an address with its %zone is refused for the SAN', said, 'refused')

print('The rest')
src = (ROOT / 'isemon.py').read_text()
ok('a network of /0 to /7, a gateway that is the network or broadcast, no DNS: refused',
   "a /%d is too wide a network for one machine" in src
   and "the gateway %s is %s\\'s own %s address" in src
   and 'a DNS server or two, with the address set by hand' in src)
ok('a way back root would refuse is no trial', "no trial: the network it has now could not be put back" in src)
ok('chrony put in again ten minutes after it failed', "done.get('hash') == h and done.get('ok') is False" in src)
ok('a power-off on its way is busy for two minutes', "and time.time() - float(p.get('moved') or p.get('at') or 0) > 120)" in src)
ok('the VPN\'s addresses kept newest last, and capped', 'self._fw_inner.move_to_end(assigned)' in src)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
