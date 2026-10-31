#!/usr/bin/env python3
"""1.10.269: a Mikrotik with a very big list - its lists read with only the
three fields used (proplist=address,timeout,comment), and five minutes for
it rather than the 45 s of a short command; a RouterOS that does not know
proplist is read whole, as before, and remembered so.

    ./test/fixes269_router.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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


class Fake(object):
    MIKROTIK_READ_S = isemon.Daemon.MIKROTIK_READ_S
    MIKROTIK_PROPLIST = {}
    mikrotik_list_print = isemon.Daemon.mikrotik_list_print

    def __init__(self, knows=True, raises=False):
        self.sent, self.knows, self.raises = [], knows, raises

    def mikrotik_run(self, command, fw='mikrotik', timeout=None):
        self.sent.append((command, timeout))
        if 'proplist=' in command and not self.knows:
            if self.raises:
                raise RuntimeError('expected end of command (line 1 column 41)')
            return 'expected end of command (line 1 column 41)\n'
        return '0   address=192.0.2.1 timeout=1d comment="isemon x"\n'


f = Fake()
out = f.mikrotik_list_print('/ip', 'ISEMonDROP', 'mikrotik')
ok('only the three fields asked for, with five minutes for the answer',
   f.sent, [('/ip firewall address-list print terse proplist=address,timeout,comment '
             'where list=ISEMonDROP', 300)])
ok('...and its answer read', 'address=192.0.2.1' in out)
for raises in (False, True):
    Fake.MIKROTIK_PROPLIST = {}
    f = Fake(knows=False, raises=raises)
    out = f.mikrotik_list_print('/ip', 'ISEMonDROP', 'fw2')
    ok('a RouterOS without proplist (%s): read whole, as before' % ('an error' if raises else 'said'),
       ([c for c, _t in f.sent], 'address=192.0.2.1' in out),
       (['/ip firewall address-list print terse proplist=address,timeout,comment where list=ISEMonDROP',
         '/ip firewall address-list print terse where list=ISEMonDROP'], True))
    f.sent = []
    f.mikrotik_list_print('/ipv6', 'ISEMonDROP', 'fw2')
    ok('...and remembered: not asked with proplist again', [c for c, _t in f.sent],
       ['/ipv6 firewall address-list print terse where list=ISEMonDROP'])
ok('a short command keeps its 45 s', isemon.SSH_RUN_TIMEOUT, 45)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
