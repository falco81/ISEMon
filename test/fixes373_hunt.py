#!/usr/bin/env python3
"""1.10.373: bug hunt, round 2 of 10 - the firewalls' readers, the domain
and its sign-ins, and the copies. All names and addresses made up.

    ./test/fixes373_hunt.py
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


def ros(lines):
    out = []
    for r in isemon.ros_parse_lines(lines, hold={}, now=1760000000):
        f = dict(r.facts)
        f['fw'] = 'mt'
        f['area'] = isemon.fw_area(f)
        out.append(f)
    return out


print('RouterOS')
rows = ros(['Oct 18 10:00:00 gw l2tp,ppp,info,account bob logged in, 10.8.0.3 from 203.0.113.7',
            'Oct 18 10:05:00 gw l2tp,ppp,info,account bob logged in, 10.8.0.4 from 198.51.100.9',
            'Oct 18 10:10:00 gw l2tp,ppp,info,account bob logged out, 600 1 2 3 4',
            'Oct 18 10:20:00 gw l2tp,ppp,info,account bob logged out, 900 1 2 3 4'])
res = isemon.fw_vpn_fold(rows, now=rows[-1]['ts'] + 10)
ok('one person signed in twice: both sessions end, the first first',
   ([r['srcip'] for r in rows if r['action'] == 'tunnel-down'], res['clients'],
    res['ended_clients']), (['203.0.113.7', '198.51.100.9'], [], 2))
rows = ros(['Oct 18 10:00:00 gw ovpn,info ovpn-out1: connected'])
ok('its own site-to-site tunnel is in the view of what is up',
   len(isemon.fw_vpn_fold(rows, now=rows[-1]['ts'] + 10).get('tunnels') or []), 1)
rows = ros(['Oct 18 10:00:00 gw system,error,critical login failure for user admin from '
            '4C:5E:0C:11:22:33 via winbox'])
ok('a sign-in through MAC-Winbox: a MAC, never an address to count or ban',
   (rows[0]['srcip'], rows[0]['fields'].get('srcmac')), ('', '4C:5E:0C:11:22:33'))

print('FortiGate')
ok('the last line of a UDP session is a session',
   isemon.fw_carried({'type': 'traffic', 'action': 'accept', 'fields': {
       'logid': '0000000013', 'sentdelta': '100', 'rcvddelta': '200'}}), (100, 200, 1))
ok('...an interim line is not',
   isemon.fw_carried({'type': 'traffic', 'action': 'accept', 'fields': {
       'logid': '0000000020', 'sentdelta': '100', 'rcvddelta': '200'}}), (100, 200, 0))

print('FTD')
got = isemon.ftd_parse_lines(['Oct 18 10:00:00 ftd1 %ASA-6-302304: Teardown TCP state-bypass '
                              'connection 5 from outside:198.51.100.1/443 to inside:10.0.0.5/5000 '
                              'duration 0:00:30 bytes 99 TCP FINs'], {}, 1760000000)
ok('a state-bypass teardown is read', [(r.facts['srcip'], r.facts['sent']) for r in got],
   [('198.51.100.1', 99)])

print('The domain')
wf = isemon.WinFields()
wf['Error Code'] = '0x00000000'
ok('0x00000000 is a success', isemon.win_worked(4776, wf), True)
wf['Error Code'] = '0xC000006A'
ok('...and a refusal still a refusal', isemon.win_worked(4776, wf), False)
fields = isemon.WinFields()
fields['LDAP Display Name'] = 'msDS-AllowedToActOnBehalfOfOtherIdentity'
fields['Class'] = 'computer'
ok('resource-based delegation written by a machine is never routine',
   isemon.win_is_machinery(5136, fields, 'EVILPC$'), False)
fields['LDAP Display Name'] = 'dNSHostName'
ok('...a computer\'s own name still is', isemon.win_is_machinery(5136, fields, 'PC1$'), True)

print('The copies')
src = (ROOT / 'isemon.py').read_text()
ok('putting back what was there makes no copy of the broken one first',
   'self.restore(safety, safety=False)' in src)
ok('half a copy never left on a remote folder or FTP',
   src.count('half a copy never left behind (1.10.373)') + src.count('Half a copy never left behind (1.10.373)') >= 2)
ok('the complete export carries the firewalls\' API passwords opened',
   isemon.rosapi_opened([{'name': 'gw', 'api': {'password': 'plain'}}])[0]['api']['password'],
   'plain')
ok('a certificate\'s SID as a URL is read', "uri.lower().startswith('tag:microsoft.com,2022-09-14:sid:')"
   in src)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
