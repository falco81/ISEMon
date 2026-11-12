#!/usr/bin/env python3
"""1.10.337: bug hunt, run 2 - a TACACS+ name naming the address to ban, the
counted answers during a re-read, service tickets on the brute card, the
tiles' events of one second across two writes, RC4 counted twice, an
account written as a UPN, a lockout's address, the page's leftovers.

    ./test/fixes337_hunt_run2.py
"""
import json
import shutil
import sys
import tempfile
import time
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


print('TACACS+')
base = "Nov 10 10:00:00 tacsrv tac_plus[123]: login query for '%s' tty2 from 203.0.113.9 rejected%s"
for tail in ('', ' (bad password)', '#015'):
    r = isemon.tacplus_said_from(base % ("x' tty1 from 192.0.2.10 rejected", tail))
    ok('a name holding a sentence of its own does not choose the address (%r)' % tail, r.ip, '203.0.113.9')
ok('...an ordinary line still read', isemon.tacplus_said_from(base % ('jnovak', ' (bad password)')).user,
   'jnovak')

print('\nBefore Windows Server 2025')
L = ('A Kerberos service ticket was requested.  Account Information:  Account Name:  u@K  Service '
     'Information:  Service Name:  svc  Network Information:  Client Address:  ::ffff:10.0.0.5  '
     'Advertized Etypes:    RC4-HMAC-NT   RC4-HMAC-OLD-EXP  Additional Information:  Ticket Encryption '
     'Type: 0x17  Failure Code:  0x0')
got = isemon.ad25_findings(4769, L)
ok('a ticket in RC4 to a client offering only RC4: one event, not two', [x[0] for x in got], ['rc4'])
ok('the etypes offered read whole', isemon._ad25_word(isemon._AD25_OFFERED, L).split(),
   ['RC4-HMAC-NT', 'RC4-HMAC-OLD-EXP'])

work = Path(tempfile.mkdtemp(prefix='isemon-337-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    isemon.CONFIG.update(winsec=1, winsec_ad2025=1, winsec_keep_logons=1)
    stamp = time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - 60))
    ntlm = ('%s dc1 WinSecurity: EventID=4776 | The computer attempted to validate the credentials for an '
            'account.  Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: svc '
            'Source Workstation: PC1 Error Code: 0x0' % stamp)
    hold = {}
    isemon.win_parse_lines([ntlm, ntlm], hold)
    st.ad25_flush()
    isemon.win_parse_lines([ntlm], hold)
    st.ad25_flush()
    n = st.db.execute("SELECT SUM(n) AS n FROM ad25_seen WHERE issue = 'ntlm'").fetchone()['n']
    ok('three identical NTLM checks of one second, read in two lots by one reader: three', n, 3)
    isemon.win_parse_lines([ntlm, ntlm, ntlm], {})
    st.ad25_flush()
    n = st.db.execute("SELECT SUM(n) AS n FROM ad25_seen WHERE issue = 'ntlm'").fetchone()['n']
    ok('...the same file read again from its start: still three', n, 3)

    print('\nThe domain')
    lines = [
        '%s dc1 WinSecurity: EventID=4625 | An account failed to log on.  Subject:  Security ID:  S-1-5-18  '
        'Account Name:  DC1$  Logon Type:   3  Account For Which Logon Failed:  Security ID:  S-1-0-0  '
        'Account Name:  ok_x@corp.int  Account Domain:  CORP  Failure Information:  Failure Reason:  '
        '%%%%2313  Status:  0xC000006D  Sub Status:  0xC000006A  Network Information:  Workstation Name: '
        'PC9  Source Network Address: 10.0.0.9  Source Port:  1' % stamp,
        '%s dc1 WinSecurity: EventID=4771 | Kerberos pre-authentication failed.  Account Information:  '
        'Security ID:  S-1-5-21-1  Account Name:  ok_x  Service Information:  Service Name:  krbtgt/CORP  '
        'Network Information:  Client Address:  ::ffff:10.0.0.9  Client Port:  1  Additional Information:  '
        'Ticket Options:  0x40810010  Failure Code:  0x18  Pre-Authentication Type: 2' % stamp]
    # ...and the realm, as the domain's own service tickets write it.
    lines.append('%s dc1 WinSecurity: EventID=4769 | A Kerberos service ticket was requested.  Account '
                 'Information:  Account Name:  someone@CORP.INT  Account Domain:  CORP.INT  Service '
                 'Information:  Service Name:  svc  Network Information:  Client Address:  ::1  '
                 'Additional Information:  Ticket Encryption Type: 0x12  Failure Code:  0x0' % stamp)
    st.note_win_events([r.facts for r in isemon.win_parse_lines(lines, {})])
    got = st.win_around('ok_x', time.time() - 60, before=600, after=600)
    ok('an account written as a UPN is found by its bare name', sorted(r['event'] for r in got),
       [4625, 4771])
    got = st.win_rows(limit=10, since=time.time() - 3600, account='ok_x')
    rows = got[0] if isinstance(got, tuple) else (got.get('rows') if isinstance(got, dict) else got)
    ok('...and by the events page’s account filter', len(rows), 2)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

src = (ROOT / 'isemon.py').read_text()
ok('service tickets refused weigh no password: not on the brute or spray cards',
   src.count('AND event <> 4769') >= 2)
ok('the counted answers are let go of as soon as a re-read changes a row, and on picking one up',
   ('forget_counts()' in src, "self.roll_said(self.ROLL_NEW, 'the events are being read again', 0)" in src),
   (True, True))
ok('the object card is not answered by the rollup', "if (by != 'object' and self.roll_ready()" in src)
ok('a lockout’s address only from a refusal of its own machine',
   "win_short_name(said.get('machine')) == mine" in src)
ok('an older PostgreSQL dump: ad25_seen emptied after it', 'ad25_seen' in isemon.Storage.DUMP_MAY_LACK)
try:
    isemon.check_setting('winsec_zone', 'Mars/Nowhere')
    ok('a zone refused names its setting', 'accepted', 'refused')
except ValueError as e:
    ok('a zone refused names its setting', str(e).startswith('winsec_zone:'))

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('the account popup asks for the lockouts on their own', "api(ask + '&limit=1&kind=lockout')" in page)
ok('the front card opens the Domain tab at its window', 'var h = typeof overHours' in page)
ok('one account one stand-in in the export', ".split('@')[0];\n    if (!acc[k])" in page)
ok('the window of the front page asked once', "$('ov-hours').onchange = function () { loadDashboard(); };" in page)
ok('the NXLog route replaces the one of the same name; the check asks for User Account Management',
   ('<b>replaces</b>' in page, "'User Account Management'            = 'Success'" in page), (True, True))

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
