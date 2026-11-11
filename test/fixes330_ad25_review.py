#!/usr/bin/env python3
"""1.10.330: Before Windows Server 2025 gone over line by line - what it
counted wrongly, and the page's scroll bar after another tab.

    ./test/fixes330_ad25_review.py
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


F = isemon.ad25_findings
STAMP = time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - 60))


def kinds(event, text):
    return [x[0] for x in F(event, text, '%s dc1 WinSecurity: EventID=%d | %s' % (STAMP, event, text))]


A4624 = ('An account was successfully logged on.  Subject:  Security ID: S-1-0-0  Account Name: -  '
         'Account Domain: -  Logon ID: 0x0  Logon Information:  Logon Type: 3  New Logon:  '
         'Security ID: %s  Account Name: %s  Account Domain: %s  Logon ID: 0x1  '
         'Network Information:  Workstation Name: PC7  Source Network Address: 172.29.1.7  '
         'Source Port: 5000  Detailed Authentication Information:  Logon Process: NtLmSsp  '
         'Authentication Package: NTLM  Transited Services: -  Package Name (NTLM only): %s  '
         'Key Length: %s')

print('What was counted that is not trouble')
ok('a null session (ANONYMOUS LOGON) written down as "NTLM V1": not an NTLMv1 client',
   kinds(4624, A4624 % ('S-1-5-7', 'ANONYMOUS LOGON', 'NT AUTHORITY', 'NTLM V1', '0')), [])
ok('...a person signing in with NTLM V1 still is',
   kinds(4624, A4624 % ('S-1-5-21-1', 'jnovak', 'KRAJ', 'NTLM V1', '128')), ['ntlmv1'])
ok('...and LM, worse than NTLMv1, counted with it',
   kinds(4624, A4624 % ('S-1-5-21-1', 'jnovak', 'KRAJ', 'LM', '0')), ['ntlmv1'])
ok('the KDC: an account that HAS AES keys, asked only for RC4 by a client - the client\'s RC4, '
   'not an account without AES',
   kinds(27, 'While processing a TGS request for the target server http/web, the account svcweb did '
             'not have a suitable key for generating a Kerberos ticket (the missing key has an ID of 23). '
             'The requested etypes were 23 -135. The accounts available etypes were 18 17 23.'),
   ['rc4'])
ok('...one that has none of them still is',
   kinds(16, 'While processing a TGS request for the target server http/web, the account old-svc did not '
             'have a suitable key for generating a Kerberos ticket (the missing key has an ID of 18). '
             'The requested etypes : 18 17. The accounts available etypes : 23.'), ['noaes'])
T4769 = ('A Kerberos service ticket was requested.  Account Information:  Account Name: u@K  '
         'Account Domain: K  Service Information:  Service Name: svc  Network Information:  '
         'Client Address: ::ffff:10.0.0.5  Client Port: 1  Advertized Etypes: %s  '
         'Additional Information:  Ticket Options: 0x0  Ticket Encryption Type: 0x12  Failure Code: 0x0')
ok('etypes offered one to a line (runs of spaces): AES further down is still AES',
   kinds(4769, T4769 % 'RC4-HMAC-NT    AES256-CTS-HMAC-SHA1-96    AES128-CTS-HMAC-SHA1-96'), [])
ok('..."-" and nothing at all are not "no AES"',
   (kinds(4769, T4769 % '-'), kinds(4769, T4769 % '')), ([], []))
ok('...a client offering RC4 alone still is',
   kinds(4769, T4769 % 'RC4-HMAC-NT    RC4-HMAC-OLD'), ['rc4'])

print('\nAn empty field is not the next one\'s label')
got = F(4776, 'The computer attempted to validate the credentials for an account.  '
              'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account: svc  '
              'Source Workstation:   Error Code: 0x0')
ok('4776 with no workstation: no machine called "ERROR"', got[0][1], '')
got = F(8004, 'Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller.  '
              'Secure Channel name: FILESRV01  User name: jnovak  Domain name: KRAJ  '
              'Workstation name:   Secure Channel type: 2')
ok('8004 with no workstation: no machine called "SECURE"; its own kind, by user, the server said',
   (got[0][0], got[0][1], got[0][3], got[0][4]), ('ntlm-srv', '', 'KRAJ\\jnovak', 'for FILESRV01'))
got = F(2889, 'The following client performed ... Client IP address: 10.1.1.1:5000  '
              'Identity the client attempted to authenticate as:   Binding Type: 1')
ok('2889 with no identity: no account called "Binding"', (got[0][0], got[0][3]), ('ldap-clear', ''))
got = F(2889, 'The following client performed ... Client IP address: 10.1.1.1:5000  '
              'Identity the client attempted to authenticate as: CN=svc ldap,OU=Apps,DC=k,DC=int  '
              'Binding Type: 1')
ok('...an identity written as a DN with spaces read whole', got[0][3], 'CN=svc ldap,OU=Apps,DC=k,DC=int')

print('\nThe daily counts')
got = F(3040, 'During the previous 24 hour period, 37 unprotected LDAPS binds were performed.')
ok('3040: the count, not the 24 of "24 hour period"; each daily event its own row',
   (got[0][3], '37' in got[0][4]), ('event 3040', True))
ok('2887 its own row too', F(2887, 'Number of simple binds performed without SSL/TLS: 12  '
                                   'Number of Negotiate/Kerberos/NTLM/Digest binds performed without '
                                   'signing: 3')[0][3], 'event 2887')

work = Path(tempfile.mkdtemp(prefix='isemon-330-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    isemon.CONFIG.update(winsec=1, winsec_ad2025=1)

    def line(event, text, host='dc1', ago=60):
        return '%s %s WinSecurity: EventID=%d | %s' % (
            time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - ago)), host, event, text)

    print('\nWritten down')
    isemon.win_parse_lines([
        line(2887, 'Number of simple binds performed without SSL/TLS: 12  Number of '
                   'Negotiate/Kerberos/NTLM/Digest binds performed without signing: 3', ago=90),
        line(3041, 'The directory server is not currently configured to require LDAP channel binding.',
             ago=80),
        line(2887, 'Number of simple binds performed without SSL/TLS: 5  Number of '
                   'Negotiate/Kerberos/NTLM/Digest binds performed without signing: 0', host='dc2'),
    ], {})
    st.ad25_flush()
    v = st.ad25_view(24)
    ok('the controllers\' own daily counts kept apart and summed for the page '
       '(what the top card says when no tile names who)',
       v['daily'], {'simple': 17, 'unsigned': 3, 'controllers': 2})
    day = int(time.time() // 86400)
    now = time.time()
    for issue, client, account, detail in (
            ('ntlmv1', 'PC1', 'ANONYMOUS LOGON', 'signed in with NTLM V1'),
            ('noaes', '', 'svcweb', 'asked 23 -135, has 18 17 23'),
            ('rc4', '', 'u', 'the client offers no AES (RC4-HMAC-NT)'),
            ('ldap-daily', '', '', 'channel binding: 24'),
            ('ntlm', 'PC2', '', 'checked for KRAJ\\u at FILESRV01'),
            ('ntlm', 'ERROR', '', 'checked for svc'),
            ('ldap-clear', '', 'Binding', 'simple bind on 389 without TLS'),
            ('ntlm', 'PC3', '', 'checked for good')):
        st.db.execute('INSERT INTO ad25_seen (day, issue, ckey, server, client, ip, account, detail, n, '
                      't_first, t_last) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                      (day, issue, isemon.ad25_ckey('dc9', client, '', account + detail), 'dc9', client, '',
                       account, detail, 3, now, now))
    st.db.commit() if hasattr(st.db, 'commit') else None
    st.ad25_tidy()
    left = sorted((r['issue'], r['client'], r['account']) for r in st.db.execute(
        "SELECT issue, client, account FROM ad25_seen WHERE server = 'dc9'"))
    ok('what earlier versions counted wrongly is let go of; the rest kept', left, [('ntlm', 'PC3', '')])

    print('\nThe KDC\'s rows apart from the Security log\'s')
    isemon.win_parse_lines([line(4769, T4769.replace('0x12', '0x17') % 'AES256-CTS-HMAC-SHA1-96', ago=10)], {})
    st.ad25_flush()
    isemon.win_parse_lines([line(201, 'The KDC issued RC4.  Account Name: u@K  Client Address: 10.0.0.5',
                                 ago=30)], {})
    ok('a KDC event arriving later, older than the Security log\'s newest, still counted', st.ad25_flush(), 1)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('back from another tab, the list fitted again; never measured while hidden; the scroller asked '
   'again after the list is its new height',
   ("if (name === 'windows' && typeof a25FitSoon === 'function') a25FitSoon();" in page,
    'if (!box.offsetParent || !box.getClientRects().length) return;' in page,
    page.count('sc = a25Scroller(box);') == 2), (True, True, True))
ok('the export puts the names inside "what it was" by the stand-ins too',
   'return [M(r.client), M(r.ip), A(r.account), D(r), M(r.server)' in page)
ok('the top card does not say "nothing" while the daily count knows of binds no tile shows',
   'var unseen = !ldapSeen && ((daily.simple || 0) + (daily.unsigned || 0)) > 0;' in page)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
