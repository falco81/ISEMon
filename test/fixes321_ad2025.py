#!/usr/bin/env python3
"""1.10.321: Domain → Before Windows Server 2025 - what a 2025 controller
refuses that a 2016 one lets through, counted off the controllers' lines as
they are read, before anything switched off is dropped; off unless switched on.

    ./test/fixes321_ad2025.py
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


now = time.localtime()
STAMP = time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - 120))


def line(event, text, host='pftcdcx02', when=STAMP):
    return '%s %s WinSecurity: EventID=%d | %s' % (when, host, event, text)


LINES = [
    line(4776, 'The computer attempted to validate the credentials for an account.  '
               'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Logon Account: jnovak  '
               'Source Workstation: PC0123  Error Code: 0x0'),
    line(4624, 'An account was successfully logged on.  Subject:  Security ID: S-1-0-0  Account Name: -  '
               'Account Domain: -  Logon ID: 0x0  Logon Information:  Logon Type: 3  Restricted Admin Mode: -  '
               'Virtual Account: No  Elevated Token: No  Impersonation Level: Impersonation  New Logon:  '
               'Security ID: S-1-5-21-1  Account Name: scanner01  Account Domain: KRAJ  Logon ID: 0x5A1  '
               'Network Information:  Workstation Name: PRINTER7  Source Network Address: 172.29.1.50  '
               'Source Port: 50211  Detailed Authentication Information:  Logon Process: NtLmSsp  '
               'Authentication Package: NTLM  Transited Services: -  Package Name (NTLM only): NTLM V1  '
               'Key Length: 0'),
    line(4769, 'A Kerberos service ticket was requested.  Account Information:  Account Name: jnovak@KRAJ.LOCAL  '
               'Account Domain: KRAJ.LOCAL  Logon GUID: {0}  MSDS-SupportedEncryptionTypes: 0x27 (DES, RC4, AES-Sk)  '
               'Available Keys: AES-SHA1, RC4  Service Information:  Service Name: svc-sql  Service ID: S-1-5-21-2  '
               'MSDS-SupportedEncryptionTypes: 0x4 (RC4)  Available Keys: RC4  Domain Controller Information:  '
               'MSDS-SupportedEncryptionTypes: 0x1C (RC4, AES128-SHA96, AES256-SHA96)  Available Keys: AES-SHA1, RC4  '
               'Network Information:  Client Address: ::ffff:172.29.5.10  Client Port: 51111  '
               'Advertized Etypes: AES256-CTS-HMAC-SHA1-96, RC4-HMAC-NT  Additional Information:  '
               'Ticket Options: 0x40810000  Ticket Encryption Type: 0x17  Failure Code: 0x0  Transited Services: -'),
    line(2889, 'The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without '
               'requesting signing (integrity verification), or performed a simple bind over a clear text '
               '(non-SSL/TLS-encrypted) LDAP connection.  Client IP address: 172.29.153.5:52811  '
               'Identity the client attempted to authenticate as: KRAJ\\svc-app  Binding Type: 1'),
    line(2889, 'The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without '
               'requesting signing (integrity verification), or performed a simple bind over a clear text '
               '(non-SSL/TLS-encrypted) LDAP connection.  Client IP address: 172.29.5.10:40000  '
               'Identity the client attempted to authenticate as: KRAJ\\jnovak  Binding Type: 0'),
    line(2887, 'During the previous 24 hour period, some clients attempted to perform LDAP binds that were '
               'either: (1) A SASL ... Number of simple binds performed without SSL/TLS: 12  '
               'Number of Negotiate/Kerberos/NTLM/Digest binds performed without signing: 3'),
    line(3000, 'SMB1 access  Client Address: 172.29.9.9  Guidance: This event indicates that a client '
               'attempted to access the server using SMB1.'),
    line(8004, 'Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller.  '
               'Secure Channel name: FILESRV01  User name: jnovak  Domain name: KRAJ  '
               'Workstation name: PC0123  Secure Channel type: 2'),
    line(16, 'While processing a TGS request for the target server http/web.kraj.local, the account '
             'old-svc did not have a suitable key for generating a Kerberos ticket (the missing key has an '
             'ID of 18). The requested etypes : 18 17. The accounts available etypes : 23.'),
    line(4662, 'An operation was performed on an object.'),
]

work = Path(tempfile.mkdtemp(prefix='isemon-321-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    isemon.CONFIG.update(winsec=1, winsec_ad2025=0, winsec_keep_logons=0, winsec_keep_reads=0)

    print('Off unless switched on')
    isemon.win_parse_lines(LINES, {})
    ok('switched off: nothing noted', (isemon.AD25['queue'], isemon.ad25_on()), ([], False))
    ok('...the default is off', isemon.DEFAULTS.get('winsec_ad2025'), 0)

    print('\nWhat the lines say')
    isemon.CONFIG['winsec_ad2025'] = 1
    isemon.win_parse_lines(LINES, {})
    got = sorted({(x[2], x[3] or x[4], x[5]) for x in isemon.AD25['queue']})
    ok('NTLM by its workstation, from 4776 (the sign-ins switched off: read anyway)',
       ('ntlm', 'PC0123', '') in got)
    ok('NTLMv1 from 4624, with the machine and the account',
       ('ntlmv1', 'PRINTER7', 'scanner01') in got)
    ok('RC4 ticket from 4769, by the client\'s address', ('rc4', '172.29.5.10', 'jnovak@KRAJ.LOCAL') in got)
    ok('...the service with no AES keys', ('noaes', '', 'svc-sql') in got)
    ok('...but not the account that has them', ('noaes', '', 'jnovak@KRAJ.LOCAL') not in got)
    ok('LDAP simple bind in the clear (2889, type 1) and unsigned (type 0), by address, port cut',
       (('ldap-clear', '172.29.153.5', 'KRAJ\\svc-app') in got,
        ('ldap-unsigned', '172.29.5.10', 'KRAJ\\jnovak') in got), (True, True))
    ok('the controller\'s daily count (2887)', any(x[0] == 'ldap-daily' for x in got))
    ok('SMB1 (3000) by address', ('smb1', '172.29.9.9', '') in got)
    ok('NTLM by server (8004) - its own kind, not a second NTLM (1.10.330)',
       any(x[2] == 'ntlm-srv' and x[5] == 'KRAJ\\jnovak' and 'FILESRV01' in x[6]
           for x in isemon.AD25['queue']))
    ok('the KDC\'s missing key (16)', ('noaes', '', 'old-svc') in got)
    ok('an event of no concern adds nothing; a client offering AES is not RC4\'s', len(isemon.AD25['queue']), 10)

    print('\nWritten down')
    n = st.ad25_flush()
    ok('a row each', n, 10)
    v = st.ad25_view(24)
    by = {i['key']: i for i in v['issues']}
    ok('the view: each kind with its count', (by['ldap-clear']['n'], by['smb1']['n'], by['ntlmv1']['n']),
       (1, 1, 1))
    m = {x['name'] or x['ip']: x for x in v['machines']}
    ok('...a machine with every kind it does; the address given the name another event knew',
       sorted(m['172.29.5.10']['issues']), ['ldap-unsigned', 'rc4'])
    a = {x['name']: x for x in v['accounts']}
    ok('...an account and what it does', sorted(a['svc-sql']['issues']), ['noaes'])
    ok('...machines worst first', isemon.AD25_LEVEL[sorted(
        v['machines'][0]['issues'], key=lambda k: {'crit': 0, 'warn': 1, 'info': 2}[
            isemon.AD25_LEVEL[k]])[0]], 'crit')
    src = v['sources']
    ok('what the logs can see: Security, Directory Service (with 2889), SMB, NTLM, KDC',
       (sorted(k for k in src if not k.startswith('_')), bool(src.get('_diag'))),
       (['ds', 'kdc', 'ntlm', 'security', 'smb'], True))

    print('\nRead again')
    isemon.win_parse_lines(LINES, {})
    st.ad25_flush()
    v = st.ad25_view(24)
    by = {i['key']: i for i in v['issues']}
    ok('the same lines read again (a rotation, the pass back): not counted again',
       (by['ldap-clear']['n'], by['ntlm']['n']), (1, 1))
    later = time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - 30))
    isemon.win_parse_lines([line(2889, LINES[3].split('| ', 1)[1], when=later)], {})
    st.ad25_flush()
    by = {i['key']: i for i in st.ad25_view(24)['issues']}
    ok('...a new one counted', by['ldap-clear']['n'], 2)

    print('\nKept')
    st.db.execute('UPDATE ad25_seen SET day = day - 200')
    st.db.commit() if hasattr(st.db, 'commit') else None
    st.ad25_tidy()
    ok('older than the days kept: let go of', st.rows_in('ad25_seen'), 0)

    print('\nThe page and the setting')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the switch under The domain controllers, shown only with them',
       ("'winsec_rollup', 'winsec_ad2025'," in page, "winsec_ad2025: ['winsec', '1']," in page),
       (True, True))
    ok('the page: its button hidden unless the status says so, the relay knows it',
       ('data-page="ad25" aria-selected="false" hidden' in page, "'ad25'      => '/api/ad25'," in page,
        "ad25Show(!!s.ad2025_on)" in page), (True, True, True))
    ok('...and the NXLog inputs for the Directory Service log on it',
       '&lt;Select Path="Directory Service"&gt;' in page)
    ok('the export for analysis (1.10.326): a few rows of each kind, names by stand-ins if wanted',
       ("function a25Markdown(d, per, hideAcc, hideMach)" in page, "var rows = i.rows.slice(0, per);" in page,
        "[50, 100, 250].forEach" in page), (True, True, True))
    guide = (ROOT / 'docs' / 'active-directory-logging.md').read_text()
    ok('the guide to the controllers\' logs (1.10.327): GPO, each controller, nxlog.conf, the check, linked',
       ('New-GPLink' in guide, 'SCENoApplyLegacyAuditPolicy' in guide, '<Input eventlog_ntlm>' in guide,
        'eventlog_kdc, eventlog_smb1, eventlog_ntlm => out_syslog' in guide,
        'active-directory-logging.md' in (ROOT / 'docs' / 'before-windows-server-2025.md').read_text()),
       (True, True, True, True, True))
    src = (ROOT / 'isemon.py').read_text()
    ok('the status says so only with the controllers\' logs on',
       "'ad2025_on': bool(self.winsec_on() and int(CONFIG.get('winsec_ad2025') or 0))," in src)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
