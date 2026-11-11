#!/usr/bin/env python3
"""1.10.331: Before Windows Server 2025 against lines exactly as one real
domain controller sends them through NXLog (names made up): 4776 and 8004
write their fields one space apart, the Security log two; the other logs'
events are found and opened like any other; DES still allowed on an account.

    ./test/fixes331_real_lines.py
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


H = 'Nov 10 00:00:29 dc2 WinSecurity: EventID=%d | %s'
L4776 = ('The computer attempted to validate the credentials for an account.  Authentication Package: '
         'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: svc_store Source Workstation: APP01 '
         'Error Code: 0x0')
L8004 = ('Domain Controller Blocked Audit: Audit NTLM authentication to this domain controller. Secure '
         'Channel name: WEB01 User name: SpInstall Domain name: CORP Workstation name: APP02 Secure '
         'Channel type: 2  Audit NTLM authentication requests within the domain CORP that would be '
         'blocked if the security policy Network Security: Restrict NTLM: NTLM authentication in this '
         'domain is set to any of the Deny options.')
L2889 = ('The following client performed a SASL (Negotiate/Kerberos/NTLM/Digest) LDAP bind without '
         'requesting signing (integrity verification), or performed a simple bind over a clear text '
         '(non-SSL/TLS-encrypted) LDAP connection.    Client IP address: 10.6.0.80:44774  Identity the '
         'client attempted to authenticate as: CORP\\tsmadmin  Binding Type: 1')
L4768 = ('A Kerberos authentication ticket (TGT) was requested.  Account Information:  Account Name:  '
         'DC2$  Supplied Realm Name: CORP.INT  User ID:   S-1-5-21-1-26449  '
         'MSDS-SupportedEncryptionTypes: 0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)  Available Keys: '
         'AES-SHA1, RC4  Service Information:  Service Name:  krbtgt  Service ID:  S-1-5-21-1-502  '
         'MSDS-SupportedEncryptionTypes: 0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)  Available Keys: '
         'AES-SHA1, RC4  Domain Controller Information:  MSDS-SupportedEncryptionTypes: 0x1F (DES, RC4, '
         'AES128-SHA96, AES256-SHA96)  Available Keys: AES-SHA1, RC4  Network Information:  Client '
         'Address:  ::1  Client Port:  0  Advertized Etypes:    RC2-CBC-ENV   DES-EDE3-CBC-ENV   '
         'AES256-CTS-HMAC-SHA1-96   AES128-CTS-HMAC-SHA1-96   RC4-HMAC-NT   DES-CBC-MD5  Additional '
         'Information:  Ticket Options:  0x40810010  Result Code:  0x0  Ticket Encryption Type: 0x12  '
         'Session Encryption Type: 0x12  Pre-Authentication Type: 2')
L4769 = ('A Kerberos service ticket was requested.  Account Information:  Account Name:  '
         'user1@CORP.INT  Account Domain:  CORP.INT  Logon GUID:  {1}  MSDS-SupportedEncryptionTypes: '
         'N/A  Available Keys: N/A  Service Information:  Service Name:  CORP.DMZ  Service ID:  '
         'S-1-5-21-1-0  MSDS-SupportedEncryptionTypes: 0x1C (RC4, AES128-SHA96, AES256-SHA96)  '
         'Available Keys: None  Domain Controller Information:  MSDS-SupportedEncryptionTypes: 0x1C '
         '(RC4, AES128-SHA96, AES256-SHA96)  Available Keys: AES-SHA1, RC4  Network Information:  Client '
         'Address:  ::ffff:10.6.151.22  Client Port:  64046  Advertized Etypes:    '
         'AES256-CTS-HMAC-SHA1-96   AES128-CTS-HMAC-SHA1-96   RC4-HMAC-NT  Additional Information:  '
         'Ticket Options:  0x40810000  Ticket Encryption Type: 0x12  Failure Code:  0x0')

print('Fields one space apart (4776, 8004)')
ok('4776: the workstation and the account, not the rest of the line',
   isemon.ad25_findings(4776, L4776), [('ntlm', 'APP01', '', '', 'checked for svc_store')])
ok('8004: the workstation, the account, the server it was for',
   isemon.ad25_findings(8004, L8004), [('ntlm-srv', 'APP02', '', 'CORP\\SpInstall', 'for WEB01')])
ok('2889 (four spaces before the address): the address, port cut, and the account',
   isemon.ad25_findings(2889, L2889),
   [('ldap-clear', '', '10.6.0.80', 'CORP\\tsmadmin', 'simple bind on 389 without TLS')])

print('\nKerberos as it is really written')
got = isemon.ad25_findings(4768, L4768)
ok('a client offering RC2 and DES first and AES further on: not "offers no AES"; '
   'no RC4 for an AES ticket', [x[0] for x in got if x[0] in ('rc4', 'des', 'noaes')], [])
ok('DES still allowed on the account and on krbtgt (0x1F), not on the controller section',
   sorted(x[3] for x in got if x[0] == 'des-allowed'), ['DC2$', 'krbtgt'])
ok('a trust\'s "Available Keys: None", N/A for the client, 0x1C: nothing', isemon.ad25_findings(4769, L4769), [])

print('\nThe other logs\' events, found like any other')
r = isemon.win_record_from(H % (2889, L2889)).facts
ok('2889 kept with its words, its account, its domain and its address',
   (r['words'], r['account'], r['domain'], r['ip'], r['said']),
   ('an LDAP bind without signing or TLS', 'tsmadmin', 'CORP', '10.6.0.80',
    'simple bind on 389 without TLS'))
r = isemon.win_record_from(H % (8004, L8004)).facts
ok('8004 with its account and its machine, and why: the server it was for',
   (r['account'], r['domain'], r['machine'], r['said']), ('SpInstall', 'CORP', 'APP02', 'for WEB01'))
r = isemon.win_record_from(H % (4776, L4776)).facts
ok('4776 as the Security log\'s reading always had it - untouched',
   (r['kind'], r['account'], r['machine']), ('ntlm', 'svc_store', 'APP01'))

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('a row opens its own events: the numbers its kind is counted from, the machine and its address, '
   'the account as a word',
   ("var parts = (ev.length ? ['event:' + ev.join(',')] : []).concat(marked);" in page,
    "if (from.length) q.push('from:' + from.join(','));" in page,
    "'ldap-clear': [2889], 'ldap-unsigned': [2889], 'ldap-cbt': [3039]," in page),
   (True, True, True))
ok('...with nothing left over from before narrowing it, the computers shown',
   ("WKIND = '';\n  $('w-event').value = '';\n  $('w-server').value = '';\n  $('w-machines').checked = true;"
    in page))
ok('the new tile says what it is', "'des-allowed': {icon: 'key'," in page)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
