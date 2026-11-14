#!/usr/bin/env python3
"""1.10.332: what a real controller's log said that the page did not -
Get-Changes alone is not replication (a SharePoint or DirSync reader); the
other logs' events with every field and their message; Digest sign-ins.

    ./test/fixes332_real_more.py
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


H = 'Nov 10 07:05:00 dc2 WinSecurity: EventID=%d | %s'
R4662 = ('An operation was performed on an object.  Subject :  Security ID:  S-1-5-21-1-25969  Account '
         'Name:  SpInstall  Account Domain:  CORP  Logon ID:  0xB139C40B  Object:  Object Server:  DS  '
         'Object Type:  %%{19195a5b-6da0-11d0-afd3-00c04fd930c9}  Object Name:  '
         '%%{b8b5c259-966a-43dd-a886-7e9edd13729f}  Handle ID:  0x0  Operation:  Operation Type:  Object '
         'Access  Accesses:  Control Access       Access Mask:  0x100  Properties:  Control Access   '
         '{%s}  {19195a5b-6da0-11d0-afd3-00c04fd930c9}   Additional Information:  Parameter 1:  -  '
         'Parameter 2:')

print('Replication is reading the secrets, not the directory')
ok('Get-Changes on its own (SharePoint profile sync, DirSync): not "asked to replicate"',
   'replication' in isemon.win_record_from(H % (4662, R4662 % '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'))
   .facts['mark'], False)
ok('Get-Changes-All - what every DCSync asks for: still is',
   'replication' in isemon.win_record_from(H % (4662, R4662 % '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
   .facts['mark'])
ok('...and In-Filtered-Set',
   'replication' in isemon.win_record_from(H % (4662, R4662 % '89e95b76-444d-4c62-991a-0facbeda640c'))
   .facts['mark'])
ok('the rows already marked are read again - only those, not every read of the directory',
   (isemon.Storage.WIN_SORT_VERSION, isemon.Storage.MARK_VERSIONS[6]),
   (10, {'events': (4662,), 'marks': ('replication',)}))
src = (ROOT / 'isemon.py').read_text()
ok('...narrowed by the mark only when every step since says so',
   ("if narrow and len(ways) == 1 and not whole:" in src,
    "\"COALESCE(mark, '') LIKE ?\" for _ in plan['marks'])" in src), (True, True))

print('\nThe other logs\' events: every field, and what they say')
f = isemon.win_record_from(H % (2887, 'During the previous 24 hour period, some clients attempted to '
                                'perform LDAP binds that were either: (1) A SASL ... connection   Number '
                                'of simple binds performed without SSL/TLS: 6688  Number of '
                                'Negotiate/Kerberos/NTLM/Digest binds performed without signing: 0')).facts
ok('2887: its message and both counts', (f['fields']['Message'][:30],
   f['fields']['Number of simple binds performed without SSL/TLS'],
   f['fields']['Number of Negotiate/Kerberos/NTLM/Digest binds performed without signing'], f['said']),
   ('During the previous 24 hour pe', '6688', '0', '6688 simple in the clear, 0 unsigned, in a day'))
f = isemon.win_record_from(H % (3041, 'The security of this directory server can be significantly '
                                'enhanced by configuring the server to enforce validation of Channel '
                                'Binding Tokens.')).facts
ok('3041: its message, and why', (f['fields']['Message'][:30], f['said']),
   ('The security of this directory', 'channel binding: the controller does not ask for it yet'))
f = isemon.win_record_from(H % (8004, 'Domain Controller Blocked Audit: Audit NTLM authentication to '
                                'this domain controller. Secure Channel name: WEB01 User name: SpInstall '
                                'Domain name: CORP Workstation name: APP02 Secure Channel type: 2  Audit '
                                'NTLM authentication requests within the domain CORP that would be '
                                'blocked.')).facts
ok('8004: every field, one space apart, and what it means',
   ([k for k in f['fields']], f['fields']['User name'], f['fields']['Secure Channel name']),
   (['Message', 'Secure Channel name', 'User name', 'Domain name', 'Workstation name',
     'Secure Channel type', 'What it means'], 'SpInstall', 'WEB01'))

print('\nDigest')
L = ('An account was successfully logged on.  Subject:  Security ID:  S-1-0-0  Account Name:  -  '
     'Logon Information:  Logon Type:  3  New Logon:  Security ID:  S-1-5-21-1-9617  Account Name:  '
     'printsrv  Account Domain:  CORP  Network Information:  Workstation Name: -  Source Network '
     'Address: 10.6.156.23  Source Port:  60164  Detailed Authentication Information:  Logon Process:  '
     'WDIGEST  Authentication Package: WDigest  Transited Services: -  Package Name (NTLM only): -  '
     'Key Length:  0')
ok('a sign-in by WDigest: by its address and its account',
   isemon.ad25_findings(4624, L, H % (4624, L)),
   [('digest', '', '10.6.156.23', 'printsrv', 'signed in with Digest (WDigest)')])

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('the list says what each of the other logs\' events is, not "something else"',
   "what.appendChild(el('span', '', r.kind === 'other' && WIN_EVENT_WORDS[String(r.event)]" in page)
ok('the Digest tile, and the events it opens', ("'digest': {icon: 'eye'," in page,
                                                "'digest': [4624]" in page), (True, True))

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
