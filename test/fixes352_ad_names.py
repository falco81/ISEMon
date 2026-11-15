#!/usr/bin/env python3
"""1.10.352: the names in Making the keytab in AD as AD itself has them (the
NetBIOS name of the domain's crossRef - CORPNET_NT, not CORPNET - its realm,
and the account each SPN is on), and a person looked up for a certificate
request: CN, the UPN, the URL of their SID for strong mapping. Read only,
against test/mockldap.py.

    ./test/fixes352_ad_names.py
"""
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import isemon                                        # noqa: E402
import mockldap                                      # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


SID = bytes([1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]) + b''.join(
    x.to_bytes(4, 'little') for x in (1345087706, 903693047, 1615293757, 16480))
mockldap.PEOPLE['CN=Jana Testova,OU=People,DC=corpnet,DC=loc'] = {
    'sAMAccountName': ['jtestova'], 'userPrincipalName': ['jtestova@corpnet.cz'],
    'cn': ['Jana Testova'], 'displayName': ['Jana Testová'], 'mail': ['jana@corpnet.cz'],
    'objectSid': [SID], 'userAccountControl': ['512'],
    'objectClass': ['top', 'person', 'organizationalPerson', 'user'], 'memberOf': [],
    '_password': 'x-long-enough-password'}
mockldap.PEOPLE['CN=svc-web-http,OU=Service,DC=corpnet,DC=loc'] = {
    'sAMAccountName': ['svc-web-http'], 'servicePrincipalName': ['HTTP/monitor.corpnet.cz'],
    'userAccountControl': ['66048'], 'msDS-SupportedEncryptionTypes': ['24'],
    'objectClass': ['top', 'person', 'user'], 'memberOf': [], '_password': 'y-long-enough-pass'}
mockldap.PEOPLE['CN=Twin One,OU=People,DC=corpnet,DC=loc'] = {
    'sAMAccountName': ['twin1'], 'mail': ['twins@corpnet.cz'], 'objectClass': ['user'], 'memberOf': []}
mockldap.PEOPLE['CN=Twin Two,OU=People,DC=corpnet,DC=loc'] = {
    'sAMAccountName': ['twin2'], 'mail': ['twins@corpnet.cz'], 'objectClass': ['user'], 'memberOf': []}

port, stop = mockldap.serve()
folder = Path(tempfile.mkdtemp(prefix='isemon-352-'))
try:
    for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                     DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                     CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1, 'directory_host': '127.0.0.1',
                          'directory_port': port, 'directory_base': 'DC=corpnet,DC=loc',
                          'directory_bind': 'CN=Jan Novak,OU=People,DC=corpnet,DC=loc',
                          'directory_password': 'a-good-long-password'})
    store = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(store)

    print('the domain\'s names, as AD keeps them')
    ok('before it is read the card has none', d.kerberos_view()['ad_names'], None)
    got = d.kerberos_ad(['monitor.corpnet.cz', 'other.corpnet.cz', '192.0.2.1', 'bad name', 'x' * 300])
    ok('read from AD', got['from_ad'], True)
    ok('NetBIOS name of the crossRef, not the first label', got['netbios'], 'CORPNET_NT')
    ok('the realm from dnsRoot', (got['dns'], got['realm']), ('corpnet.loc', 'CORPNET.LOC'))
    ok('the first label is what was guessed before', d.kerberos_view()['netbios'], 'CORPNET')
    ok('...and the card now has it as AD keeps it', d.kerberos_view()['ad_names']['netbios'], 'CORPNET_NT')
    acc = {a['name']: a for a in got['accounts']}
    ok('only names, never an address or junk', sorted(acc), ['monitor.corpnet.cz', 'other.corpnet.cz'])
    ok('the account the SPN is on', (acc['monitor.corpnet.cz']['sam'], acc['monitor.corpnet.cz']['spn']),
       ('svc-web-http', 'HTTP/monitor.corpnet.cz'))
    ok('...AES 256 allowed, not switched off', (acc['monitor.corpnet.cz']['aes'],
                                                acc['monitor.corpnet.cz']['disabled']), (True, False))
    ok('a name with no SPN: no account', acc['other.corpnet.cz']['sam'], '')
    ok('not a list: nothing asked', d.kerberos_ad('monitor.corpnet.cz')['accounts'], [])
    isemon.CONFIG['directory_base'] = 'OU=People,DC=corpnet,DC=loc'
    ok('another base: what was kept is not shown', d.kerberos_view()['ad_names'], None)
    isemon.CONFIG['directory_base'] = 'DC=corpnet,DC=loc'

    print('a person, for a certificate request')
    for typed in ('jtestova', 'CORPNET_NT\\jtestova', 'jtestova@corpnet.cz', 'jana@corpnet.cz'):
        p = d.certlogin_person(typed)
        ok('found by %s' % typed, p['sam'], 'jtestova')
    ok('CN, UPN', (p['cn'], p['upn']), ('Jana Testova', 'jtestova@corpnet.cz'))
    ok('the SID as text', p['sid'], 'S-1-5-21-1345087706-903693047-1615293757-16480')
    ok('...and as the URL for strong mapping', p['url'],
       'tag:microsoft.com,2022-09-14:sid:S-1-5-21-1345087706-903693047-1615293757-16480')
    ok('the down-level name with the real NetBIOS name', p['down_level'], 'CORPNET_NT\\jtestova')
    ok('not switched off', p['disabled'], False)
    for typed, why in (('nobody-here', 'nobody'), ('twins@corpnet.cz', 'more than one'),
                       ('', 'type the name'), ('a\nb', 'type the name')):
        try:
            d.certlogin_person(typed)
            ok('%r refused' % typed, False)
        except ValueError as e:
            ok('%r refused: %s' % (typed, str(e)[:40]), why in str(e))

    print('the directory not answering')
    isemon.CONFIG['directory_port'] = 1
    got = d.kerberos_ad(['monitor.corpnet.cz'])
    ok('said, not thrown', (got['from_ad'], bool(got['said'])), (False, True))
    try:
        d.certlogin_person('jtestova')
        ok('a person: refused', False)
    except ValueError as e:
        ok('a person: refused with why', 'could not be asked' in str(e))

    print('the API and the page')
    src = (HERE.parent / 'isemon.py').read_text()
    page = (HERE.parent / 'web' / 'index.php').read_text()
    ok('kerberos ad is an action of a signed-in admin',
       "if act == 'ad':" in src and src.index("if act == 'ad':") > src.index("if path == '/api/kerberos':"))
    ok('certlogin person after need_admin', src.index("if act == 'person':") > src.index(
        "me = self.need_admin()", src.index("if path == '/api/certlogin':")))
    ok('the page asks AD for the names', "api('kerberos', {action: 'ad'" in page)
    ok('...and has the finder', "api('certlogin', {action: 'person'" in page)
    ok('no CORP guess left in the command', "var nb = d.netbios || 'CORP';" not in page)
finally:
    stop.set()
    shutil.rmtree(str(folder), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
