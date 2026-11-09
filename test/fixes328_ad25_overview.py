#!/usr/bin/env python3
"""1.10.328: Domain → Overview → Worth looking at says what the logs of
Before Windows Server 2025 found - LDAP in the clear, NTLMv1, DES, SMB1,
unsigned LDAP, channel binding, accounts with no AES keys - and only where
that page is switched on and they found something: without them the
overview is exactly what it was.

    ./test/fixes328_ad25_overview.py
"""
import json
import shutil
import sys
import tempfile
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


# The lines of fixes321, without running its checks.
src = (HERE / 'fixes321_ad2025.py').read_text()
head = src.split("work = Path(tempfile.mkdtemp(")[0]
ns = {'__file__': str(HERE / 'fixes321_ad2025.py'), '__name__': 'lines'}
exec(compile(head, 'fixes321', 'exec'), ns)
LINES = ns['LINES']


class Stub(object):
    """What `ad25_incidents` needs of the daemon, and nothing else."""
    AD25_WORTH = isemon.Daemon.AD25_WORTH
    WIN_INCIDENTS = isemon.Daemon.WIN_INCIDENTS

    def __init__(self, store):
        self.store = store

    def held(self, key, seconds, make, *a, **k):
        return make()


def incidents(stub, since):
    out = []

    def add(key, n, who='', last=0.0, says='', where=None, domain=''):
        for kind, level, words, told in stub.WIN_INCIDENTS:
            if kind == key and n:
                out.append({'kind': key, 'level': level, 'words': words, 'says': told,
                            'more': says, 'n': int(n), 'who': who, 'last': last,
                            'where': where or {}})
    isemon.Daemon.ad25_incidents(stub, add, out, since)
    return out


work = Path(tempfile.mkdtemp(prefix='isemon-328-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    stub = Stub(st)
    since = isemon.time.time() - 24 * 3600

    print('Without the new logs')
    isemon.CONFIG.update(winsec=1, winsec_ad2025=0, winsec_keep_logons=0, winsec_keep_reads=0)
    ok('switched off: nothing added to the overview', incidents(stub, since), [])
    isemon.CONFIG['winsec_ad2025'] = 1
    ok('switched on but nothing counted yet: nothing added either', incidents(stub, since), [])

    print('\nWith them')
    isemon.win_parse_lines(LINES, {})
    st.ad25_flush()
    got = incidents(stub, since)
    by = {x['kind']: x for x in got}
    ok('the kinds found, each once; RC4 and NTLM left to the cards that already say them',
       sorted(by), ['ad25-ldap-clear', 'ad25-ldap-unsigned', 'ad25-noaes', 'ad25-ntlmv1',
                    'ad25-smb1'])
    ok('...each a kind the overview knows, with its level',
       (by['ad25-ldap-clear']['level'], by['ad25-ldap-unsigned']['level']), ('warn', 'info'))
    ok('...the machine and the account doing it, said',
       'the most from 172.29.153.5 as KRAJ\\svc-app' in by['ad25-ldap-clear']['more'])
    ok('...an address given the name another event knew it by',
       'from PRINTER7' in by['ad25-ntlmv1']['more'] or 'PRINTER7' in by['ad25-ntlmv1']['more'])
    ok('...what fixes it, and where the rest is',
       (by['ad25-smb1']['reads'][0].startswith('What fixes it: SMB 2/3'),
        'Before Windows Server 2025' in by['ad25-smb1']['next'][0]), (True, True))
    ok('...pressed, it opens that page at that kind: by machine, or by account',
       (by['ad25-ldap-clear']['where'], by['ad25-noaes']['where']),
       ({'ad25': 'ldap-clear', 'page': 'machines'}, {'ad25': 'noaes', 'page': 'accounts'}))
    w = st.ad25_worth(since)
    ok('the counting: a machine and an account each', (w['ldap-clear']['n'],
       w['ldap-clear']['clients'], w['ldap-clear']['accounts']), (1, 1, 1))
    ok('...older than the window: not counted', st.ad25_worth(isemon.time.time() + 60), {})

    print('\nAvailable Keys: N/A (1.10.329)')
    real = ns['line'](4769, 'A Kerberos service ticket was requested.  Account Information:  '
        'Account Name: 9809138PCW11$@KR-OLOMOUCKY.INT  Account Domain: KR-OLOMOUCKY.INT  '
        'Logon GUID: {A81A8543-780F-750F-3842-8D9F6002D1FB}  MSDS-SupportedEncryptionTypes: N/A  '
        'Available Keys: N/A  Service Information:  Service Name: 9809138PCW11$  '
        'Service ID: S-1-5-21-1345087706-903693047-1615293757-53352  '
        'MSDS-SupportedEncryptionTypes: 0x1C (RC4, AES128-SHA96, AES256-SHA96)  '
        'Available Keys: AES-SHA1, RC4  Domain Controller Information:  '
        'MSDS-SupportedEncryptionTypes: 0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)  '
        'Available Keys: AES-SHA1, RC4  Network Information:  Client Address: ::ffff:172.29.185.104  '
        'Client Port: 60752  Advertized Etypes: AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 '
        'RC4-HMAC-NT  Additional Information:  Ticket Options: 0x40810000  '
        'Ticket Encryption Type: 0x12  Session Encryption Type: 0x12  Failure Code: 0x0  '
        'Transited Services: -')
    ok('a computer\'s own 4769, its keys N/A: not an account with no AES keys, nothing at all',
       isemon.ad25_findings(4769, real.split('| ', 1)[1]), [])
    ok('...an account that really has RC4 only still is',
       [x[0] for x in isemon.ad25_findings(4769, real.split('| ', 1)[1].replace(
           'Available Keys: AES-SHA1, RC4  Domain', 'Available Keys: RC4  Domain'))], ['noaes'])
    st.db.execute("INSERT INTO ad25_seen (day, issue, ckey, server, client, ip, account, detail, n, "
                  "t_first, t_last) VALUES (?, 'noaes', 'x', 'dc', '', '', 'pc$', 'its keys: N', 5, ?, ?)",
                  (int(isemon.time.time() // 86400), isemon.time.time(), isemon.time.time()))
    st.db.commit() if hasattr(st.db, 'commit') else None
    st.ad25_tidy()
    left = [r['account'] for r in st.db.execute("SELECT account FROM ad25_seen WHERE issue = 'noaes'")]
    ok('...what was counted off N/A before is let go of; the real ones kept',
       ('pc$' in left, 'svc-sql' in left), (False, True))
    v = st.ad25_view(24)
    ok('the page is told how many there are in all', (v['machines_n'], v['accounts_n']),
       (len(v['machines']), len(v['accounts'])))

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('a card out of these opens Before Windows Server 2025 at its kind',
       ("if (where.ad25 && typeof a25Go === 'function') {" in page,
        "a25Go(where.page === 'accounts' ? 'accounts' : 'machines', String(where.ad25));" in page),
       (True, True))
    ok('...and says when it was handed only those with the most',
       "found.textContent += ' \\u00b7 the ' + num(all) + ' with the most of ' + num(whole);" in page)
    src = (ROOT / 'isemon.py').read_text()
    ok('the daemon adds them only with the page on', 'if not ad25_on():\n            return' in src)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
