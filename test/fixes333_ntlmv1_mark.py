#!/usr/bin/env python3
"""1.10.333: an NTLMv1 (or LM) sign-in and a Digest one carry a mark, so that
a row of Before Windows Server 2025 opens exactly those - not every sign-in
of the machine; the ones stored before are marked by reading again only the
sign-ins of the accounts that page saw doing it.

    ./test/fixes333_ntlmv1_mark.py
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


STAMP = time.strftime('%b %e %H:%M:%S', time.localtime(time.time() - 120))
L = ('%s dc1 WinSecurity: EventID=4624 | An account was successfully logged on.  Subject:  Security '
     'ID:  S-1-0-0  Account Name:  -  Logon Information:  Logon Type:  3  New Logon:  Security ID:  '
     'S-1-5-21-1-9  Account Name:  %s  Account Domain:  CORP  Network Information:  Workstation Name: '
     'PC7  Source Network Address: 10.0.0.7  Source Port:  5000  Detailed Authentication Information:  '
     'Logon Process:  NtLmSsp  Authentication Package: %s  Transited Services: -  Package Name (NTLM '
     'only): %s  Key Length:  0')

print('The marks')
mark = lambda who, pkg, ver: isemon.win_record_from(L % (STAMP, who, pkg, ver)).facts['mark']
ok('NTLM V1: marked', mark('jnovak', 'NTLM', 'NTLM V1'), 'ntlmv1')
ok('...LM too', mark('jnovak', 'NTLM', 'LM'), 'ntlmv1')
ok('...NTLM V2 not', mark('jnovak', 'NTLM', 'NTLM V2'), '')
ok('...a null session written as NTLM V1 is anonymous, not NTLMv1',
   mark('ANONYMOUS LOGON', 'NTLM', 'NTLM V1'), 'anonymous')
ok('Digest: marked', mark('printsrv', 'WDigest', '-'), 'digest')
ok('...each a bit of its own', (isemon.WIN_MARK_BITS['ntlmv1'], isemon.WIN_MARK_BITS['digest']),
   (4096, 8192))

work = Path(tempfile.mkdtemp(prefix='isemon-333-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    isemon.CONFIG.update(winsec=1, winsec_ad2025=1, winsec_keep_logons=1)
    lines = [L % (STAMP, 'jnovak', 'NTLM', 'NTLM V1'), L % (STAMP, 'other', 'NTLM', 'NTLM V2')]
    st.note_win_events([r.facts for r in isemon.win_parse_lines(lines, {})])
    isemon.win_parse_lines(lines, {})
    st.ad25_flush()
    st.win_marks_noted()

    print('\nRead again: only the sign-ins of the accounts seen doing it')
    st.db.execute("UPDATE win_events SET mark = '', marks = 0 WHERE event = 4624")
    st.db.commit() if hasattr(st.db, 'commit') else None
    was = st.meta_json('win_reading', None) or {}
    st.set_meta('win_reading', json.dumps(dict(was, version=6)))
    plan, _why = st.win_marks_plan()
    ok('the plan: 4624, of the accounts Before Windows Server 2025 saw', plan,
       {'events': [4624], 'accounts': ['jnovak']})
    st.fill_in_win_marks()
    got = sorted((r['account'], r['mark']) for r in st.db.execute(
        'SELECT account, mark FROM win_events WHERE event = 4624'))
    ok('...the NTLMv1 sign-in marked again, the other left as it was', got,
       [('jnovak', 'ntlmv1'), ('other', '')])
    st.db.execute('DELETE FROM ad25_seen')
    st.db.commit() if hasattr(st.db, 'commit') else None
    st.set_meta('win_reading', json.dumps(dict(was, version=6)))
    ok('a site without that page (nobody seen): nothing to read again', st.win_marks_plan()[0], {})
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('a row of one such kind opens by its mark',
   "marked.push('(event:4624 mark:*' + A25_MARK[k] + '*)');" in page)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
