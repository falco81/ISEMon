#!/usr/bin/env python3
"""1.10.334: Before Windows Server 2025 hunted for bugs once more - the
sieve keeping what earns the new marks, the re-reading plan, \\\\PC names,
IPv6 addresses, the clean-up run once; on the page a window chosen while
loading, filters not carried over, the place kept on a refresh, rows opened
by a mark among others, the top card opening what it counted, stand-ins.

    ./test/fixes334_ad25_hunt.py
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


print('The daemon')
w = isemon.WIN_MARK_WORDS
ok('the sieve reads far enough to mark NTLMv1, LM and Digest even with sign-ins switched off',
   (bool(w.search('Package Name (NTLM only): NTLM V1')), bool(w.search('Package Name (NTLM only): LM  Key')),
    bool(w.search('Authentication Package: WDigest')), bool(w.search('Package Name (NTLM only): -  Key'))),
   (True, True, True, False))
a = isemon._ad25_addr
ok('IPv6 addresses whole; a port cut only after a bracket or IPv4; the zone dropped',
   [a('Client Address: fe80::2  X'), a('Client Address: 2001:db8::5'), a('Client Address: [fe80::1%12]:5000'),
    a('Client IP address: 10.6.0.80:44774  Identity'), a('Client Address: ::ffff:10.1.1.1:5000'),
    a('Client Address: -')],
   ['fe80::2', '2001:db8::5', 'fe80::1', '10.6.0.80', '10.1.1.1', ''])
ok('\\\\PC01 is PC01 (4776)', isemon.ad25_findings(
    4776, 'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: u Source '
          'Workstation: \\\\PC01 Error Code: 0x0')[0][1], 'PC01')
work = Path(tempfile.mkdtemp(prefix='isemon-334-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    st.win_marks_noted()
    was = st.meta_json('win_reading', None) or {}
    st.set_meta('win_reading', json.dumps(dict(was, version=5, names=['olddc'])))
    ok('a reading changed for some events AND machines named differently: everything, not the '
       'one ANDed with the other', st.win_marks_plan()[0], {'all': True})
    st.set_meta('win_reading', json.dumps(dict(was, names=['olddc'])))
    ok('...machines named differently alone: just theirs', st.win_marks_plan()[0], {'accounts': ['olddc']})
    st.db.execute("INSERT INTO ad25_seen (day, issue, ckey, server, client, ip, account, detail, n, t_first, "
                  "t_last) VALUES (1, 'ldap-clear', 'k', 'dc', '', '', 'Service', 'x', 1, 1, 1)")
    st.db.commit() if hasattr(st.db, 'commit') else None
    import time
    st.db.execute('UPDATE ad25_seen SET day = ?', (int(time.time() // 86400),))
    st.db.commit() if hasattr(st.db, 'commit') else None
    st.set_meta('ad25_cleaned', isemon.AD25_CLEANED)
    st.ad25_tidy()
    ok('the clean-up of earlier mistakes runs once: an account really called "Service" stays',
       st.rows_in('ad25_seen'), 1)
    isemon.AD25['sources'] = {'security': {'dc': 1.0}}
    isemon.ad25_take()
    ok('what the logs said is handed over once, not written again every pass',
       isemon.AD25['sources'], {})
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe page')
page = (ROOT / 'web' / 'index.php').read_text()
ok('a window chosen while an answer is on its way is asked again; an old answer is not drawn',
   ("if (A25.asking) { A25.again = A25.again || (quiet ? 'quiet' : 'loud'); return; }" in page,
    "if (String($('a25-window').value || 168) !== hours) return;" in page), (True, True))
ok('opened from a tile, the top card or an alarm: no search or controller carried over',
   "if (issue !== undefined) { A25.issue = issue; A25.q = ''; A25.dc = ''; A25.only = only || ''; }" in page)
ok('the minute\'s refresh keeps the place', ('box.scrollTop = at;' in page, 'if (!keep) a25Fit(box);' in page),
   (True, True))
ok('a marked kind opened by a mark among others, each in its bracket',
   ("marked.push('(event:4624 mark:*' + A25_MARK[k] + '*)');" in page,
    "var q = parts.length > 1 ? ['(' + parts.join(' OR ') + ')'] : parts;" in page), (True, True))
ok('the top card opens what it counted', "one.onclick = function () { a25Go(f[2], '', f[3]); };" in page)
ok('stand-ins for controllers, for computer accounts, and past 999',
   ("(d.controllers || []).map(M).join(', ')" in page, 'M(r.server), r.n' in page,
    "String(n).length < 3 ? ('00' + n).slice(-3) : String(n)" in page), (True, True, True))
cols = ['ident', 'ts', 'server', 'event', 'kind', 'account', 'machine', 'ip', 'said', 'domain', 'service',
        'object', 'by_who', 'process', 'mark']
g = isemon.ListQuery('win', '(event:2889,4776 OR (event:4624 mark:*ntlmv1*)) from:PC1,10.0.0.1 jnovak',
                     ident=lambda x: x, columns=cols)
ok('...and the events page reads that search', ('LIKE' in g.sql, g.words), (True, 'jnovak'))

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
