#!/usr/bin/env python3
"""1.10.167: a token attempt is searched by the packet the page shows beside
it - also where every packet carries the same id; tac_plus's Service; and a
value typed as a column shows it is put back in English too.

    ./test/fixes167.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
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


folder = tempfile.mkdtemp(prefix='isemon-167-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0})
store = isemon.Storage(isemon.DB_FILE)
NOW = time.time() - 3600
RID = '172.22.0.137:1812'          # the head end, on every packet alike
people = (('alfa', '198.51.100.70'), ('beta', '198.51.100.71'), ('gama', '198.51.100.72'))
for n, (user, addr) in enumerate(people):
    for k in range(3):
        at = NOW - n * 600 - k * 3000
        store.add_passed({'session': 'otp-%s-%d' % (user, k), 'ts': at, 'kind': 'otp',
                          'ip': '127.0.0.1', 'username': user, 'tkey': user + '@example.cz',
                          'subtype': 'Valid token used', 'server': 'otp2', 'asked_as': RID})
        with store.db_write() as db:
            db.execute('INSERT INTO otp_asked (ident, ts, at, server, kind, username, ip, nas, '
                       'tunnel, verdict, device, rid) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                       ('pk-%s-%d' % (user, k), at + 1, at + 1, 'otp2', 'ask',
                        user + '@example.cz', addr, '172.22.0.137', 'STAFF', 'accept',
                        'NB-' + user, RID))
store.add_passed({'session': 'tp-1', 'ts': NOW, 'kind': 'tacplus', 'ip': '10.6.6.1',
                  'username': 'op1', 'tkey': 'op1|r1|tty1', 'device': 'r1',
                  'profile': 'priv-lvl 15', 'policy': 'shell', 'server': 'tacd'})
store.add_passed({'session': 'tp-2', 'ts': NOW, 'kind': 'tacplus', 'ip': '10.6.6.2',
                  'username': 'op2', 'tkey': 'op2|r1|tty2', 'device': 'r1',
                  'profile': 'priv-lvl 1', 'policy': 'exec', 'server': 'tacd'})


def found(table, door, q):
    lq = isemon.ListQuery(table, q, ident=store.dialect.ident, columns=store.columns_of(table),
                          door=door, concat=store.dialect.concat,
                          word_columns=store.auth_word_columns(table, door),
                          asked_sessions=store.otp_asked_sessions,
                          acl_names=store.acl_names)
    rows, _total = store.passed_rows(limit=200, since=0, text=lq.words,
                                     where=(lq.sql, lq.args) if lq.sql else None, kind=door)
    return sorted(r['session'] for r in rows)


print('\nOTP: every packet carries the head end\'s id, and each attempt is still its own')
shown = store.otp_asked_near([(r['session'], r['server'], r['username'], r['ts'], True,
                               r['tkey'], r['asked_as'])
                              for r in store.passed_rows(limit=200, since=0, kind='otp')[0]])
ok('the page puts each person\'s own address beside each attempt',
   sorted({(k.split('-')[1], v['ip']) for k, v in shown.items()}),
   sorted((u, a) for u, a in people))
for user, addr in people:
    ok('from:%s is %s\'s three attempts and nobody else\'s' % (addr, user),
       found('passed', 'otp', 'from:%s' % addr),
       sorted('otp-%s-%d' % (user, k) for k in range(3)))
ok('machine:NB-beta', found('passed', 'otp', 'machine:NB-beta'),
   ['otp-beta-0', 'otp-beta-1', 'otp-beta-2'])
ok('a word is the same: 198.51.100.71', found('passed', 'otp', '198.51.100.71'),
   ['otp-beta-0', 'otp-beta-1', 'otp-beta-2'])
ok('-from: is everybody else', found('passed', 'otp', '-from:198.51.100.70'),
   sorted('otp-%s-%d' % (u, k) for u in ('beta', 'gama') for k in range(3)))

print('\ntac_plus: Service is the column headed so')
ok('service:shell', found('passed', 'tacplus', 'service:shell'), ['tp-1'])
ok('privilege:"priv-lvl 1"', found('passed', 'tacplus', 'privilege:"priv-lvl 1"'), ['tp-2'])

print('\nThe page, in English: the words are put back')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
node = shutil.which('node')
if node:
    block = page[page.index('function qShown(words)'):page.index('/** What each list')]
    tok = page[page.index('function qTokens(text)'):]
    tok = tok[:tok.index('\n}\n') + 3]
    script = ('var I18N = {on: false, exact: null};\n'
              'function i18nText() { throw new Error("no translation loaded"); }\n'
              + block + tok + '''
var TOKEN_WORDS = {'valid token used': ['the token was right', 'ok']};
console.log(JSON.stringify(qRewrite('how:"the token was right"', {how: qBackBy(TOKEN_WORDS)})));''')
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('with no translation loaded, as the page is in English', got, 'how:"valid token used"')
else:
    print('  (no node here)')

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
