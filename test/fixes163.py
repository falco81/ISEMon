#!/usr/bin/env python3
"""1.10.163: `field:value` in every search box, with the values offered.

What a box with no field in it does is checked to be exactly what it was;
what each field finds is checked against the rows themselves, on whichever
engine this is run on.

    ./test/fixes163.py
"""
import json
import re
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
FOLDERS = []


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-163-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'f.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'watch_devices': '', 'feeds_ban': 0, 'geo': 0})
    return isemon.Storage(isemon.DB_FILE)


print('\nA box with no field in it is searched as it always was')
for text in ('novak', '98:fc:84:e0:29:d6', '2001:db8::1', '07:30', 'EXAMPLE\\novak',
             'a:b c', 'the password was wrong', 'OR', '"quoted words"', 'x:y:z', ''):
    got = isemon.ListQuery('failed', text)
    ok('%r is words alone' % text, (got.sql, got.words), ('', text.strip()))

print('\nWhat the fields become')


def piece(listname, text):
    got = isemon.ListQuery(listname, text)
    return got.sql, got.args, got.words


ok('a name', piece('failed', 'user:Novak'), ('LOWER(username) = ?', ['novak'], ''))
ok('...beside words: the first to the word search, the next beside it',
   [piece('failed', 'user:novak vpn group')[i] for i in (2, 1)],
   ['vpn', ['novak'] + ['%group%'] * 5])
ok('a field still being typed is nothing yet', piece('failed', 'user:')[:2], ('', []))
ok('a range of addresses on whole octets', piece('failed', 'ip:10.1.0.0/16')[1], ['10.1.%'])
ok('...and between them, as the octets it covers',
   len(piece('failed', 'ip:10.0.0.0/12')[1]), 16)
ok('...and inside the last one, as the addresses',
   piece('failed', 'ip:10.1.2.0/30')[1], ['10.1.2.0', '10.1.2.1', '10.1.2.2', '10.1.2.3'])
ok('a MAC written any way is the MAC as it is kept',
   [piece('failed', 'mac:' + m)[1] for m in ('98fc.84e0.29d6', '98:FC:84:E0:29:D6')],
   [['98-FC-84-E0-29-D6']] * 2)
ok('a Windows event number, a list and a range',
   piece('win', 'event:4625,4740-4741')[:2],
   ('(event = ? OR event BETWEEN ? AND ?)', [4625, 4740, 4741]))
ok('a number asked with ~, or with :> as well as >',
   [piece('history', q)[:2] for q in ('hits~5', 'hits:>10', 'hits>10')],
   [('hits = ?', [5]), ('hits > ?', [10]), ('hits > ?', [10])])
for bad in ('user:a OR', '(user:a', 'user:a)', 'hits:many', 'ip:0.0.0.0/0',
            'event:99999999999999999999', 'event:1-99999999999999999999'):
    try:
        isemon.ListQuery('history' if 'hits' in bad else ('win' if 'event' in bad
                                                           else 'failed'), bad)
        ok('%r is refused, and says why' % bad, False, True)
    except isemon.ListQueryError as e:
        ok('%r is refused, and says why' % bad, bool(str(e)), True)
try:
    isemon.ListQuery('failed', 'profile:x', columns=('ip', 'username'))
    ok('a field the table does not hold is said to be one', False, True)
except isemon.ListQueryError:
    ok('a field the table does not hold is said to be one', True, True)

print('\nWhat they find')
store = fresh()
NOW = time.time()
people = [('novak', '10.1.2.3', 'the password was wrong', 'CZ', '98-FC-84-E0-29-D6'),
          ('mkral', '10.1.9.9', 'no such account', 'DE', ''),
          ('admin', '203.0.113.5', 'no such account', 'CN', ''),
          ('Novak', '10.2.0.1', 'the account is locked', 'CZ', ''),
          ('pdvorak', '198.51.100.7', 'the password was wrong', '', '')]
for i, (user, ip, why, cc, mac) in enumerate(people):
    for k in range(i + 1):
        store.add_failed({'session': 's%d-%d' % (i, k), 'ts': NOW - 60 * (i * 10 + k),
                          'ip': ip, 'username': user, 'reason': why, 'country': cc,
                          'mac': mac, 'device': 'FTD-VPN', 'server': 'ise1', 'kind': 'vpn',
                          'detail': '{}'})


def found(text, listname='failed'):
    q = isemon.ListQuery(listname, text, ident=store.dialect.ident,
                         columns=store.columns_of(isemon.LIST_TABLES[listname]))
    rows, _total = store.failed_rows(limit=500, text=q.words,
                                     where=(q.sql, q.args) if q.sql else None)
    return sorted({(r['username'], r['ip']) for r in rows})


ok('a name, whatever its case', found('user:NOVAK'),
   [('Novak', '10.2.0.1'), ('novak', '10.1.2.3')])
ok('any of two names', [u for u, _ in found('user:mkral,admin')], ['admin', 'mkral'])
ok('everybody but one', 'mkral' in [u for u, _ in found('-user:mkral')], False)
ok('...and != says the same', found('user!=mkral'), found('-user:mkral'))
ok('a range', found('ip:10.1.0.0/16'), [('mkral', '10.1.9.9'), ('novak', '10.1.2.3')])
ok('a wider one', [u for u, _ in found('ip:10.0.0.0/12')], ['Novak', 'mkral', 'novak'])
ok('a wildcard', found('ip:10.2.*'), [('Novak', '10.2.0.1')])
ok('inside a reason', [u for u, _ in found('reason:*password*')], ['novak', 'pdvorak'])
ok('~ is "has it inside"', found('reason~password'), found('reason:*password*'))
ok('a country', [u for u, _ in found('country:cz')], ['Novak', 'novak'])
ok('a MAC, written as a switch writes it', found('mac:98fc.84e0.29d6'),
   [('novak', '10.1.2.3')])
ok('...or the start of one', found('mac:98fc*'), [('novak', '10.1.2.3')])
ok('either of two things, in brackets', [u for u, _ in found('(country:de OR country:cn)')],
   ['admin', 'mkral'])
ok('a field and a word together', found('country:cz locked'), [('Novak', '10.2.0.1')])
ok('a word turned round', [u for u, _ in found('country:cz -locked')], ['novak'])
ok('two words either side of a field are two words, not one phrase',
   found('password ip:10.1.* wrong'), [('novak', '10.1.2.3')])
ok('NOT and - leave the same rows', found('NOT country:cz'), found('-country:cz'))
ok('NOT inside NOT is said once, not doubled each time',
   len(isemon.ListQuery('failed', '! ' * 30 + 'ip:1.2.3.4').args), 1)
ok('...and NOT NOT is the thing itself', found('NOT NOT country:cz'), found('country:cz'))
ok('a row with nothing in a field is "not" anything',
   'pdvorak' in [u for u, _ in found('-country:cz')], True)

print('\nThe values a field holds, most first')
got = store.list_values('failed', 'username', 'text', '', NOW - 86400)
ok('busiest first', [v['val'] for v in got][:2], ['pdvorak', 'Novak'])
ok('...with how many', got[0]['n'], 5)
got = store.list_values('failed', 'reason', 'text', 'pass', NOW - 86400)
ok('...narrowed to what is typed', [v['val'] for v in got], ['the password was wrong'])
ok('...a number narrowed as typed, on any engine',
   store.list_values('history', 'hits', 'num', '5', 0), [])
ok('...and never a field the table does not have',
   store.list_values('failed', 'nonsense', 'text', '', 0), [])

print('\nThe other lists')
store.add_event('settings', 'block_tries changed', who='admin')
store.add_event('block', 'banned 203.0.113.5', who='')
q = isemon.ListQuery('events', 'kind:settings who:admin', ident=store.dialect.ident)
rows, _ = store.events(50, where=(q.sql, q.args))
ok('the daemon\'s own events, by kind and by who', [r['kind'] for r in rows], ['settings'])
ok('...and their kinds offered', [v['val'] for v in store.list_values(
    'events', 'kind', 'text', 'set', 0)], ['settings'])
win = []
for i, (event, kind, account) in enumerate(((4625, 'logon-failed', 'jnovak'),
                                            (4740, 'lockout', 'jnovak'),
                                            (4624, 'logon', 'mkral'))):
    f = {'ts': NOW - i, 'server': 'DC1', 'event': event, 'kind': kind, 'account': account,
         'is_machine': False, 'domain': 'EXAMPLE', 'by': '', 'machine': 'PC1',
         'ip': '10.1.2.3', 'logon_type': '3', 'process': '', 'service': '', 'object': '',
         'said': '', 'mark': '', 'by_logon': '', 'fields': {}, 'raw': 'r%d' % i}
    f['ident'] = isemon.win_ident(f)
    win.append(f)
store.note_win_events(win)
q = isemon.ListQuery('win', 'event:4625,4740 account:jnovak', ident=store.dialect.ident)
rows, _ = store.win_rows(limit=50, where=(q.sql, q.args))
ok('the domain\'s events, by number and account', sorted(int(r['event']) for r in rows),
   [4625, 4740])
ok('...and the accounts offered', [v['val'] for v in store.list_values(
    'win', 'account', 'text', 'jn', 0)], ['jnovak'])
ok('...and the numbers, narrowed as typed', [v['val'] for v in store.list_values(
    'win', 'event', 'num', '474', 0)], ['4740'])
q = isemon.ListQuery('win', 'event~4625', ident=store.dialect.ident)
ok('...and ~ on a number is the number', len(store.win_rows(limit=50, where=(q.sql, q.args))[0]),
   1)

print('\nThe page asks for the same fields the daemon reads')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
qf = page[page.index('var QF = {'):page.index('};', page.index('var QF = {'))]
for listname in ('failed', 'passed', 'win', 'events', 'history'):
    block = qf[qf.index(listname + ': ['):]
    block = block[:block.index(']\n  ]') if ']\n  ]' in block else len(block)]
    names = re.findall(r"\['([a-z_]+)',", block)
    ok('%s: every field the page offers is one the daemon knows' % listname,
       [n for n in names if n not in isemon.LIST_FIELDS[listname]], [])
ok('the daemon is asked through the page\'s own door', "'suggest'   => '/api/suggest'" in page)

node = shutil.which('node')


def js_function(name):
    at = page.index('\nfunction %s(' % name) + 1
    return page[at:page.index('\n}', at) + 2]


if node:
    script = 'var I18N = {on: false};\nvar Q_UNTRANSLATED = null;\n' + '\n'.join(
        js_function(n) for n in ('qTokens', 'qLocalParse', 'qLocalMatch', 'qUntranslate',
                                 'qLocalTest')) + r'''
var rows = [{ip: '10.1.2.3', why: 'INVALID name', country: 'CZ'},
            {ip: '45.9.148.9', why: 'too many', country: 'RU'},
            {ip: '45.9.148.10', why: 'too many', country: 'CN'}];
var known = {ip: true, why: true, country: true, 'how-it-ended': true};
function pick(q) {
  var p = qLocalParse(q, known);
  if (!p) return null;
  return rows.filter(function (r) {
    return qLocalTest(p, function (f) { return r[f]; },
                      function () { return JSON.stringify(r).toLowerCase(); });
  }).map(function (r) { return r.ip; });
}
console.log(JSON.stringify({
  none: pick('45.9'), one: pick('ip:45.9.*'), two: pick('country:ru,cn'),
  not: pick('-country:ru'), word: pick('why:many 148.10'), glob: pick('why:*INVALID*'),
  mac: pick('98:fc:84:e0:29:d6'),
  either: pick('country:cz OR country:cn'),
  heading: pick('how-it-ended:x')
}));
'''
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('a list in the page: no field is the old search', got['none'], None)
    ok('...a field with a wildcard', got['one'], ['45.9.148.9', '45.9.148.10'])
    ok('...any of two', got['two'], ['45.9.148.9', '45.9.148.10'])
    ok('...turned round', got['not'], ['10.1.2.3', '45.9.148.10'])
    ok('...a field and a word', got['word'], ['45.9.148.10'])
    ok('...a whole value with wildcards', got['glob'], ['10.1.2.3'])
    ok('...a MAC is words', got['mac'], None)
    ok('...either side of OR', got['either'], ['10.1.2.3', '45.9.148.10'])
    ok('...a field named by a heading of several words', got['heading'], [])
else:
    print('  (no node here: the page\'s own functions are not run)')

for folder in FOLDERS:
    shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
