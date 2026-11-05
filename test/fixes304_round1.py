#!/usr/bin/env python3
"""1.10.304: what the first round of looking for bugs found, fixed.

    ./test/fixes304_round1.py
"""
import json
import os
import shutil
import subprocess
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


src = (ROOT / 'isemon.py').read_text()
work = Path(tempfile.mkdtemp(prefix='isemon-304-'))
try:
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)

    print('Going back over the logs')
    log = work / 'otp.log'
    with open(log, 'w') as f:
        junk = 'Nov  5 10:00:00 otp sshd[1]: something else entirely, nothing to read here\n'
        f.write(junk * (9 * 1024 * 1024 // len(junk)))
        f.write('Nov  5 10:00:01 otp totp.cgi[7]: Failure: user=jnovak, mode=x, host=203.0.113.5, '
                'rid=1, what=wrong code\n')
    tail = isemon.LogTail(log, parser=daemon.parser_for('otp', str(log)))
    got = []
    while True:
        recs = isemon.Daemon.read_whole(tail)
        if not recs:
            break
        got += recs
    ok('a first 8 MB with nothing in it for us is not the end of the file',
       (tail.offset, os.path.getsize(log)), (os.path.getsize(log),) * 2)

    print('\nThe ladder')
    store.block('203.0.113.7', None, 'by hand', auto=False, by='test')
    ok('a ban made as one that keeps somebody out is written down already',
       store.ban_marked('203.0.113.7'), True)
    ok('...one with no mark at all is not', store.ban_marked('203.0.113.99'), False)

    print('\nThe hour the lists are fetched in')
    isemon.CONFIG.update({'update_when': 'at_time', 'update_at': '23:50'})
    real = time.localtime
    for hm, want in (((23, 55), True), ((0, 30), True), ((0, 55), False), ((22, 0), False)):
        time.localtime = lambda *a, hm=hm: time.struct_time((2026, 11, 5, hm[0], hm[1], 0, 3,
                                                             309, -1))
        ok('23:50 for an hour: %02d:%02d %s' % (hm + ('in' if want else 'out',)),
           isemon.Daemon.update_window_open(3600), want)
    time.localtime = real
    isemon.CONFIG.update({'update_when': isemon.DEFAULTS['update_when']})
    ok('a range written backwards is no range', isemon.range_of('1.2.3.255-1.2.3.0'), None)
    ok('...forwards it is', bool(isemon.range_of('1.2.3.0-1.2.3.255')))

    print('\nThe firewalls')
    ok('a list that came back is not a refusal, whatever its comments say',
       "if 'address=' in (out or '') or not re.search(refused, out or ''):" in src)
    ok('a failed sync on a change is tried again by itself',
       "if (how != 'every' and getattr(self, '_mikrotik_retry', False)" in src)
    store.block('198.51.100.9', None, 'for good', auto=False, by='test')
    acl = daemon.ios_acl()['text'].split('\n')
    first_deny = next(i for i, l in enumerate(acl) if ' deny   ip ' in l)
    last_permit = max(i for i, l in enumerate(acl) if 'permit ip any any' in l)
    ok('the Cisco list: its ending put in before the first deny, numbered after it',
       (last_permit < first_deny, acl[last_permit].startswith(' 20000000'),
        acl[first_deny].startswith(' 10 deny')), (True, True, True))

    print('\nCarried and put back')
    store.put_passkeys([{'id': 'a', 'user': 'boss', 'name': 'iPad', 'pem': 'x', 'alg': -7}])
    out = daemon.export_config(secrets_too=True)
    ok('a complete export carries the passkeys', 'passkeys' in out.get('keys', {}))
    ok('...and so does a backup of the settings', 'passkeys' in isemon.RB_CONF_META)
    ok('the tables an older dump cannot hold are emptied after it',
       isemon.Storage.DUMP_MAY_LACK, ('acme_events', 'acme_jobs', 'load_samples'))
    isemon.CONFIG['downgrade_offered'] = 1
    isemon.CONFIG['passkeys'] = 1
    why = daemon.upgrades.back_refused('1.10.300') if hasattr(daemon, 'upgrades') else \
        isemon.Upgrades(daemon).back_refused('1.10.300')
    ok('going back past Face ID while it is on: refused, and said why', 'Face ID' in why)
    isemon.CONFIG['passkeys'] = 0

    print('\nThe API')
    isemon.CONFIG['fwlog_sources'] = [{'name': 'fw1', 'api': {'user': 'x',
                                                               'password': isemon.seal_secret('Sup3rS3cret!!')}}]
    plain = daemon.export_config(secrets_too=False)
    ok('the export without the secrets carries no API password of a firewall',
       'Sup3rS3cret' in json.dumps(plain) or 'sealed:' in json.dumps(plain), False)
    isemon.CONFIG['fwlog_sources'] = isemon.DEFAULTS['fwlog_sources']
    ok('settings that are not an object: said, not a 500',
       "return self.fail('settings are an object of names and values')" in src)
    ok('a password changed keeps the age of the sign-in',
       "(float(me.get('made') or time.time()),) + store.session_pair(token)" in src)
    ok('one\'s own passkey taken away only just after Face ID',
       "'away', 428)" in src)

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the find box over a popup keeps its own Tab',
       "if ($('findback') && !$('findback').hidden) return;" in page)
    ok('a refresh draws the answer to its own question only',
       'if (lane.last && lane.lastWhat === plain) return Promise.resolve(lane.last);' in page)
    ok('the polls of root\'s work ask one at a time',
       ('if (SK.asking) return;' in page, 'if (OT.asking) return;' in page,
        'if (AT.asking) return;' in page), (True, True, True))
    node = shutil.which('node')
    if node:
        js = r'''
const src = require('fs').readFileSync(process.argv[1], 'utf8');
function grab(n) { const a = src.indexOf('function ' + n + '('); let d = 0;
  for (let j = src.indexOf('{', a); j < src.length; j++) { if (src[j] === '{') d++;
    else if (src[j] === '}') { d--; if (!d) return src.slice(a, j + 1); } } }
global.shownNumber = x => parseFloat(x); global.qUntranslate = () => [];
eval(['qTokens', 'qLocalParse', 'qAddressMatch', 'qLocalMatch', 'qLocalTest'].map(grab).join('\n')
     + ';global.P=qLocalParse;global.T=qLocalTest;');
const rows = [{ip: '203.0.113.1', c: 'CN'}, {ip: '203.0.113.2', c: 'RU'}, {ip: '203.0.113.3', c: 'US'},
              {ip: '203.0.113.10', c: 'CN'}, {ip: '10.1.2.3', c: 'DE'}];
const run = q => { const p = P(q, {ip: 1, c: 1});
  return rows.filter(r => T(p, f => r[f], () => JSON.stringify(r).toLowerCase())).map(r => r.ip).join(' '); };
console.log(JSON.stringify(['c:CN (ip:203.0.113.2 OR ip:203.0.113.3)', 'NOT c:CN', 'ip:203.0.113.1',
  'ip:10.0.0.0/8', 'c:CN OR NOT c:RU'].map(run)));
'''
        out = subprocess.run([node, '-e', js, str(ROOT / 'web' / 'index.php')],
                             capture_output=True, text=True).stdout.strip()
        ok('a list held in the page reads a search as the daemon does: brackets, NOT, an '
           'address whole, a range', json.loads(out or '[]'),
           ['', '203.0.113.2 203.0.113.3 10.1.2.3', '203.0.113.1', '10.1.2.3',
            '203.0.113.1 203.0.113.3 203.0.113.10 10.1.2.3'])
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
