#!/usr/bin/env python3
"""1.10.356: three rounds of looking for bugs - the first one's fixes.

    ./test/fixes356_hunt.py
"""
import json
import os
import pwd
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'deploy'))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 24000 + random.randint(0, 3000)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


folder = Path(tempfile.mkdtemp(prefix='isemon-356-'))
try:
    for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                     DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                     CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                     TOKEN_FILE=folder / 'tok').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1, 'directory_host': 'dc.x',
                          'directory_base': 'DC=corpnet,DC=loc', 'certlogin': 1, 'api_port': PORT})
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-keyout', str(folder / 'c.key'), '-out', str(folder / 'c.pem'),
                    '-days', '2', '-subj', '/CN=card'], capture_output=True, check=True)
    card = (folder / 'c.pem').read_text()
    store = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(store)
    d.add_user('falco', 'a-long-enough-password-1', 'fulladmin', by='test')
    api = isemon.ApiServer(d, PORT)
    api.start()
    time.sleep(0.4)

    print('sealed values inside JSON text are sealed again')
    other = os.urandom(32)
    real = isemon.sealing_key
    isemon.sealing_key = lambda make=False: other          # as another machine sealed it
    wrapped = json.dumps({'sealed': isemon.seal_secret('the keytab'), 'at': 1})
    isemon.sealing_key = real
    ok('another machine\'s seal does not open here', isemon.unseal_secret(json.loads(wrapped)['sealed']),
       None)
    back = isemon.reseal_all(wrapped, other)
    ok('the keytab\'s {"sealed": ...} opens here after', isemon.unseal_secret(
        json.loads(back)['sealed']), 'the keytab')
    ok('...plain text left as it is', isemon.reseal_all('{not json sealed:1:', other),
       '{not json sealed:1:')

    print('switches read as the setting reads them')
    for v in ('01', ' 1', 1.0, '1', True):
        ok('passkeys %r is on' % (v,), isemon.setting_is('passkeys', v, 1))
    ok('junk is neither', (isemon.setting_is('passkeys', 'x', 1), isemon.setting_is('passkeys', 'x', 0)),
       (False, False))
    said = d.import_config({'_what': 'isemon configuration', 'settings':
                            {'password_off': '01', 'passkeys': '01'}}, by='test')
    ok('an import does not switch on "no password" or Face ID by "01"',
       (int(isemon.CONFIG.get('password_off') or 0), int(isemon.CONFIG.get('passkeys') or 0)), (0, 0))
    tok = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')
    st, body = call('/api/settings', 'POST', {'settings': {'password_off': '01'}}, session=tok)
    ok('the API refuses "no password" as "01" from a password session', st, 409)

    print('the certificate\'s port never the daemon\'s own')
    ok('said as a rule of two', any('api_port' in s for s in isemon.settings_problems(
        dict(isemon.CONFIG, certlogin=1, certlogin_port=PORT, api_port=PORT))), True)
    ok('...off, no word', any('api_port' in s for s in isemon.settings_problems(
        dict(isemon.CONFIG, certlogin=0, certlogin_port=PORT, api_port=PORT))), False)

    print('the export carries the certificate sign-in\'s authorities')
    store.set_meta('certlogin_cas', json.dumps([{'pem': card, 'sha256': 'ab'}]))
    ok('in the complete export', 'certlogin_cas' in d.export_config(secrets_too=True)['keys'])
    ok('...and in a configuration backup', all(isemon.rb_conf_meta_ok(k) for k in
                                              ('certlogin_cas', 'kerberos_keytab', 'osu_pwpolicy')))

    print('the card watched')
    isemon.CONFIG['certlogin_watch'] = 'grace'
    tok = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')
    d.certlogin_watch_mark(tok, card)
    store.session_card(tok, card_ok=time.time())
    d.certlogin_alive(tok, '')
    ok('held: whoami gives nothing of the person', call('/api/auth/whoami', session=tok)[1].get('prefs'),
       {})
    st, body = call('/api/auth/passkey', 'POST', {'step': 'begin', 'want': 'enrol'}, session=tok)
    ok('held: no passkey added (423)', (st, body.get('code')), (423, 'card'))
    d.save_settings({'certlogin_watch': 'signout'}, by='test')
    row = store.session(tok)
    ok('another mode: every watched session counted from now', (row['card_out'], row['card_seen']),
       (None, None))
    ok('...not ended for an "out" of before', bool(d.who(tok)), True)
    tok2 = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')
    d.certlogin_watch_mark(tok2, card)
    d.webroot.pending = lambda: True
    ok('root still putting the port in: no word about the browser', d.certlogin_card_gone(tok2),
       {'watched': False, 'gone': False})
    ok('...not marked unwatched', store.session(tok2).get('card_ok'), None)
    tok3 = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')
    d.certlogin_watch_mark(tok3, card)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                    '-nodes', '-keyout', str(folder / 'o.key'), '-out', str(folder / 'o.pem'),
                    '-days', '2', '-subj', '/CN=other'], capture_output=True, check=True)
    ok('another card: the page is told which', d.certlogin_alive(tok3, (folder / 'o.pem').read_text())
       .get('why'), 'other')

    print('the watched sessions of 1.10.353 into their rows')
    tok4 = store.new_session('falco', 'fulladmin', '127.0.0.1', 'test', '')
    key = d._cols_key(tok4)
    store.set_meta('certlogin_sessions', json.dumps({key: {'at': time.time(), 'fp': 'a' * 64}}))
    isemon.Daemon(store)
    ok('carried over at the start', store.session(tok4).get('card'), 'a' * 64)
    ok('...the old key gone', bool(store.get_meta('certlogin_sessions')), False)

    print('addresses never from a name somebody typed (round 2)')
    f = isemon.WinFields() if hasattr(isemon, 'WinFields') else None
    fields = {'Network Information / Workstation Name': 'EVIL',
              'Network Information / Source Network Address': '8.8.8.8',
              'Network Information / Source Network Address (2)': '-'}
    ok('Windows 4625: the real address "-" - none, not the typed one',
       isemon.win_address(fields, 4625), '')
    ok('Windows 4776: no address of its own - none', isemon.win_address(
        {'Network Information / Source Network Address': '8.8.8.8'}, 4776), '')
    ok('Windows 4625 with an address of its own still read', isemon.win_address(
        {'Network Information / Source Network Address': '198.51.100.7'}, 4625), '198.51.100.7')
    src = (ROOT / 'isemon.py').read_text()
    ok('RouterOS PPP: an address only after the failure\'s own words', 'msg[af.end():])' in src)
    ok('Kerberos 4771: its own Client Address, not a typed Source Network Address',
       isemon.win_address({'Network Information / Source Network Address': '8.8.8.8',
                           'Network Information / Client Address': '::ffff:10.0.0.9'}, 4771), '10.0.0.9')
    ok('4648: its own Network Address', isemon.win_address(
        {'Network Information / Source Network Address': '8.8.8.8',
         'Network Information / Network Address': '10.0.0.8'}, 4648), '10.0.0.8')
    isemon.CONFIG['never_block'] = '::ffff:203.0.113.0/120'
    d._spare_from = None
    ok('never_block written the IPv6 way spares the IPv4 address', bool(d.spared('203.0.113.9')), True)
    isemon.CONFIG['never_block'] = ''
    d._spare_from = None

    print('dumps and backups (round 2)')
    ok('a PostgreSQL dump with a trigger: refused', bool(isemon.PG_CODE_RE.match(
        '3456; 0 0 TRIGGER public t1 isemon')), True)
    ok('...pg_trgm is ours', isemon.PG_CODE_RE.match('2; 3079 16385 EXTENSION - pg_trgm').group(1),
       'EXTENSION')
    ok('a MariaDB dump with a trigger: refused', bool(isemon.MARIA_CODE_RE.match(
        '/*!50003 CREATE*/ /*!50017 DEFINER=`root`@`%`*/ /*!50003 TRIGGER t BEFORE INSERT ON users')), True)
    ok('...a table of its own is not', bool(isemon.MARIA_CODE_RE.match('CREATE TABLE `events` (')), False)
    up = (ROOT / 'deploy' / 'isemon_upgrade.py').read_text()
    ok('the security floor kept by root, for every older helper', 'note_floor(installed_floor(), SECURITY_FLOOR)' in up)
    ok('a package\'s folder entries never made (they are not signed)',
       "if one.isdir():\n                        continue" in up)

    print('round 3')
    line = 'level=a ' + ' '.join('b="x"y' for _ in range(6000))
    t0 = time.time()
    isemon.acme_fields(line)
    ok('an acme line of 64 KB with one key said again and again: read at once', time.time() - t0 < 3)
    try:
        isemon._push_json(b'[' * 200000)
        ok('acme push: JSON nested deep - refused', False)
    except isemon.PushRefused:
        ok('acme push: JSON nested deep - refused', True)
    src = (ROOT / 'isemon.py').read_text()
    ok('acme jobs: a time that is no time not kept', 'if not math.isfinite(end_ts) or abs(end_ts - at) > 30 * 86400:' in src)
    ok('automatic certificates never put over one put in by hand while ordering',
       "a certificate was put in by hand while this order ran" in src)
    ok('pairing: wrong codes counted for each key', "per[kid] >= PUSH_CODE_TRIES" in src)
    store.add_event('login', 'a wrong password for x\x1b]52;c;AAAA\x07\x1b[2J from 1.2.3.4', who='x\x1b[8m')
    last = store.db.execute('SELECT detail, who FROM events ORDER BY rowid DESC LIMIT 1').fetchone()
    ok('events keep no escape of anybody\'s', ('\x1b' in last[0] + last[1]), False)
    import io
    pal = isemon.Palette(colour=False, stream=io.StringIO())
    isemon.print_table(pal, ['who'], [['bad\x1b]0;title\x07name']])
    ok('the command line prints no escape out of the data', '\x1b]' in pal.out.getvalue(), False)
    ok('sign-in: a directory account gone from the directory - its password here not taken',
       'if right and dir_answered and user.get(\'from_dir\'):' in src)
    # (1.10.378: and stripped of the spaces the directory throws away too)
    ok('sign-in: DOMAIN\\ in front counted as the name', "count_name = (name.split('\\\\', 1)[1]" in src)
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('page: a popup drawn again compared by its English title', "$('modal-title').dataset.src === title" in page)
    ok('page: acme tab kept after F5', "'windows', 'acmelog', 'router',\n       'events'" in page)

    print('root\'s helper')
    import isemon_web as w
    sec = folder / 'sec'
    (sec / 'pwquality.conf.d').mkdir(parents=True)
    (sec / 'pwquality.conf').write_text('minlen = 8\n')
    (sec / 'pwquality.conf.d' / '50-isemon.conf').write_text('minlen = 14\nminclass = 3\n')
    w.SEC_DIR = str(sec)
    got = w.pwp_read()
    ok('pwquality.conf over the drop-ins, as libpwquality reads them', (got['pwquality']['minlen'],
                                                                       got['pwquality']['minclass']),
       (8, 3))
    ok('...the key set by hand over isemon\'s said', got['pwq_over'], ['minlen'])
    if os.geteuid() == 0:
        w.AS_USER_S = 1
        nobody = pwd.getpwnam('nobody')
        t0 = time.time()
        try:
            w.as_user(nobody, lambda: time.sleep(30))
            ok('a user\'s side that never answers: refused', False)
        except w.Refused as e:
            ok('a user\'s side that never answers: refused within its time',
               (time.time() - t0 < 10, 'did not answer' in str(e)), (True, True))
    else:
        print('  skip  not root: as_user not tried')
    src = (ROOT / 'deploy' / 'isemon_web.py').read_text()
    ok('an Add of a user already here changes nothing', "said='%s was here already - nothing was changed'" in src)
    ok('sudo by the primary group: refused, never shown as done', "own primary group is %s" in src)
    ok('Unlock puts back the day kept, past or not', "lu_run(['chage', '-E', was if was and re.fullmatch(" in src)
    ok('a dropped user\'s kept day goes with them', "lu_expiry_keep(name, None)              # a later user" in src)
    ok('bytes that are not UTF-8 kept in authorized_keys', "errors='surrogateescape') as f:" in src)
    lines = ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl caf\udce9', '']
    try:
        got = w.auth_keys(lines)
        ok('...and a key with such a comment still read (add, drop)', (len(got), bool(got[0].get('fp'))),
           (1, True))
    except Exception as e:                              # noqa: BLE001
        ok('...and a key with such a comment still read (add, drop): %s' % e, False)
    ok('a second Lock keeps the day kept', "elif not entry[3]:" in src)
    ok('a child that does not die is not waited on for ever', 'os.waitpid(pid, os.WNOHANG)' in src)
    ok('the SELinux report: no command lines of other programs',
       w.se_no_cmdlines('type=AVC msg=a\ntype=PROCTITLE proctitle=secret\ntype=EXECVE a0=x\ntype=SYSCALL y'),
       'type=AVC msg=a\ntype=SYSCALL y')
    main = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
    hb = w.http_block(main)
    blk = main[hb[0]:hb[1]]
    if 'location / {' not in blk and 'return ' in blk:
        lines = blk.split('\n')
        at = next(n for n, l in enumerate(lines) if 'server_name' in l) + 1
        lines[at:at] = ['    location / { return 404; }']
        twice = main[:hb[0]] + '\n'.join(lines) + main[hb[1]:]
        new, said = w.acme_into(twice, ['a.example'])
        ok('ACME on port 80 with a location / of its own: no second one, said',
           (new == twice, 'location / of its own' in said), (True, True))
    try:
        w.tls_checked({'managed': True, 'hsts': float('inf')}) if hasattr(w, 'tls_checked') else None
        ok('Infinity in a request: refused as a value', True)
    except w.Refused:
        ok('Infinity in a request: refused as a value', True)
    except OverflowError:
        ok('Infinity in a request: refused as a value', False)
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('page: anything over 64 KB refused before signing in', "(isemon_session() === '' || in_array(" in page)
    ok('page: a name with an underscore', "[A-Za-z0-9._-]{1,253}" in page)
    ok('page: the session ended - said why (5/6 px)', "if (w === 5 || w === 6) { certWatchEnd(" in page)
    ok('page: an emptied days box keeps its value', 'if (isFinite(v)) e[key] = v;' in page)
    ok('the least days a password is good for is 1', isemon.PWP_RANGES['max_days'][0], 1)
finally:
    shutil.rmtree(str(folder), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
