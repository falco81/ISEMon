#!/usr/bin/env python3
"""1.10.294: what the first round of review found, fixed.

- acme's logs: a number too big for a BIGINT (bytes=1e20, status=inf) no
  longer stops every pass over the file at that line; a quote left inside a
  value before msg (acme's own scrub leaves `"[hidden]"`) no longer loses the
  rest of the line; a line of 1 January read at New Year's Eve, and a 29
  February, get their own year; a certificate deleted and added again is
  there again; a job begun just before the window and ended in it is one of
  its jobs; whether a job was interrupted is how long since its last line
  ARRIVED; the views keep the newest rows, not the oldest.
- acme push: a pairing nobody may make is refused before its nonce is kept,
  and a full store of nonces refuses rather than letting one go.
- The ZIPs of otp and acme: an entry unpacked no further than an entry may be.
- Root's helper: a port another program listens on is refused, SELinux never
  takes a port from another service, a request's time that is not a number
  is refused, a file is isemon's by its own mark only.
- The acme tab: answers drawn only for the newest question, the axis of when
  they run out held to 400 days, its marks and cards reached by the keyboard.

    ./test/fixes294_audit.py
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
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


def iso(ago):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - ago))


work = Path(tempfile.mkdtemp(prefix='isemon-294-'))
try:
    print('The lines, read')
    f, _ = isemon.acme_fields('level=bad kind=job node=a who=acme error="the API said "[hidden]" '
                              'back" event=validation job=4711 state=invalid msg="x"')
    ok('a quote left inside a value: the rest of the line kept',
       (f['error'], f['event'], f['job'], f['state'], f['msg']),
       ('the API said "[hidden]" back', 'validation', '4711', 'invalid', 'x'))
    now = time.mktime((2026, 12, 31, 23, 59, 58, 0, 0, -1))
    m = isemon.ACME_ENVELOPE.match('Jan  1 00:00:03 acme acme-certs[1]: level=info kind=c '
                                   'node=a who=b msg=x')
    ok('1 January read on New Year\'s Eve: next year', time.localtime(
        isemon.acme_when(m, now))[:3], (2027, 1, 1))
    now = time.mktime((2029, 3, 2, 10, 0, 0, 0, 0, -1))
    m = isemon.ACME_ENVELOPE.match('Feb 29 10:00:00 acme acme-certs[1]: level=info kind=c '
                                   'node=a who=b msg=x')
    ok('29 February read in a year without one: the last that had it',
       time.localtime(isemon.acme_when(m, now))[:3], (2028, 2, 29))
    now = time.mktime((2026, 11, 5, 10, 0, 0, 0, 0, -1))
    m = isemon.ACME_ENVELOPE.match('Nov  4 10:00:00 acme acme-certs[1]: level=info kind=c '
                                   'node=a who=b msg=x')
    ok('...and an ordinary day as it was', time.localtime(isemon.acme_when(m, now))[:3],
       (2026, 11, 4))

    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    logs = work / 'acme'
    logs.mkdir()
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'acmelog': 1, 'acmelog_paths': [str(logs)]})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)

    print('\nA number too big for the database')
    (logs / 'acme-jobs.log').write_text(
        '%s acme acme-jobs[1]: level=debug kind=job node=acme1 who=acme bytes=99999999999999999999 '
        'event=http job=9 status=inf t_ms=1 msg=x\n'
        '%s acme acme-jobs[1]: level=info kind=job node=acme1 who=acme event=start job=10 t_ms=0 '
        'msg=after\n' % (iso(60), iso(50)))
    daemon.read_logs()
    daemon.read_logs()
    rows = {r['job']: dict(r) for r in store.db.execute('SELECT job, bytes, status FROM acme_jobs')}
    ok('the line kept, the number held to a BIGINT, the one beyond it not taken',
       (rows.get('9', {}).get('bytes'), rows.get('9', {}).get('status')),
       (isemon.BIGINT_MOST, None))
    ok('...and the line after it read too', '10' in rows)

    print('\nWhat a certificate is, and the jobs')
    lines = []

    def L(ago, tag, **f):
        head = 'level=info kind=%s node=acme1 who=acme' % f.pop('kind', 'certificates')
        rest = ' '.join('%s=%s' % (k, f[k]) for k in sorted(f))
        lines.append('%s acme %s[1]: %s %s msg=x' % (iso(ago), tag, head, rest))
    L(500, 'acme-certs', action='issued', cert='back')
    L(400, 'acme-certs', action='deleted', cert='back')
    L(300, 'acme-certs', action='added', cert='back')
    L(86400 + 10, 'acme-jobs', kind='job', event='start', job='20', t_ms=0)
    L(86400 - 20, 'acme-jobs', kind='job', event='end', job='20', state='ok', ok=1, took_ms=30000)
    # Written on a node whose clock is two hours behind - arrived just now.
    L(7200 + 30, 'acme-jobs', kind='job', event='start', job='21', t_ms=0)
    daemon.read_records(lines, kind='acmelog')
    states = {c['cert']: c['state'] for c in store.acme_certificates()}
    ok('deleted, then added again: there again', states.get('back'), 'ok')
    jobs = {j['job']: j for j in store.acme_jobs_list(time.time() - 86400)}
    ok('begun before the window, ended in it: one of its jobs', jobs.get('20', {}).get('state'),
       'ok')
    ok('its last line arrived a moment ago, whatever its clock: running',
       jobs.get('21', {}).get('state'), 'running')
    L(20 * 3600, 'acme-jobs', kind='job', event='start', job='22', t_ms=0)
    daemon.read_records(lines[-1:], kind='acmelog')
    jobs = {j['job']: j for j in store.acme_jobs_list(time.time() - 86400)}
    ok('read again long after it was written: interrupted, though it arrived just now',
       jobs.get('22', {}).get('state'), 'interrupted')

    print('\nacme push')
    isemon.CONFIG['acme_push'] = 1
    src = (ROOT / 'isemon.py').read_text()
    a = src.index('def push_checked(')
    body = src[a:src.index('def push_pair(', a)]
    ok('a pairing with no code waiting: refused before its nonce is kept',
       body.index("if op == 'pair':\n        waiting") < body.index("seen['%s:%s' % (kid, nonce)] = now"))
    ok('a full store of nonces refuses, never lets one go',
       ("if len(seen) >= PUSH_NONCES_MOST:" in body, 'sorted(seen.items()' in body), (True, False))

    print('\nThe ZIPs of otp and acme')
    big = zlib.compressobj(9, zlib.DEFLATED, -15)
    bomb = big.compress(b'\0' * (8 << 20)) + big.flush()
    ok('the bomb is small', len(bomb) < 20000)
    try:
        ext = {'strength': 3, 'method': 8, 'ver': 2}
        # Encrypted as WinZip AES does it, with a key of our own.
        import hashlib
        import hmac
        salt = b'S' * 16
        keys = hashlib.pbkdf2_hmac('sha1', b'pw', salt, 1000, 66)
        n = (len(bomb) + 15) // 16
        stream = isemon._aes_ecb(keys[:32], b''.join(struct.pack('<QQ', i + 1, 0)
                                                     for i in range(n)))
        enc = bytes(x ^ y for x, y in zip(bomb, stream))
        raw = salt + keys[64:66] + enc + hmac.new(keys[32:64], enc, 'sha1').digest()[:10]
        isemon._winzip_aes(raw, ext, b'pw', 0, False)
        ok('an entry that unpacks to 8 MB: refused', False)
    except ValueError as e:
        ok('an entry that unpacks to 8 MB: refused, said so', 'far more' in str(e))

    print('\nRoot\'s helper')
    helper = (ROOT / 'deploy' / 'isemon_web.py').read_text()
    ok('a port another program holds: refused', "is taken here already" in helper)
    ok('...rsyslog itself must hold it after the restart', "'rsyslogd' in who" in helper)
    ok('SELinux: never -m, a port of another service refused',
       ("'semanage', 'port', '-m'" in helper or "('-a', '-m')" in helper,
        'SELinux keeps %d/tcp for another service' in helper), (False, True))
    # ...three since 1.10.305: a change of the network or the clock asked
    # too long ago is not done either; four since 1.10.319: nor a step of
    # SELinux.
    ok('a time that is not a number is not fresh', helper.count('math.isfinite(at)'), 4)
    ok('a file is isemon\'s by its mark at the start of a line',
       'l.startswith(TLS_MARKS)' in helper and "'# isemon: the ' not in text" not in helper)
    ok('off or removed with the other file changed: rsyslog asked first',
       'if tls_loads_fix(said):\n                rsyslog_check()' in helper)

    print('\nThe acme tab')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('only the newest question\'s answer drawn',
       ('if (mine !== AM_ASKED || days !== AM.days) return;' in page,
        'if (mine !== AMJ.seq || page !== AM.page || days !== AM.days) return;' in page),
       (True, True))
    ok('the axis held to 400 days back', 'var lo = Math.max(-400,' in page)
    ok('its marks and cards reached by the keyboard', page.count('amKeys(') >= 5)
    ok('the lines narrowed from elsewhere show it in their own boxes',
       'function amEventsAs(want)' in page)
    ok('Read again comes back whatever the answer',
       'loadAcmeLog().then(function () { busy(again, false); }' in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
