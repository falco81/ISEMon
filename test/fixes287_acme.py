#!/usr/bin/env python3
"""1.10.287: acme - the certificate manager - read from its logs, an acme tab,
and its nodes sending encrypted.

- Settings → The acme logs (`acmelog*`, off by default): what acme sends by
  syslog (acme-certs, and acme where isemon_events is on), filed by rsyslog
  as /var/log/remote/<HOST>/<TAG>.log, read as the OTP logs are. A line is
  the envelope (RFC 3164, PRI or not, BSD or ISO time) and key=value: bare
  or "quoted" with \\" and \\\\, msg last, " ...TRUNCATED" perhaps inside a
  quoted value; unknown kinds and fields kept; a line not key=value (acme's
  tests) kept as text; another program's line left alone. Read twice, kept
  once. Never judged.
- The acme tab (/api/acmelog, /api/acmelog/events): each certificate as its
  last line says (fine, runs out soon, run out, renewal failing, not
  deployed, revoked, deleted), the targets, the nodes, what failed, day by
  day, and every line - filtered. There only while the logs are read.
- Encrypted receiving for acme's nodes: otp's receiver done again by root's
  helper (acmetls.ask) with a file, a folder and a port of its own - and
  imtcp loaded once between the two.
- `acme` stays what it was: this server's Automatic certificates.

    ./test/fixes287_acme.py
"""
import json
import os
import random
import shutil
import stat
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
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19700 + random.randint(0, 90)
PW = 'correct-horse-battery'
ZIP = (HERE / 'otp-tls' / 'isemon-tls.zip').read_bytes()


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


SPEC = [
    '<29>Nov  1 10:27:04 acme acme-certs[812]: level=info kind=certificates node=acme1 who=acme '
    'action=deployed cert=www issuer="Let\'s Encrypt" names="www.example.cz,example.cz" '
    'not_after=2027-01-30T10:26:48Z result=ok serial=04A19C552E0B target=f5-prague '
    'target_kind=f5 version=7 msg="www (version 7) deployed to f5-prague"',
    '<29>Nov  4 17:40:00 acme acme-certs[812]: level=bad kind=certificates node=acme1 who=acme '
    'action=renew cert=www result=failed msg="renewing www failed: the CA said: rateLimited '
    '\\"too many\\""',
    '<29>Nov  4 06:00:12 acme acme-certs[812]: level=warn kind=certificates node=acme2 who=acme '
    'action=expiring cert=vpn names=vpn.example.cz not_after=2026-11-18T08:00:00Z result=warn '
    'serial=7F21AB issuer="Internal CA" msg="vpn ends in 14 days and is not renewed by itself"',
    '<29>Nov  4 16:36:41 acme acme[812]: level=info kind=sign-ins node=acme1 who=admin '
    'msg="admin signed in from 192.0.2.10 (an account here, fulladmin)"',
    '<29>Nov  4 16:40:02 acme acme[3021]: a test from acme 1.0.44 on the command line - isemon '
    'reads nothing from this line',
]
NOW = time.mktime((2026, 11, 4, 20, 0, 0, 0, 0, -1))


def parse(lines, now=NOW):
    return list(isemon.acme_parse_lines(lines, now=now))


work = Path(tempfile.mkdtemp(prefix='isemon-287-'))
api = None
try:
    # ------------------------------------------------------------------------
    print('A line of acme\'s, read')
    got = parse(SPEC)
    ok('every line of the specification read', len(got), 5)
    a = got[0]
    ok('the envelope: program, host, pid', (a.tag, a.host, a.pid), ('acme-certs', 'acme', '812'))
    ok('...its time: the node\'s clock, this year',
       time.localtime(a.ts)[:6], (2026, 11, 1, 10, 27, 4))
    ok('the fields, quoted and bare', (a.fields['issuer'], a.fields['names'], a.fields['version'],
                                       a.fields['target_kind']),
       ("Let's Encrypt", 'www.example.cz,example.cz', '7', 'f5'))
    ok('...msg the last, taken whole', a.msg, 'www (version 7) deployed to f5-prague')
    ok('\\" inside a quoted value', got[1].msg, 'renewing www failed: the CA said: rateLimited '
       '"too many"')
    ok('a line not key=value: kept as text', (got[4].raw, got[4].fields, got[4].msg[:14]),
       (True, {}, 'a test from ac'))
    ok('another program in the same folder: left alone',
       parse(['<29>Nov  4 16:40:02 acme sshd[1]: level=info kind=x node=a who=b msg=c']), [])
    one = parse(['Nov  4 16:40:02 acme acme[1]: level=info kind=x node=a who=b '
                 'zz_new="a \\\\ b" msg="x ...TRUNCATED'])[0]
    ok('no PRI (rsyslog\'s file), an unknown field, a backslash, cut inside msg',
       (one.fields['zz_new'], one.msg, one.truncated), ('a \\ b', 'x', True))
    one = parse(['2026-11-04T16:40:02.123+01:00 acme acme-certs[1]: level=info kind=certificates '
                 'node=acme1 who=acme msg=ok'])[0]
    ok('an ISO time with its zone', one.ts, 1793806802.123)
    cut = parse(['Nov  4 16:40:02 acme acme-certs[1]: level=info kind=certificates node=a who=b '
                 'cert=x names="a,b,c ...TRUNCATED'])[0]
    ok('cut inside a quoted value before msg', (cut.fields['names'], cut.truncated, cut.msg),
       ('a,b,c', True, ''))
    ok('the same line: the same ident; another: another',
       (parse(SPEC[:1])[0].ident == got[0].ident, got[0].ident == got[1].ident), (True, False))
    ok('not_after as a moment', isemon.acme_iso_ts('2027-01-30T10:26:48Z'), 1801304808.0)

    # ------------------------------------------------------------------------
    print('\nThe settings: acme stays this server\'s Automatic certificates')
    D = isemon.DEFAULTS
    ok('new, off by default', (D['acmelog'], D['acmelog_paths'], D['acmelog_certs_name'],
                               D['acmelog_events'], D['acmelog_events_name'],
                               D['retain_acmelog_days']),
       (0, ['/var/log/remote/acme'], 'acme-certs.log', 1, 'acme.log', 400))
    ok('acme itself as it was', (D['acme'], D['acme_ca']), (0, 'letsencrypt'))
    state = work / 'state'
    state.mkdir()
    (state / 'web').mkdir()
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'b'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'token'
    isemon.WEB_DIR = state / 'web'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('look', 'a-third-long-password', 'readonly', by='test')
    src = (ROOT / 'isemon.py').read_text()
    ok('acme\'s label is still Automatic certificates\'',
       "'acme': 'Certificates from an ACME CA'," in src)
    ok('off: not one file of acme\'s read', [x for x in daemon.log_files() if x[0] == 'acmelog'],
       [])
    logs = work / 'remote' / 'acme'
    logs.mkdir(parents=True)
    isemon.CONFIG.update({'acmelog': 1, 'acmelog_paths': [str(logs)]})
    ok('on: its files in the folder (acme-jobs.log too, from 1.10.288)',
       [x for x in daemon.log_files() if x[0] == 'acmelog'],
       [('acmelog', str(logs / 'acme-certs.log'), 'acmelog'),
        ('acmelog', str(logs / 'acme.log'), 'acmelog'),
        ('acmelog', str(logs / 'acme-jobs.log'), 'acmelog')])
    isemon.CONFIG['acmelog_events'] = 0
    ok('...the certificates\' alone with isemon_events off here',
       len([x for x in daemon.log_files() if x[0] == 'acmelog']), 2)
    isemon.CONFIG['acmelog_events'] = 1
    ok('its reader', isemon.LOG_PARSERS['acmelog'] is isemon.acme_parse_lines)

    # ------------------------------------------------------------------------
    print('\nKept, once, never judged')
    daemon.read_records(SPEC, kind='acmelog')
    daemon.read_records(SPEC, kind='acmelog')
    rows = [dict(r) for r in store.db.execute('SELECT * FROM acme_events ORDER BY ts').fetchall()]
    ok('read twice, kept once', len(rows), 5)
    dep = [r for r in rows if r['action'] == 'deployed'][0]
    ok('the columns of a deployment', (dep['cert'], dep['target'], dep['target_kind'],
                                       dep['serial'], dep['not_after'], dep['node'], dep['level']),
       ('www', 'f5-prague', 'f5', '04A19C552E0B', 1801304808.0, 'acme1', 'info'))
    raw = [r for r in rows if r['raw']][0]
    ok('the test line: text, no node', (raw['tag'], raw['node'], raw['host']),
       ('acme', None, 'acme'))
    daemon.read_records(['Nov  4 16:40:02 acme acme[1]: level=info kind=modules node=acme1 '
                         'who=acme zz_new=1 msg=x'], kind='acmelog')
    ex = store.db.execute("SELECT extra, kind FROM acme_events WHERE kind = 'modules'").fetchone()
    ok('an unknown kind and field: kept as they came', (ex['kind'], json.loads(ex['extra'])),
       ('modules', {'zz_new': '1'}))
    ok('nobody banned, no failed row', (store.db.execute('SELECT COUNT(*) AS n FROM failed')
                                        .fetchone()['n']), 0)

    # ------------------------------------------------------------------------
    print('\nWhat each certificate adds up to')
    with store.db_write() as db:
        db.execute('DELETE FROM acme_events')
    now = time.time()

    def L(ago_d, tag, **f):
        ts = now - ago_d * 86400
        msg = f.pop('msg', 'x')
        head = ' '.join('%s=%s' % (k, f.pop(k)) for k in ('level', 'kind', 'node', 'who'))
        rest = ' '.join('%s=%s' % (k, f[k]) for k in sorted(f))
        return '%s acme %s[1]: %s %s msg="%s"' % (
            time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(ts)), tag, head, rest, msg)

    def iso(d):
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + d * 86400))
    C = dict(level='info', kind='certificates', node='acme1', who='acme')
    lines = [
        L(10, 'acme-certs', action='renewed', cert='fine', not_after=iso(80), serial='AA', **C),
        L(9, 'acme-certs', action='deployed', cert='fine', target='f5', target_kind='f5',
          result='ok', **C),
        L(5, 'acme-certs', action='issued', cert='soon', not_after=iso(12), **C),
        L(20, 'acme-certs', action='renewed', cert='gone', not_after=iso(-2), **C),
        L(30, 'acme-certs', action='renewed', cert='fails', not_after=iso(40), **C),
        L(1, 'acme-certs', action='renew', cert='fails', result='failed',
          msg='renewing fails failed', **dict(C, level='bad')),
        L(4, 'acme-certs', action='renewed', cert='nodeploy', not_after=iso(70), **C),
        L(3, 'acme-certs', action='deployed', cert='nodeploy', target='fg', result='ok', **C),
        L(2, 'acme-certs', action='deploy', cert='nodeploy', target='lx', result='failed',
          **dict(C, level='bad')),
        L(6, 'acme-certs', action='renewed', cert='rv', not_after=iso(50), **C),
        L(1, 'acme-certs', action='revoked', cert='rv', reason='keyCompromise', **C),
        L(8, 'acme-certs', action='added', cert='del', **C),
        L(1, 'acme-certs', action='deleted', cert='del', **C),
        L(2, 'acme', msg='admin signed in', **dict(C, kind='sign-ins', who='admin', node='acme2')),
    ]
    daemon.read_records(lines, kind='acmelog')
    states = {c['cert']: c['state'] for c in store.acme_certificates()}
    ok('fine, runs out soon, run out, failing, not deployed, revoked, deleted', states,
       {'fine': 'ok', 'soon': 'expiring', 'gone': 'expired', 'fails': 'failing',
        'nodeploy': 'deploy_failed', 'rv': 'revoked', 'del': 'deleted'})
    v = store.acme_view(30)
    ok('the counts', (v['kpi']['certs'], v['kpi']['ok'], v['kpi']['expiring'],
                      v['kpi']['expired'], v['kpi']['failing'], v['kpi']['revoked']),
       (6, 1, 1, 1, 2, 1))
    ok('...over the period', (v['sums']['issued'], v['sums']['deployed'],
                              v['sums']['deploy_failed'], v['sums']['renew_failed']), (5, 2, 1, 1))
    ok('the worst first', [c['cert'] for c in v['certs']][:3], ['gone', 'fails', 'nodeploy'])
    nd = [c for c in v['certs'] if c['cert'] == 'nodeploy'][0]
    ok('its targets, each its last word', [(t['target'], t['ok']) for t in nd['targets']],
       [('fg', True), ('lx', False)])
    ok('the targets', sorted((t['target'], t['ok'], t['failed']) for t in v['targets']),
       [('f5', 1, 0), ('fg', 1, 0), ('lx', 0, 1)])
    ok('the nodes', [(n['node'], n['events_on']) for n in v['nodes']],
       [('acme1', False), ('acme2', True)])
    ok('what failed', sorted(r['cert'] for r in v['failures']), ['fails', 'nodeploy'])
    ok('day by day: every day of the period', len(v['activity']) in (31, 32))
    ok('how many want looking at', store.acme_attention(), 4)
    e = store.acme_events_list({'cert': 'nodeploy'})
    ok('the lines of one certificate, newest first',
       [r['action'] for r in e['rows']], ['deploy', 'deployed', 'renewed'])
    e = store.acme_events_list({'q': 'SIGNED'})
    ok('a word anywhere in the message', [r['who'] for r in e['rows']], ['admin'])
    e = store.acme_events_list({'level': 'bad'}, limit=1)
    ok('a page, and whether there is more', (len(e['rows']), e['more']), (1, True))
    e2 = store.acme_events_list({'level': 'bad', 'before': e['rows'][0]['ts']}, limit=5)
    ok('...the page after it', len(e2['rows']), 1)
    ok('the choices for the filters', e['facets']['tag'], ['acme', 'acme-certs'])
    ok('a quote in a search does nothing it should not', store.acme_events_list(
        {'q': "' OR 1=1 --"})['rows'], [])
    with store.db_write() as db:
        db.execute('UPDATE acme_events SET ts = ? WHERE cert = ?', (now - 500 * 86400, 'del'))
    store.tidy_acme()
    ok('older than it is kept: let go', store.acme_events_list({'cert': 'del'})['rows'], [])

    # ------------------------------------------------------------------------
    print('\nThe API')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, body=None, sess=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method='POST' if body is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if sess:
            req.add_header('X-Isemon-Session', sess)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def login(n, p):
        return call('/api/auth/login', {'name': n, 'password': p})[1]['token']
    boss, look = login('boss', 'a-long-enough-password'), login('look', 'a-third-long-password')
    st, d = call('/api/acmelog?days=30', sess=look)
    ok('anybody signed in sees the tab', (st, d['on'], d['kpi']['certs']), (200, True, 6))
    st, d = call('/api/acmelog/events?node=acme2', sess=look)
    ok('...and its lines, filtered', (st, [r['who'] for r in d['rows']]), (200, ['admin']))
    ok('signed out: not', call('/api/acmelog')[0], 401)
    st, s = call('/api/status', sess=look)
    ok('the status says it is on, and how many want looking at',
       (s.get('acmelog_on'), s.get('acmelog_attention')), (True, 4))
    st, d = call('/api/acme', sess=boss)
    ok('/api/acme is still Automatic certificates', (st, 'on' in d and 'kpi' not in d),
       (200, True))
    isemon.CONFIG['acmelog'] = 0
    daemon.forget_held('acmelog/')
    ok('off: the tab says so', call('/api/acmelog', sess=look)[1], {'on': False})
    isemon.CONFIG['acmelog'] = 1

    # ------------------------------------------------------------------------
    print('\nThe file acme made, opened')
    got = isemon.acmetls_open_zip(ZIP, PW)
    ok('opened, the key held here', (got['token'] in isemon.ACMETLS_OPENED,
                                     got['token'] in isemon.OTPTLS_OPENED,
                                     'PRIVATE' in json.dumps(got)), (True, False, False))
    try:
        isemon.acmetls_open_zip(b'nope', PW)
        ok('not a zip: refused', False)
    except ValueError as e:
        ok('not a zip: refused, in acme\'s words', 'as acme makes it' in str(e))
    held = isemon.ACMETLS_OPENED[got['token']]

    # ------------------------------------------------------------------------
    print('\nRoot\'s helper: acme\'s receiver beside otp\'s')
    etc = work / 'etc'
    rsd = etc / 'rsyslog.d'
    rsd.mkdir(parents=True)
    (etc / 'rsyslog.conf').write_text('module(load="imuxsock")\n$IncludeConfig /x/*.conf\n')
    (rsd / '10-plain.conf').write_text('module(load="imudp")\ninput(type="imudp" port="514")\n')
    mods = work / 'mods'
    mods.mkdir()
    (mods / 'lmnsd_gtls.so').write_text('')
    rsyslogd = work / 'rsyslogd'
    rsyslogd.write_text('#!/bin/sh\ncase "$1" in\n  -v) echo "rsyslogd  8.2310.0"; exit 0;;\n'
                        '  -N1) exit 0;;\nesac\nexit 1\n')
    rsyslogd.chmod(0o755)
    hs = work / 'hstate'
    (hs / 'web').mkdir(parents=True)
    ENV = dict(os.environ, ISEMON_STATE=str(hs), ISEMON_WEB_NO_SERVICES='1',
               ISEMON_RSYSLOG='%s:%s' % (etc / 'rsyslog.conf', rsd),
               ISEMON_OTPTLS_CONF=str(rsd / '99-otp-tls.conf'),
               ISEMON_OTPTLS_OLD=str(rsd / '10-otp-tls.conf'),
               ISEMON_OTPTLS_DIR=str(etc / 'pki' / 'otp'),
               ISEMON_RSYSLOGD=str(rsyslogd), ISEMON_RSYSLOG_MODDIR=str(mods),
               ISEMON_NGINX_CONF=str(work / 'none.conf'))
    HELPER = ROOT / 'deploy' / 'isemon_web.py'
    ACONF, OCONF = rsd / '99-tls-acme.conf', rsd / '99-otp-tls.conf'
    APKI = etc / 'pki' / 'acme'

    def ask(which, req):
        req = dict(req, at=time.time())
        (hs / 'web' / ('%stls.ask' % which)).write_text(json.dumps(req))
        r = subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True,
                           text=True)
        if r.returncode:
            print(r.stderr)
        return json.loads((hs / 'web' / ('%stls.json' % which)).read_text())

    def loads(p):
        return 'module(load="imtcp")' in p.read_text() if p.exists() else None
    r = ask('acme', {'id': 'x1', 'do': 'read'})
    ok('a read: nothing there', (r['ok'], r['data']['conf'], r['data']['dir']),
       (True, {'there': False}, str(APKI)))
    r = ask('acme', {'id': 'x2', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'],
                     'key': held['key'], 'port': 6514, 'mutual': True, 'peers': 'acme1 acme2',
                     'how': 'acme'})
    ok('acme\'s put in', (r['ok'], r['id']), (True, 'x2'))
    text = ACONF.read_text()
    ok('...its own file, marked, its input named, the nodes by name',
       ('# isemon: the acme logs over TLS' in text, 'name="acme-tls"' in text,
        'PermittedPeer=["acme1", "acme2"]' in text, 'Settings → acme’s log' in text),
       (True, True, True, True))
    ok('...its own folder, root\'s alone, the key 0600',
       (stat.S_IMODE(os.stat(APKI).st_mode), stat.S_IMODE(os.stat(APKI / 'isemon.key').st_mode)),
       (0o750, 0o600))
    ok('...alone, it loads imtcp itself', loads(ACONF), True)
    ok('...said in acme\'s words', any('acme logs over TLS on 6514/tcp' in x for x in r['said']))
    ok('otp\'s answer file not touched', (hs / 'web' / 'otptls.json').exists(), False)
    r = ask('otp', {'id': 'y1', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'],
                    'key': held['key'], 'port': 6514, 'mutual': False, 'how': 'otp'})
    ok('otp\'s on the same port: refused', (r['ok'], 'listens on 6514/tcp already' in r['said']),
       (False, True))
    r = ask('otp', {'id': 'y2', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'],
                    'key': held['key'], 'port': 6515, 'mutual': False, 'how': 'otp'})
    ok('otp\'s on another port: put in', r['ok'])
    otext = OCONF.read_text()
    ok('...otp\'s file in otp\'s words, as it always was',
       ('# isemon: the otp logs over TLS' in otext, 'name="otp-tls"' in otext,
        'Settings → The OTP logs' in otext, '(11-otp.conf)' in otext), (True, True, True, True))
    ok('imtcp loaded once, by the file read first (otp\'s)', (loads(OCONF), loads(ACONF)),
       (True, False))
    ok('...the folders apart', ((etc / 'pki' / 'otp' / 'isemon.crt').exists(),
                                (APKI / 'isemon.crt').exists()), (True, True))
    r = ask('otp', {'id': 'y3', 'do': 'remove'})
    ok('otp\'s removed: acme\'s loads imtcp again', (r['ok'], OCONF.exists(), loads(ACONF)),
       (True, False, True))
    r = ask('acme', {'id': 'x3', 'do': 'set', 'port': 6516, 'mutual': True, 'peers': 'acme1'})
    ok('acme\'s changed: its port, its node', (r['ok'], 'port="6516"' in ACONF.read_text(),
                                              'PermittedPeer=["acme1"]' in ACONF.read_text()),
       (True, True, True))
    (rsd / '10-plain.conf').write_text('module(load="imtcp")\ninput(type="imtcp" port="514")\n')
    r = ask('acme', {'id': 'x4', 'do': 'set', 'port': 6516, 'mutual': False})
    ok('imtcp loaded by another file: not loaded again', (r['ok'], loads(ACONF)), (True, False))
    r = ask('acme', {'id': 'x5', 'do': 'remove'})
    ok('removed: the file and the folder gone', (r['ok'], ACONF.exists(), APKI.exists()),
       (True, False, False))

    # ------------------------------------------------------------------------
    print('\nThe pages, the path unit, rsyslog\'s rule')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the pane, beside The OTP logs, with its TLS card',
       (page.index('id="pane-otp"') < page.index('id="pane-acmelog"')
        < page.index('id="acmetls-card"') < page.index('id="pane-tacplus"')), True)
    ok('the tab, hidden until it is on', 'data-tab="acmelog" data-icon="lock" hidden' in page)
    ok('the relay knows the three', all(x in page for x in (
        "'acmetls'      => '/api/acmetls'", "'acmelog'      => '/api/acmelog'",
        "'acmelog-events' => '/api/acmelog/events'")))
    ok('otp\'s card as it was', ("api('otptls'" in page, 'function drawOtpTls()' in page,
                                 'function drawAcmeTls()' in page), (True, True, True))
    unit = (ROOT / 'deploy' / 'isemon-web.path').read_text()
    ok('isemon-web.path watches acmetls.ask', 'PathExists=/var/lib/isemon/web/acmetls.ask' in unit)
    rule = (ROOT / 'deploy' / 'rsyslog-acme.conf').read_text()
    ok('deploy/rsyslog-acme.conf files both programs by HOST',
       ('$programname == "acme-certs" or $programname == "acme"' in rule,
        '%HOSTNAME:::secpath-replace%/%PROGRAMNAME:::secpath-replace%.log' in rule), (True, True))
finally:
    if api is not None:
        try:
            api.stop()
        except Exception:
            pass
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
