#!/usr/bin/env python3
"""1.10.292: the acme tab searched as every other list is.

- Its three lists - the certificates, every line acme sent, the jobs - have
  the search box of the other lists: fields (`cert:www`, `level:bad`,
  `host:api.cloudflare.com status:429`, `-kind:sign-ins`, `took>30000`,
  `error:*NXDOMAIN*`), offered as they are typed with what each holds
  (/api/suggest, lists `acme` and `acmejobs`), and what is wrong with a
  search said under the box.
- Every line acme sent: the drop-downs, the window ("choose dates…"), the
  page size, Clear, a page at a time with how many in all, and its headings
  ordering it on the server.
- The certificates and the jobs: the ones any matching line is about.

    ./test/fixes292_acmesearch.py
"""
import json
import os
import random
import shutil
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
PORT = 19500 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def line(ago_s, tag, msg='x', **f):
    ts = time.time() - ago_s
    head = 'level=%s kind=%s node=%s who=%s' % (f.pop('level', 'info'), f.pop('kind', 'certificates'),
                                               f.pop('node', 'acme1'), f.pop('who', 'acme'))
    rest = ' '.join('%s=%s' % (k, f[k]) for k in sorted(f))
    return '%s acme %s[1]: %s %s msg="%s"' % (
        time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(ts)), tag, head, rest, msg)


work = Path(tempfile.mkdtemp(prefix='isemon-292-'))
api = None
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
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'acmelog': 1,
                          'acmelog_paths': [str(work)]})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('look', 'a-third-long-password', 'readonly', by='test')
    lines = [
        line(3000, 'acme-certs', 'www renewed', action='renewed', cert='www', names='www.example.cz',
             issuer='LE'),
        line(2900, 'acme-certs', 'www deployed', action='deployed', cert='www', target='f5-brno',
             result='ok'),
        line(2800, 'acme-certs', 'shop deploy failed', action='deploy', cert='shop',
             target='f5-brno', result='failed', level='bad'),
        line(2700, 'acme-certs', 'vpn runs out', action='expiring', cert='vpn', level='warn',
             node='acme2'),
        line(2600, 'acme', 'admin signed in', kind='sign-ins', who='admin', node='acme2'),
        line(90 * 86400, 'acme', 'long ago', kind='settings', who='eva'),
    ]
    for i in range(40):
        lines.append(line(100 + i, 'acme', 'eva signed in %d' % i, kind='sign-ins', who='eva'))
    jl = []

    def job(j, ago, events, **f):
        for ev, t, extra in events:
            jl.append(line(ago - t / 1000.0, 'acme-jobs', 'm', kind='job', event=ev, job=j,
                           t_ms=t, **dict(f, **extra)))
    job('1', 5000, [('start', 0, {}), ('http', 100, {'host': 'api.cloudflare.com', 'status': 429,
                                                     'ms': 80, 'level': 'warn'}),
                    ('end', 4000, {'state': 'failed', 'ok': 0, 'took_ms': 40000,
                                   'level': 'bad'})], job_kind='renew', cert='mail')
    job('2', 4000, [('start', 0, {}), ('http', 100, {'host': 'acme-v02.api.letsencrypt.org',
                                                     'status': 201, 'ms': 90}),
                    ('validation', 900, {'state': 'invalid', 'via': 'challenge:dns-cz',
                                         'error': '"NXDOMAIN for example.cz"', 'level': 'bad'}),
                    ('end', 1000, {'state': 'ok', 'ok': 1, 'took_ms': 1000})],
        job_kind='renew', cert='www')
    daemon.read_records(lines + jl, kind='acmelog')

    print('The fields of the two lists')
    ok('acme and acmejobs are lists of their own', (isemon.LIST_TABLES['acme'],
                                                     isemon.LIST_TABLES['acmejobs']),
       ('acme_events', 'acme_jobs'))
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, sess=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path))
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        if sess:
            req.add_header('X-Isemon-Session', sess)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    req = urllib.request.Request('http://127.0.0.1:%d/api/auth/login' % PORT,
                                 data=json.dumps({'name': 'look',
                                                  'password': 'a-third-long-password'}).encode(),
                                 method='POST')
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('Content-Type', 'application/json')
    s = json.loads(urllib.request.urlopen(req, timeout=30).read().decode())['token']
    from urllib.parse import quote

    def ev(q='', extra=''):
        lim = '' if 'limit=' in extra else '&limit=100'
        return call('/api/acmelog/events?q=%s%s%s' % (quote(q), lim, extra), s)[1]

    print('\nEvery line acme sent')
    d = ev()
    ok('a page, and how many in all', (len(d['rows']), d['total'], d['q_error']), (46, 46, ''))
    ok('a field', [r['cert'] for r in ev('cert:www')['rows']], ['www', 'www'])
    ok('two fields, and one turned round',
       sorted(r['cert'] for r in ev('target:f5-brno -level:bad')['rows']), ['www'])
    ok('any of a list', sorted(r['cert'] for r in ev('cert:www,vpn')['rows']),
       ['vpn', 'www', 'www'])
    ok('a wildcard', sorted({r['cert'] for r in ev('cert:s*')['rows']}), ['shop'])
    ok('a word anywhere, with a field', [r['msg'] for r in ev('admin kind:sign-ins')['rows']],
       ['admin signed in'])
    ok('the window: an hour', ev('', '&hours=1')['total'], 45)
    ok('...all of it', ev('', '&hours=0')['total'], 46)
    d = ev('', '&limit=10&offset=10')
    ok('a page further on, the count the same', (len(d['rows']), d['total']), (10, 46))
    d = ev('', '&sort=who&dir=asc&limit=5')
    ok('ordered by a heading, on the server', [r['who'] for r in d['rows']][:1], ['acme'])
    d = ev('cert:(')
    ok('a search that does not read: said, nothing shown', (bool(d['q_error']), d['rows']),
       (True, []))
    st, d = call('/api/failed?q=%s' % quote('ip:('), s)
    ok('...and on every other list too, not a 500', (st, bool(d.get('q_error'))), (200, True))
    st, v = call('/api/suggest?list=acme&field=cert&typed=', s)
    ok('what a field holds, offered', sorted(x['val'] for x in v['values']),
       ['shop', 'vpn', 'www'])

    print('\nThe certificates')
    st, d = call('/api/acmelog?days=30&q=%s' % quote('target:f5-brno'), s)
    ok('those any matching line is about', (d['match'], d['q_error']), (['shop', 'www'], ''))
    st, d = call('/api/acmelog?days=30', s)
    ok('...and without a search, every one, no match said', 'match' in d, False)

    print('\nThe jobs')
    st, d = call('/api/acmelog/jobs?days=30&q=%s' % quote('host:api.cloudflare.com status:429'), s)
    ok('those with a line like that', d['match'], ['1|acme1'])
    st, d = call('/api/acmelog/jobs?days=30&q=%s' % quote('error:*NXDOMAIN*'), s)
    ok('...a wildcard in an error', d['match'], ['2|acme1'])
    st, d = call('/api/acmelog/jobs?days=30&q=%s' % quote('took>30000'), s)
    ok('...a number compared', d['match'], ['1|acme1'])
    st, v = call('/api/suggest?list=acmejobs&field=host&typed=api', s)
    ok('what the servers were, offered - what was typed anywhere in them, as every box',
       sorted(x['val'] for x in v['values']),
       ['acme-v02.api.letsencrypt.org', 'api.cloudflare.com'])

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the three boxes, as the other lists\' are',
       all(x in page for x in ("qSuggest(find, {lane: 'acmecerts'", "qSuggest(q, {lane: 'acme'",
                               "qSuggest(find, {lane: 'acmejobs'", "windowInstall('am-ev-hours')",
                               "pager('am-ev-pager'", "serverSortHeads(table.tHead.rows[0], "
                               "SORTS.acme")))
    ok('...the fields they offer', ('  acme: [' in page, '  acmejobs: [' in page), (True, True))
finally:
    if api is not None:
        try:
            api.stop()
        except Exception:
            pass
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
