#!/usr/bin/env python3
"""The page in another language (1.10.153).

The files in web/lang/ are checked as files: each one valid JSON with its
`_meta` first and flat, the same IDs as en.json, and every translation
keeping what the page needs from the English - the {0} slots, the inline
tags, the code inside <code>, the spaces it starts and ends with. Then the
web page hands them out (`?api=lang`): only what differs from the English,
nothing for a code that is not a file, and nothing at all - the page as it
always was - when the folder is not there. Then the daemon keeps each
person's choice (`user_prefs`): theirs only, checked, carried in the
settings file, gone with the account. And last, what the page's code reads
back off the page is read in English.

    ./test/i18n.py
"""
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
TREE = HERE.parent
sys.path.insert(0, str(TREE))
import isemon                                        # noqa: E402

LANG = TREE / 'web' / 'lang'
PAGE_SRC = (TREE / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0
PORT = 19877


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


TAGS = re.compile(r'</?(?:b|i|em|strong|code|kbd)>|<br>')
SLOT = re.compile(r'\{\d+\}')

print('\nThe files')
files = sorted(LANG.glob('*.json'))
ok('English and Czech are shipped', sorted(f.stem for f in files) >= ['cs', 'en'], True)
en = json.loads((LANG / 'en.json').read_text(encoding='utf-8'))
ids = {k: v['source'] for part in ('strings', 'patterns', 'rich') for k, v in en[part].items()}
ok('en.json holds the words of the page (thousands of them)', len(ids) > 5000)
for f in files:
    raw = f.read_text(encoding='utf-8')
    try:
        data = json.loads(raw)
    except ValueError as e:
        ok('%s is valid JSON' % f.name, str(e), '')
        continue
    ok('%s is valid JSON' % f.name, True)
    head = re.search(r'"_meta"\s*:\s*(\{[^{}]*\})', raw[:8192], re.S)
    ok('%s: its _meta comes first and is flat (the page reads only that much to offer it)'
       % f.name, bool(head) and raw.lstrip().startswith('{') and
       raw.index('"_meta"') < 40, True)
    meta = data.get('_meta', {})
    ok('%s: _meta names its code, which is the file name' % f.name, meta.get('code'), f.stem)
    ok('%s: ...and the language by its own name' % f.name, bool(meta.get('name')), True)
    mine = {k: v for part in ('strings', 'patterns', 'rich')
            for k, v in data.get(part, {}).items()}
    ok('%s: the same IDs as en.json, none missing, none extra' % f.name,
       (sorted(set(ids) - set(mine))[:3], sorted(set(mine) - set(ids))[:3]), ([], []))
    ok('%s: every source is the English of its ID' % f.name,
       [k for k, v in mine.items() if ids.get(k) != v.get('source')][:3], [])
    bad = []
    for k, v in mine.items():
        s, t = v.get('source', ''), v.get('text', '')
        if not t:
            continue
        if sorted(SLOT.findall(s)) != sorted(SLOT.findall(t)):
            bad.append(('slots', k))
        if sorted(TAGS.findall(s)) != sorted(TAGS.findall(t)):
            bad.append(('tags', k))
        if any('<code>%s</code>' % c not in t for c in re.findall(r'<code>(.*?)</code>', s)):
            bad.append(('code', k))
        if re.match(r'\s*', s).group() != re.match(r'\s*', t).group() \
                or re.search(r'\s*$', s).group() != re.search(r'\s*$', t).group():
            bad.append(('spaces', k))
    ok('%s: every translation keeps the slots, tags, code and spaces of its English'
       % f.name, bad[:5], [])
cs = json.loads((LANG / 'cs.json').read_text(encoding='utf-8'))
cs_all = {k: v for part in ('strings', 'patterns', 'rich') for k, v in cs[part].items()}
ok('Czech: every text translated', [k for k, v in cs_all.items() if not v['text']][:3], [])
ok('Czech: the tabs are Czech', cs['strings'].get(
    next(k for k, v in cs['strings'].items() if v['source'] == 'Overview'), {}).get('text'),
   'Přehled')


def free(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) != 0


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status, r.headers, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode('utf-8', 'replace')


print('\nThe web page hands them out')
php = shutil.which('php')
if not php:
    print('  (php is not here: skipped)')
else:
    web = Path(tempfile.mkdtemp(prefix='isemon-i18n-web-'))
    shutil.copytree(TREE / 'web', web / 'web')
    wport = 19878
    while not free(wport):
        wport += 1
    server = subprocess.Popen([php, '-S', '127.0.0.1:%d' % wport, '-t', str(web / 'web')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if not free(wport):
                break
            time.sleep(0.1)
        base = 'http://127.0.0.1:%d/index.php' % wport
        status, head, body = fetch(base + '?api=lang&code=cs&v=1')
        ok('Czech is handed out as a script', (status, head.get('Content-Type', '')[:22]),
           (200, 'application/javascript'))
        ok('...that a browser keeps until the file changes',
           'immutable' in head.get('Cache-Control', ''), True)
        pack = json.loads(body[body.index('=') + 1:].strip().rstrip(';'))
        ok('...with the words of the page', pack['strings'].get('Overview'), 'Přehled')
        ok('...and only what differs from the English',
           all(k != v for k, v in pack['strings'].items()), True)
        ok('...patterns as pairs, slots kept',
           all(sorted(SLOT.findall(a)) == sorted(SLOT.findall(b)) for a, b in pack['patterns']),
           True)
        for code in ('xx', '../../etc/passwd', 'cs.json', ''):
            status, head, body = fetch(base + '?api=lang&code=' + urllib.request.quote(code))
            ok('%r: nothing handed out, the page stays English' % code,
               (status, 'ISEMON_LANG_PACK' in body), (200, False))
        status, head, body = fetch(base + '?api=lang&code=en')
        ok('English as it comes: nothing to hand out at all', 'ISEMON_LANG_PACK' in body, False)
        status, head, body = fetch(base)
        ok('the sign-in page offers both', '"code":"cs"' in body and '"code":"en"' in body, True)
        ok('...and is English with nothing loaded when nobody chose',
           ('?api=lang' in body, 'i18n-wait' in body.split('<head>')[0]), (False, False))
        req = urllib.request.Request(base, headers={'Cookie': 'isemon_lang=cs'})
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode('utf-8')
        ok('a browser that chose Czech gets it loaded before anything is drawn',
           ('?api=lang&amp;code=cs' in body, 'lang="cs"' in body,
            'html.i18n-wait body{visibility:hidden}' in body), (True, True, True))
        shutil.rmtree(web / 'web' / 'lang')
        req = urllib.request.Request(base, headers={'Cookie': 'isemon_lang=cs'})
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode('utf-8')
        ok('with the folder gone: English, nothing loaded, only English offered',
           ('?api=lang' in body, 'lang="en"' in body, '"code":"cs"' in body),
           (False, True, False))
        status, head, body = fetch(base + '?api=lang&code=cs')
        ok('...and asking for Czech gets nothing', 'ISEMON_LANG_PACK' in body, False)
        (web / 'web' / 'lang').mkdir()
        (web / 'web' / 'lang' / 'cs.json').write_text('{"_meta": {"code": "cs", "name": "x"}, ',
                                                       encoding='utf-8')
        req = urllib.request.Request(base, headers={'Cookie': 'isemon_lang=cs'})
        with urllib.request.urlopen(req, timeout=20) as r:
            body = r.read().decode('utf-8')
        ok('a broken file: English, nothing loaded', ('?api=lang' in body, 'lang="en"' in body),
           (False, True))
    finally:
        server.terminate()
        server.wait(10)
        shutil.rmtree(web, ignore_errors=True)


print('\nThe daemon keeps the choice')


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


folder = tempfile.mkdtemp(prefix='isemon-i18n-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder]})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
try:
    admin = call('/api/auth/login', 'POST', {'name': 'boss',
                                             'password': 'a-long-enough-password'})[1]['token']
    looker = call('/api/auth/login', 'POST', {'name': 'watcher',
                                              'password': 'another-long-password'})[1]['token']
    status, said = call('/api/auth/whoami', session=looker)
    ok('nothing chosen: the page is told nothing', said.get('prefs'), {})
    status, said = call('/api/auth/prefs', 'POST', {'prefs': {'lang': 'cs'}}, session=looker)
    ok('a read-only account chooses its own language', (status, said.get('prefs')),
       (200, {'lang': 'cs'}))
    status, said = call('/api/auth/whoami', session=looker)
    ok('...and the page is told it with who they are', said.get('prefs'), {'lang': 'cs'})
    status, said = call('/api/auth/whoami', session=admin)
    ok('...nobody else is', said.get('prefs'), {})
    for wrong in ('../x', 'c s', 'x' * 30, 5):
        status, said = call('/api/auth/prefs', 'POST', {'prefs': {'lang': wrong}},
                            session=looker)
        ok('%r is not a language code: refused, the choice stays' % (wrong,),
           (status, store.user_prefs('watcher')), (400, {'lang': 'cs'}))
    status, said = call('/api/auth/prefs', 'POST', {'prefs': {'lang': 'cs', 'evil': 1}},
                        session=looker)
    ok('anything that is not a choice is not kept', store.user_prefs('watcher'), {'lang': 'cs'})
    status, said = call('/api/auth/prefs', 'POST', {'prefs': {'lang': 'cs'}})
    ok('nobody signed in may choose', status, 401)
    status, said = call('/api/auth/prefs', 'POST', {'prefs': 'cs'}, session=looker)
    ok('choices that are not an object are refused, not a fault (1.10.155)', status, 400)
    store.put_user_finds('watcher', [['kept', 1, time.time()]])
    status, said = call('/api/auth/settings', 'POST',
                        {'settings': {'search': [], 'prefs': ['x']}}, session=looker)
    ok('...and a file with a bad section changes nothing at all, not half of it',
       (status, len(store.user_finds('watcher'))), (400, 1))
    status, said = call('/api/auth/settings', session=looker)
    ok('the settings file carries it', said.get('settings', {}).get('prefs'), {'lang': 'cs'})
    status, said = call('/api/auth/settings', 'POST',
                        {'settings': {'prefs': {'lang': 'en'}}}, session=admin)
    ok('...and it is read back from one', (status, store.user_prefs('boss')),
       (200, {'lang': 'en'}))
    status, said = call('/api/auth/prefs', 'POST', {'prefs': {'lang': ''}}, session=admin)
    ok('chosen as nothing: gone, English as it comes', store.user_prefs('boss'), {})
    daemon.drop_user('watcher', by='test') if hasattr(daemon, 'drop_user') else \
        store.drop_user('watcher')
    ok('an account removed takes its choice with it',
       store.db.execute("SELECT COUNT(*) AS n FROM user_prefs WHERE name='watcher'")
       .fetchone()['n'], 0)
finally:
    api.stop() if hasattr(api, 'stop') else None
    shutil.rmtree(folder, ignore_errors=True)


print('\nThe page')
ok('the words are swapped before the page is shown, and it is never left hidden',
   ('i18n-wait' in PAGE_SRC, 'setTimeout(release, 2500)' in PAGE_SRC), (True, True))
ok('a table is kept under its English headings, whatever the language',
   'said += srcText(n);' in PAGE_SRC)
ok('the explanations of columns and tags are looked up in English',
   ('COLUMN_SAYS[(srcText(th)' in PAGE_SRC
    or 'COLUMN_SAYS[(th.dataset.words || colsLabel(th) || srcText(th)' in PAGE_SRC,
    'TAG_SAYS[(srcText(tag)' in PAGE_SRC), (True, True))
ok('data is never translated: inputs, code, .mono, data-no-i18n',
   all(x in PAGE_SRC for x in ("INPUT: 1", "contains('mono')", "data-no-i18n")))
ok('a tag the code keeps (an id, a class) is never swapped away',
   'if (k.attributes && k.attributes.length) return' in PAGE_SRC)
ok('the language is chosen under the person\'s own name', "pickLang.id = 'me-lang'" in PAGE_SRC)
print('\nWhat 1.10.155 put right')
ok('a name in a pattern\'s slot is never translated: one word is a name',
   "if (!/\\S\\s+\\S/.test(got.trim())) return got;" in PAGE_SRC)
ok('a slot does not reach across a " · " unless its pattern has one',
   'var across = ' in PAGE_SRC)
ok('no lookbehind in a literal (it stopped the whole page on older Safari)',
   ('(?<=[.!?:;])' in PAGE_SRC, "replace(/([.!?:;])\\s+/g, '$1\\u0001')" in PAGE_SRC),
   (False, True))
ok('sorting and the explanations of columns read the English',
   ("var t = String(srcText(td) || '')" in PAGE_SRC, 'text += srcText(bit);' in PAGE_SRC),
   (True, True))
ok('notes, names, groups and the installation\'s name are kept out of it',
   all(x in PAGE_SRC for x in ("noI18n(el('td', '', r.note || ''))", '<h1 data-no-i18n>',
                               "gname.setAttribute('data-no-i18n', '')",
                               "o.setAttribute('data-no-i18n', '')")))
ok('...and attributes are looked at on the element itself',
   '(!checked && i18nAttrsSkip(el))) return;' in PAGE_SRC)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
