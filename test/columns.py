#!/usr/bin/env python3
"""Columns laid out by hand: kept with the account, put back on request.

From 1.10.145 every table with a heading can be laid out by whoever is
looking - columns made wider or narrower, moved - and the layout is kept
with their account (`user_cols`) rather than in one browser. Here, through
the daemon's own API: anybody signed in keeps their own and only their own,
a read-only account included; the page is handed it with who is asking; what
is kept is only what a layout can hold, and never more than the cap; a full
admin can put somebody's back, nobody else can; and an account removed takes
its layout with it. Then the page: the module is there, sorting goes by the
column rather than its position, and the watcher that kept a table ordered
no longer orders it for ever.

    ./test/columns.py
"""
import json
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
API_SRC = (HERE.parent / 'web' / 'isemon-api.php').read_text(encoding='utf-8')
PASS = FAIL = 0
PORT = 19874


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


folder = tempfile.mkdtemp(prefix='isemon-columns-')
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
print('  (engine: %s)' % store.dialect.name)

LAYOUT = {'t-table:abc': {'w': {'source': 420, 'when': 150.4}, 'o': ['when', 'source'],
                          't': 1790000000},
          'users-list:x1': {'o': ['name', 'role']}}

try:
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    status, data = call('/api/auth/login', 'POST', {'name': 'watcher',
                                                    'password': 'another-long-password'})
    looker = data['token']

    print('\nSomebody who has laid nothing out')
    status, said = call('/api/auth/whoami', session=looker)
    ok('the page is told: nothing, every table as it comes', said.get('cols'), {})
    status, said = call('/api/auth/whoami')
    ok('nobody signed in is told nothing', (said.get('who'), said.get('cols')), (None, {}))

    print('\nThe switch: off at every sign-in, for that sign-in only (1.10.146)')
    status, said = call('/api/auth/whoami', session=looker)
    ok('a fresh sign-in may not change the columns', said.get('cols_edit'), False)
    status, said = call('/api/auth/columns', 'POST', {'cols': LAYOUT}, session=looker)
    ok('...so a layout sent without the switch is refused, and nothing is kept',
       (status, store.user_cols('watcher')), (409, {}))
    status, said = call('/api/auth/columns', 'POST', {'edit': True}, session=looker)
    ok('switched on, a read-only account included', (status, said.get('edit')), (200, True))
    status, said = call('/api/auth/whoami', session=looker)
    ok('...and the page is told so with who it is', said.get('cols_edit'), True)
    status, said = call('/api/auth/whoami', session=admin)
    ok('...for that sign-in only, not the next person', said.get('cols_edit'), False)
    ok('...held in memory only, never in the database',
       store.db.execute('SELECT COUNT(*) AS n FROM user_cols').fetchone()['n'], 0)

    print('\nKeeping a layout')
    status, said = call('/api/auth/columns', 'POST', {'cols': LAYOUT}, session=looker)
    ok('a read-only account keeps its own layout (it changes nothing anybody else sees)',
       (status, said.get('ok'), said.get('tables')), (200, True, 2))
    status, said = call('/api/auth/whoami', session=looker)
    ok('...and is handed it back with who it is, widths as whole pixels',
       said.get('cols', {}).get('t-table:abc', {}).get('w'), {'source': 420, 'when': 150})
    ok('...and the order as it was set',
       said.get('cols', {}).get('t-table:abc', {}).get('o'), ['when', 'source'])
    status, said = call('/api/auth/whoami', session=admin)
    ok('somebody else is not handed it', said.get('cols'), {})
    status, said = call('/api/auth/columns', 'POST', {'cols': LAYOUT})
    ok('nobody signed in may keep anything', status, 401)

    print('\nColumns put away and empty ones added (1.10.149)')
    call('/api/auth/columns', 'POST', {'edit': True}, session=looker)
    status, said = call('/api/auth/columns', 'POST', {'cols': {'ov-logs:k': {
        'h': ['behind', 7, {'x': 1}], 's': ['~1', '~no', 'x', '~22'],
        'o': ['file', '~1', 'records'], 'w': {'~1': 48}}}}, session=looker)
    kept = store.user_cols('watcher').get('ov-logs:k', {})
    ok('kept: which are put away, by name', kept.get('h'), ['behind', '7'])
    ok('...and the empty columns, `~` and a number and nothing else', kept.get('s'),
       ['~1', '~22'])
    ok('...standing in the order with the rest, with widths of their own',
       (kept.get('o'), kept.get('w')), (['file', '~1', 'records'], {'~1': 48}))
    call('/api/auth/columns', 'POST', {'cols': LAYOUT}, session=looker)

    print('\nOnly what a layout can hold')
    call('/api/auth/columns', 'POST', {'edit': True}, session=admin)
    status, said = call('/api/auth/columns', 'POST', {'cols': {
        'a': {'w': {'x': 'wide', 'y': 1, 'z': 99999}, 'o': ['p', {'evil': 1}, 3], 'junk': 'x'},
        'b': 'not a table', 'c': {'nothing': True}}}, session=admin)
    kept = store.user_cols('boss')
    ok('a width that is not a number is dropped, the rest held within reason',
       kept.get('a', {}).get('w'), {'y': 24, 'z': 3000})
    ok('...an order is names and nothing else', kept.get('a', {}).get('o'), ['p', '3'])
    ok('...and what is not a layout at all is not kept', sorted(kept), ['a'])
    status, said = call('/api/auth/columns', 'POST', {'cols': 'a string'}, session=admin)
    ok('a layout that is not one is refused', (status, said.get('ok')), (400, False))
    big = {'t%d' % i: {'w': {'c%02d' % j: 100 for j in range(60)}} for i in range(200)}
    status, said = call('/api/auth/columns', 'POST', {'cols': big}, session=admin)
    ok('one too big to keep is refused, and what was kept stays',
       (status, sorted(store.user_cols('boss'))), (400, ['a']))

    print('\nPutting it back')
    status, said = call('/api/users', session=admin)
    ok('the accounts page is told how many tables each has laid out',
       said.get('cols'), {'boss': 1, 'watcher': 2})
    status, said = call('/api/users', session=looker)
    ok('...a read-only account only its own', said.get('cols'), {'watcher': 2})
    ok('...and either is told which directory groups give which role (1.10.147)',
       sorted(said.get('role_groups') or {}), ['banadmin', 'fulladmin', 'readonly'])  # 1.10.165: three roles
    status, said = call('/api/users', 'POST', {'reset_cols': 'boss'}, session=looker)
    ok('a read-only account cannot put anybody’s back', status, 403)
    status, said = call('/api/users', 'POST', {'reset_cols': 'watcher'}, session=admin)
    ok('a full admin puts somebody’s back', (status, store.user_cols('watcher')),
       (200, {}))
    ok('...and it is in the events, by whom',
       any('put back as they come for watcher' in str(dict(e).get('detail') or '')
           and dict(e).get('who') == 'boss' for e in store.events(limit=20)[0]), True)
    status, said = call('/api/users', 'POST', {'reset_cols': 'nobody-here'}, session=admin)
    ok('...not for an account that is not there', status, 404)
    status, said = call('/api/auth/columns', 'POST', {'cols': {}, 'reset': True},
                        session=admin)
    ok('anybody puts their own back', (status, store.user_cols('boss')), (200, {}))
    ok('...and nothing is left in the table for them',
       store.db.execute("SELECT COUNT(*) AS n FROM user_cols WHERE name='boss'")
       .fetchone()['n'], 0)

    print('\nThe switch goes off again')
    call('/api/auth/columns', 'POST', {'edit': False}, session=admin)
    status, said = call('/api/auth/whoami', session=admin)
    ok('switched off by hand', said.get('cols_edit'), False)
    status, said = call('/api/auth/columns', 'POST', {'cols': {}, 'reset': True},
                        session=admin)
    ok('...and putting them back still works with it off', status, 200)
    call('/api/auth/columns', 'POST', {'edit': True}, session=admin)
    call('/api/auth/logout', 'POST', {}, session=admin)
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    status, said = call('/api/auth/whoami', session=admin)
    ok('signing out and in again: off', said.get('cols_edit'), False)
    call('/api/auth/columns', 'POST', {'edit': True}, session=admin)
    restarted = isemon.Daemon(store)
    ok('a restart of the service: off (a new daemon knows of no sign-in switched on)',
       restarted.cols_editing(admin), False)
    ok('...while the sign-in itself still stands', bool(restarted.who(admin)), True)
    isemon.CONFIG['session_idle_min'] = 1
    store.db.execute('UPDATE sessions SET seen=seen-3600')
    store.db.commit() if hasattr(store.db, 'commit') else None
    ok('a sign-in that runs out: gone, and its switch with it',
       (daemon.who(admin), daemon.cols_editing(admin)), (None, False))
    isemon.CONFIG['session_idle_min'] = isemon.DEFAULTS.get('session_idle_min', 120)

    print('\nOne\u2019s own settings to a file and back (1.10.148)')
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    call('/api/auth/columns', 'POST', {'edit': True}, session=admin)
    call('/api/auth/columns', 'POST', {'cols': LAYOUT}, session=admin)
    status, said = call('/api/auth/settings', session=admin)
    ok('read as a file would hold them: whose, and the columns',
       (status, said.get('name'), sorted(said.get('settings', {}).get('columns', {}))),
       (200, 'boss', ['t-table:abc', 'users-list:x1']))
    ok('...and nothing about the account itself (the search history joined in 1.10.151)',
       sorted(said.get('settings', {})), ['columns', 'prefs', 'search'])
    exported = said['settings']
    call('/api/auth/columns', 'POST', {'cols': {}, 'reset': True}, session=admin)
    call('/api/auth/logout', 'POST', {}, session=admin)
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    status, said = call('/api/auth/settings', 'POST',
                        {'settings': dict(exported, theme={'x': 1})}, session=admin)
    ok('read back from the file - with the columns switch off, it is asked for on purpose',
       (status, said.get('took'), said.get('ignored')),
       (200, {'columns': 2, 'search': 0, 'prefs': 0}, ['theme']))
    ok('...and the layout is exactly what was saved',
       store.user_cols('boss').get('t-table:abc', {}).get('w'), {'source': 420, 'when': 150})
    status, said = call('/api/auth/settings', 'POST', {'settings': {'theme': 1}},
                        session=admin)
    ok('a file with nothing this version keeps is refused, and says what it held',
       (status, 'theme' in said.get('error', '')), (400, True))
    status, said = call('/api/auth/settings', 'POST', {'nothing': 1}, session=admin)
    ok('...as is something that is not a file of settings at all', status, 400)
    status, said = call('/api/auth/settings', 'POST',
                        {'settings': {'columns': 'not a layout'}}, session=admin)
    ok('...and columns that are not a layout', (status, bool(store.user_cols('boss'))),
       (400, True))
    status, said = call('/api/auth/settings', 'POST', {'settings': exported})
    ok('nobody signed in may read anything back', status, 401)
    ok('the page saves them as a file and reads one back, through its own door',
       "'my-settings' => '/api/auth/settings'," in PAGE_SRC
       and 'function meExport(button)' in PAGE_SRC and 'function meImport(file)' in PAGE_SRC
       and "var ME_FILE_KIND = 'isemon-user-settings';" in PAGE_SRC, True)

    print('\nWhat somebody has looked for in the find box (1.10.151)')
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    for said in ('10.1.2.3', 'novak', '10.1.2.3', '  10.1.2.3 ', 'x'):
        call('/api/auth/finds', 'POST', {'add': said}, session=admin)
    status, said = call('/api/auth/whoami', session=admin)
    ok('the page is handed them with who is asking, the most used first, one search once '
       'whatever its spaces; one letter is not a search',
       [(f[0], f[1]) for f in said.get('finds', [])], [('10.1.2.3', 3), ('novak', 1)])
    status, said = call('/api/auth/finds', 'POST', {'drop': 'NOVAK'}, session=admin)
    ok('one taken out, whatever its capitals', [f[0] for f in said.get('finds', [])],
       ['10.1.2.3'])
    many = [['q%03d' % i, 1, i] for i in range(200)]
    store.put_user_finds('boss', many + [['kept', 50, 0]])
    ok('never more than are kept, the most used always among them',
       (len(store.user_finds('boss')), store.user_finds('boss')[0][0]),
       (store.FINDS_KEPT, 'kept'))
    status, said = call('/api/auth/settings', session=admin)
    ok('they are part of one’s own settings in a file',
       len(said.get('settings', {}).get('search', [])), store.FINDS_KEPT)
    status, said = call('/api/auth/finds', 'POST', {'clear': True}, session=admin)
    ok('cleared in one go', (said.get('finds'), store.user_finds('boss')), ([], []))
    status, said = call('/api/auth/settings', 'POST',
                        {'settings': {'search': [['from a file', 4, 1.0], 'and another']}},
                        session=admin)
    ok('...and read back from one', (said.get('took'), [f[0] for f in store.user_finds('boss')]),
       ({'search': 2}, ['from a file', 'and another']))
    status, said = call('/api/auth/finds', 'POST', {'add': 'x y'})
    ok('nobody signed in has any', status, 401)
    ok('the page shows the most used few under a line, each with its cross, and remembers a '
       'search acted on or looked at, not every letter typed',
       'function findHistoryInto(host)' in PAGE_SRC and 'var FINDS_SHOWN = 8;' in PAGE_SRC
       and "findRemember($('findinput').value);" in PAGE_SRC
       and "var wipe = cmdButton('Clear my search history', 'forget', 'small');" in PAGE_SRC,
       True)

    print('\nAn account removed')
    call('/api/auth/columns', 'POST', {'edit': True}, session=looker)
    call('/api/auth/columns', 'POST', {'cols': LAYOUT}, session=looker)
    ok('(it was kept)', bool(store.user_cols('watcher')), True)
    daemon.drop_user('watcher', by='test')
    ok('...and its search history', store.db.execute(
        "SELECT COUNT(*) AS n FROM user_finds WHERE name='watcher'").fetchone()['n'], 0)
    ok('takes its layout with it',
       store.db.execute("SELECT COUNT(*) AS n FROM user_cols WHERE name='watcher'")
       .fetchone()['n'], 0)
    ok('the table is one of this program’s own (backed up, moved, wiped with the rest)',
       'user_cols' in isemon.Dialect.schema_tables(isemon.SCHEMA), True)

    print('\nThe page')
    ok('it is handed the layout with who is signed in, as an object even when empty',
       "$who['cols'] = (is_array($cols) && $cols) ? $cols : new stdClass();" in API_SRC, True)
    ok('...and saves through its own door', "'columns'      => '/api/auth/columns'," in PAGE_SRC,
       True)
    ok('every table with one row of headings is laid out as it is drawn, before it is '
       'painted', 'function colsApply(table)' in PAGE_SRC
       and 'watch.observe(document.body, {childList: true, subtree: true});' in PAGE_SRC, True)
    ok('...a grip to size a column and the heading to carry it - only while switched on',
       '.col-grip{position:absolute;' in PAGE_SRC and 'th.draggable = COLS_EDIT;' in PAGE_SRC
       and 'body.cols-editing .col-grip{display:block}' in PAGE_SRC
       and 'z-index:4;touch-action:none;display:none}' in PAGE_SRC, True)
    ok('...the table never wider than its card: widths as shares, what one column gains '
       'the others give up, none below its longest line',
       "th.style.width = px[at] ? (px[at] / sum * 100).toFixed(4) + '%' : '';" in PAGE_SRC
       and 'function colsNatural(table, head)' in PAGE_SRC
       and "table.style.width = 'max(100%" not in PAGE_SRC, True)
    ok('...the right button on a heading, while editing: hide one, bring any back, add or '
       'take away an empty one, the whole table back (1.10.149)',
       "th.addEventListener('contextmenu', function (e) {" in PAGE_SRC
       and 'if (!COLS_EDIT) return;\n      e.preventDefault();' in PAGE_SRC
       and 'function colsMenu(x, y, table, th)' in PAGE_SRC
       and 'function colsAddSpacer(table, th, after)' in PAGE_SRC
       and 'function colsDropSpacer(table, id)' in PAGE_SRC
       and 'function colsHide(table, ck, away)' in PAGE_SRC
       and 'table .col-hidden{display:none !important}' in PAGE_SRC, True)
    ok('...and on any cell of the table, not only its heading (1.10.152)',
       "var cell = e.target.closest('td, th');" in PAGE_SRC
       and 'colsMenu(e.clientX, e.clientY, table, th);' in PAGE_SRC, True)
    ok('...never every column away', 'if (hid.length >= n) { hidden = {}; hid = []; }'
       in PAGE_SRC, True)
    ok('the Logs table has the columns `isemon --status` prints, and names itself so a '
       'layout outlives a column added', 'id="ov-logs" data-cols-key="logs"' in PAGE_SRC
       and '>What is in it</th>' in PAGE_SRC and '>Last read</th>' in PAGE_SRC
       and '>Not read yet</th>' in PAGE_SRC and '>Trouble</th>' in PAGE_SRC, True)
    ok('the logins of the other doors have a heading for every cell their rows carry',
       "other: ['When', 'Name', addrHeads(), 'Profile', 'Device', 'Tunnel', 'Firewall', "
       "'Node', '']," in PAGE_SRC, True)
    ok('...its width in a pill at the foot of the window while it is dragged',
       'function colsSizeSay(th, px)' in PAGE_SRC, True)
    ok('...saved the moment it is let go of, one save after another',
       'COLS_SOON = (COLS_SOON || Promise.resolve()).then(send, send);' in PAGE_SRC, True)
    ok('the name at the top right is a button that opens the account: the switch, the '
       'reset, the password for a local account only', 'id="me-btn"' in PAGE_SRC
       and 'function showMe()' in PAGE_SRC and "box.id = 'me-cols-edit';" in PAGE_SRC
       and "back.id = 'me-cols-reset';" in PAGE_SRC and 'if (ME.from_dir) {' in PAGE_SRC
       and 'id="mypassword"' not in PAGE_SRC, True)
    ok('...the groups once each, by name, with where they live and which give the role; the '
       'place in the directory as a path (1.10.147)', 'function meGroups(said)' in PAGE_SRC
       and 'function dnPlace(dn)' in PAGE_SRC and "'medium');" in PAGE_SRC, True)
    ok('...the whole list from the directory itself when it answers, compact: the ones that '
       'give the role as cards, the rest a line of names, past 18 behind "and N more" '
       '(1.10.149)', 'function meDrawGroups(cell, label, found, gives, live)' in PAGE_SRC
       and "api('who&name=' + encodeURIComponent(ME.name))" in PAGE_SRC
       and 'var SHOW = 18;' in PAGE_SRC, True)
    ok('ordering goes by the column, wherever it stands now',
       'cellSortValue(cellOf(g[0], st.col))' in PAGE_SRC
       and PAGE_SRC.count('var col = colOf(th, at);') == 2, True)
    ok('a table ordered on the page is no longer ordered again for ever (froze the page)',
       'if (same) return;' in PAGE_SRC
       and 'table._sortWatch.takeRecords();' in PAGE_SRC, True)
    ok('Settings, Accounts: put my own back, and a full admin anybody’s',
       'id="cols-reset"' in PAGE_SRC and "api('users', {reset_cols: whose})" in PAGE_SRC, True)
finally:
    api.stop()
    shutil.rmtree(folder, ignore_errors=True)

print('\nColumns kept out of sight until asked for (1.10.156)')
kept = isemon.Storage.clean_cols({'t-table:x': {'v': ['source interface', 'protocol', 7, {}],
                                                'h': ['service']}})
ok('a layout keeps which of them somebody switched on',
   kept['t-table:x'].get('v'), ['source interface', 'protocol', '7'])
ok('the page hides them unless switched on, and names a table without them',
   ("c.hasAttribute('data-cols-optional') && !asked[c.dataset.ck]" in PAGE_SRC,
    "byCi.filter(function (th) { return !th.hasAttribute('data-cols-optional'); })"
    in PAGE_SRC), (True, True))
ok('...so a layout saved before they existed is still the same table\'s',
   "return where + ':' + colsHash(named.join('|'));" in PAGE_SRC)
ok('switching one on and off goes into what is kept',
   "if (!away) v.push(ck);" in PAGE_SRC)
ok('every Traffic page offers the rest of a line, and the main lists their records',
   all(x in PAGE_SRC for x in ('var T_OPTIONAL = [', "optColumns($('f-table'), OPT_AUTH);",
                               "optColumns($('p-table'), OPT_PASSED);",
                               "optColumns($('past-table'), OPT_PAST);",
                               "optColumns($('ev-table'), OPT_EVENTS);",
                               "optColumns($('w-table'), OPT_WIN);",
                               'optColumns(table, optFieldsOf(rows));')))
ok('...each one born out of sight', "el('th', 'col-hidden', d[0])" in PAGE_SRC)

print('\n...and drawn as the rest of the page draws the same thing (1.10.157)')
import re                                            # noqa: E402
opt_src = PAGE_SRC[PAGE_SRC.index('var OPT_AUTH = ['):PAGE_SRC.index('function optFieldsOf(')]
drawn = {}
for field, kind in re.findall(r"\['[^']+', '(\w+)'(?:, '(\w+)')?\]", opt_src):
    drawn.setdefault(field, set()).add(kind)
for field, kind in re.findall(r"(\w+): \['[^']+'(?:, '(\w+)')?\]", opt_src):
    drawn.setdefault(field, set()).add(kind)
ok('a country, wherever it can be switched on, with its flag', drawn.get('country'), {'cc'})
ok('an address with its name', drawn.get('ip'), {'addr'})
ok('a name with the button that asks the directory', drawn.get('username'), {'name'})
ok('a moment as every other moment', drawn.get('ts') | drawn.get('ended'), {'time'})
ok('yes and no as a tag', drawn.get('auto'), {'yes'})
ok('the renderer has each of those',
   all("kind === '%s'" % k in PAGE_SRC for k in ('cc', 'fgcc', 'addr', 'name', 'time', 'yes',
                                                 'door', 'bytes', 'span', 'num', 'mono')))
ok('...a firewall country with its flag too, and its traffic the same way',
   ("optCell('fgcc', r.srccountry)" in PAGE_SRC, "optCell('fgcc', r.dstcountry)" in PAGE_SRC,
    "optCell('name', r.user, r)" in PAGE_SRC, 'tPlainCell(r.' not in PAGE_SRC),
   (True, True, True, True))

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
