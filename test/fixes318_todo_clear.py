#!/usr/bin/env python3
"""1.10.318: Clear beside "Done lately" under Settings -> Upgrades - the rows
the pane shows emptied, what is still to be done by hand never touched.

    ./test/fixes318_todo_clear.py
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


work = Path(tempfile.mkdtemp(prefix='isemon-318-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)

    class D(object):
        version = isemon.__version__
    d = D()
    d.store = st

    def fill():
        st.set_meta('todo_done', json.dumps([
            {'title': 'A', 'how': 'done', 'who': 'boss', 'at': 1793986771.4},
            {'title': 'B', 'how': 'gone by itself', 'who': '', 'at': 1793980000.9},
            {'title': 'C', 'how': 'done', 'who': 'pin', 'at': 1793970000.0}]))
        st.set_meta('todo_seen', json.dumps({'root-parts': {'at': 1793990000, 'title': 'pending'}}))

    print('Clear with the rows the pane shows')
    fill()
    r = isemon.todo_api(d, {'do': 'clear', 'items': [['A', 1793986771], ['C', 1793970000]]}, 'boss')
    ok('only those rows go; a row the pane did not show stays',
       ([x['title'] for x in isemon.todo_view(st)['done']], r['gone']), (['B'], 2))
    ok('...the answer has the list as it is now and says how many', (r['done'][0]['title'], r['message']),
       ('B', 'done lately cleared (2)'))
    ok('...what is still to be done is never touched',
       sorted(json.loads(st.get_meta('todo_seen') or '{}')), ['root-parts'])
    rows, _n = st.events(limit=20, text='done lately')
    ok('...in Events, who and how many', [(e['detail'], e['who']) for e in rows][:1],
       [('"done lately" cleared by boss (2)', 'boss')])
    print('\nClear with nothing named (the command line): all of it')
    fill()
    r = isemon.todo_api(d, {'do': 'clear'}, '')
    ok('every row gone, how many said', (isemon.todo_view(st)['done'], r['gone']), ([], 3))
    ok('...what is still to be done stays', sorted(json.loads(st.get_meta('todo_seen') or '{}')),
       ['root-parts'])
    print('\nWhat the page sends that is not a row')
    fill()
    r = isemon.todo_api(d, {'do': 'clear', 'items': [['A'], 'x', ['B', 'not a time'], None]}, 'boss')
    ok('nothing that is not [title, at] takes a row away', (r['gone'], len(r['done'])), (0, 3))
    r = isemon.todo_api(d, {'do': 'clear', 'items': []}, 'boss')
    ok('an empty list takes nothing away (not "all of it")', (r['gone'], len(r['done'])), (0, 3))
    try:
        isemon.todo_api(d, {'do': 'wipe'}, 'boss')
        ok('another do: refused', False)
    except ValueError:
        ok('another do: refused', True)

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('Clear sits in the heading of Done lately, drawn only with its rows',
       ("var head = el('div', 'todo-done-head');" in page,
        "cmdButton('Clear', 'trash', 'small todo-done-clear')" in page,
        page.index("if (!done.length) return;") < page.index("cmdButton('Clear', 'trash'")),
       (True, True, True))
    ok('...and sends the rows it shows, never all of it',
       "api('todo', {do: 'clear', items: shown.map(" in page)
    ok('the tooltip says what stays', "'Empty this list - what is still to be done stays'" in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
