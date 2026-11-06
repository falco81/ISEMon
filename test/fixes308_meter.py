#!/usr/bin/env python3
"""1.10.308: the performance meter asked in step with the daemon, every
reading on the graphs, and the last state drawn at once.

    ./test/fixes308_meter.py
"""
import json
import shutil
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


page = (ROOT / 'web' / 'index.php').read_text()
work = Path(tempfile.mkdtemp(prefix='isemon-308-'))
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
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'perf_meter': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    node = isemon.load_node()
    now = time.time()
    for i, at in enumerate((now - 20, now - 15, now - 10, now - 5)):
        store.load_note(node, {'at': at, 'cpu': 10 + i, 'mem': 40.0, 'disk': 100 * i, 'net': 7})

    print('The first ask after a quiet while')
    isemon.LOAD_LAST.update(at=0.0, raw=None, out=None)
    isemon.LOAD_WATCH['asked'] = 0.0
    got = isemon.api_load(store=store)
    ok('no rate of its own yet: the newest reading written down stands in',
       (got.get('cpu'), (got.get('written') or {}).get('cpu')), (13, 13))

    print('\nEvery reading since the one the page has')
    got = isemon.api_load(store=store, since=now - 12)
    ok('the two after it, oldest first', [x['cpu'] for x in got.get('more') or []], [12, 13])
    ok('...none when it has the newest', isemon.api_load(store=store, since=now - 1).get('more'), [])
    ok('the first ask has the two minutes, not "more"',
       ('hist' in isemon.api_load(store=store, hist=True, since=now - 12),
        'more' in isemon.api_load(store=store, hist=True, since=now - 12)), (True, False))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\nThe page')
ok('asked again just after the daemon reads next',
   "if (d.next && d.now) hloadSoon(1000 * (d.next - d.now) + 600);" in page)
ok('...with the moment of the newest reading it has', "['&since', newest.toFixed(2)].join('=')" in page)
ok('the last state kept in this browser and drawn at once',
   ("var HLOAD_STORE = 'isemon-hload-v1';" in page, 'hloadFromKept();' in page), (True, True))
ok('...for the same person only, and not older than ten minutes',
   "got.who !== (ME && ME.name)" in page and '10 * 60000' in page)
ok('come back to: drawn again at once, then asked', "  hloadTick(true);\n});" in page)
ok('the same reading twice is drawn once', 'a[a.length - 1].t >= t - 0.5' in page)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
