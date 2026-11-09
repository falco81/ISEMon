#!/usr/bin/env python3
"""1.10.322: a save refused only for a rule the save itself breaks - not for
a pair of numbers saved before the rule existed (block_lots no bigger than
block_tries, from before 1.10.306), which stopped every save on every pane.

    ./test/fixes322_save_old_pair.py
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


work = Path(tempfile.mkdtemp(prefix='isemon-322-'))
try:
    isemon.DB_FILE = work / 'd.db'
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = work / 'config.json'
    st = isemon.Storage(isemon.DB_FILE)
    d = isemon.Daemon(st)
    # Saved before the rule: a burst of five out for good, five to a ban.
    isemon.CONFIG.update(block_tries=5, block_lots=5)

    def save(values):
        try:
            d._save_settings(values, by='test')
            return 'saved'
        except ValueError as e:
            return str(e)

    ok('something else entirely: saved, the old pair notwithstanding',
       (save({'winsec_ad2025': 1}), isemon.CONFIG.get('winsec_ad2025')), ('saved', 1))
    ok('...and a change to the banning that leaves the pair as it was: saved too',
       save({'block_minutes': 61}), 'saved')
    got = save({'block_tries': 6})
    ok('a change that breaks the rule itself: refused, said as before',
       'has to be bigger than' in got and '(6)' in got)
    got = save({'block_lots': 4})
    ok('...and one that makes the old pair worse: refused', 'has to be bigger than' in got)
    ok('putting it right: saved', save({'block_lots': 10}), 'saved')
    ok('...and from then on the rule holds for every save', 'has to be bigger than' in save(
        {'block_lots': 5}))
    ok('nothing broken before: the rule as it always was',
       'has to be bigger than' in save({'block_tries': 12}))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
