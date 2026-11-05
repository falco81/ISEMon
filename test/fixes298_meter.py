#!/usr/bin/env python3
"""1.10.298: the performance meter of the header.

- How busy this server is - CPU, memory, the disks, the network - for a full
  admin, off unless they choose a look under Your account; off, the page
  asks the daemon nothing.
- GET /api/load: the summary, `detail=1` each core, sensor, disk, card and
  the processes taking most, `hist=1` the last two minutes - kept by the
  daemon from the readings asked for anyway, so after F5 the graphs go on
  where they were rather than starting again.

    ./test/fixes298_meter.py
"""
import os
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


work = Path(tempfile.mkdtemp(prefix='isemon-298-'))
try:
    print('What the daemon reads')
    isemon.LOAD_LAST.update(at=0.0, raw=None, out=None)
    isemon.LOAD_HIST.clear()
    first = isemon.api_load()
    ok('the first ask: no rates yet, the memory there',
       ('cpu' in first, bool(first.get('mem_total'))), (False, True))
    time.sleep(1.1)
    two = isemon.api_load()
    ok('...the second: the processor, the disks and the network as rates',
       all(k in two for k in ('cpu', 'disk_rd', 'disk_wr', 'net_rx', 'net_tx', 'over_s')))
    ok('...and one reading kept for the graphs', len(isemon.load_history()), 1)
    time.sleep(1.1)
    isemon.api_load()
    ok('readings closer than 2.5 s apart are one in the graphs', len(isemon.load_history()), 1)
    isemon.LOAD_HIST[-1]['at'] -= 3
    time.sleep(1.1)
    got = isemon.api_load(hist=True)
    ok('...further apart, two - handed back with hist=1, oldest first',
       (len(got['hist']), got['hist'][0]['at'] < got['hist'][1]['at']), (2, True))
    ok('...each with what the four graphs draw', sorted(got['hist'][-1]),
       ['at', 'cpu', 'disk', 'mem', 'net'])
    isemon.LOAD_HIST[0]['at'] -= 600
    ok('older than two minutes: not handed back', len(isemon.load_history()), 1)
    detail = isemon.api_load(detail=True)['detail']
    ok('the details: each core, the disks, the filesystems, the cards, the processes',
       all(k in detail for k in ('cores', 'disks', 'filesystems', 'nics', 'top_cpu', 'top_mem',
                                 'mem', 'temps', 'uptime')) and len(detail['cores']) >= 1)

    print('\nThe sensors')
    sysfs = work / 'sys'
    for d, files in {
            'class/hwmon/hwmon0': {'name': 'coretemp', 'temp1_input': '61000',
                                   'temp1_label': 'Package id 0', 'temp2_input': '55000',
                                   'temp2_label': 'Core 0'},
            'class/hwmon/hwmon1': {'name': 'acpitz', 'temp1_input': '40000'},
            'class/hwmon/hwmon2': {'name': 'k10temp', 'temp1_input': '999000'}}.items():
        (sysfs / d).mkdir(parents=True)
        for f, v in files.items():
            (sysfs / d / f).write_text(v + '\n')
    was = isemon.LOAD_SYS
    isemon.LOAD_SYS = str(sysfs)
    t = isemon.load_temps()
    isemon.LOAD_SYS = was
    ok('the package, a core, another sensor - and one beyond 150 °C left out',
       (t['cpu'], t['cores'], t['other']), ([['Package id 0', 61.0]], {0: 55.0}, [['acpitz', 40.0]]))

    print('\nWhat a person chooses')
    clean = isemon.Storage.clean_prefs
    ok('a look and a style of the details kept, the language beside them',
       clean({'lang': 'cs', 'hload': 'graphs', 'hpanel': 'map'}),
       {'lang': 'cs', 'hload': 'graphs', 'hpanel': 'map'})
    try:
        clean({'hload': 'fireworks'})
        ok('a look there is not: refused', False)
    except isemon.StorageError as e:
        ok('a look there is not: refused, and said', 'not one of' in str(e))

    print('\nThe API and the page')
    src = (ROOT / 'isemon.py').read_text()
    a = src.index("if path == '/api/load':")
    ok('GET /api/load for a full admin alone', 'me = self.need_admin()' in src[a:a + 600])
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('relayed to the daemon as a read', "'load'           => '/api/load'," in page)
    ok('in the header for a full admin only',
       "<?php if (($me['role'] ?? '') === 'fulladmin'): ?>\n  <div class=\"hload\" id=\"hload\""
       in page)
    ok('off unless chosen: nothing asked of the daemon while it is',
       ("HLOAD.look = hlPrefs().hload || 'off';" in page,
        "if (HLOAD.look === 'off') { $('hload').hidden = true; return; }" in page), (True, True))
    ok('the choice kept with the account', "return api('prefs', {prefs: change})" in page)
    ok('after F5 the last two minutes asked for, and drawn from',
       ("(withHist ? '&hist=1' : '')" in page, 'if (d.hist && d.hist.length) {' in page),
       (True, True))
    ok('chosen under Your account', 'hloadPickers(meter);' in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
