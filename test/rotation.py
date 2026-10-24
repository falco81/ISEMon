#!/usr/bin/env python3
"""
rotation.py - every way an ISE log gets rotated, against the daemon's own
reader.

Nothing here tests one function: it drives the whole read path the way
logrotate drives it - rename-and-create, copy-and-truncate, a rotation while
the daemon was stopped, a copy that has since been compressed, several
generations in a row - and then asks the one question that matters. Is every
record in the database exactly once, and is any record missing.

This is the part that cannot be checked by looking: a log that rotates at
midnight loses an hour of attempts silently, and the only sign is a number
that is lower than it should be on a page nobody is comparing against
anything.

    ./test/rotation.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                       # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def title(text):
    print('\n%s' % text)


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-rot-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'r.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'r.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    logs = Path(folder) / 'ise2'
    logs.mkdir()
    isemon.CONFIG['ise_paths'] = [str(logs)]
    isemon.CONFIG['blacklist'] = 0
    isemon.CONFIG['read_passed'] = 0
    store = isemon.Storage(isemon.DB_FILE)
    return folder, logs, store, isemon.Daemon(store)


SEQ = [0]


def line(host, cat, seq, of, n, rest):
    return '%s %s %s %010d %d %d %s' % ('Sep 23 13:27:47', host, cat, seq, of, n, rest)


def records(how_many, ip='203.0.113.9'):
    """Whole ISE records, each with a session id of its own."""
    out = []
    for _ in range(how_many):
        SEQ[0] += 1
        seq = SEQ[0]
        when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + '.500 +02:00'
        head = ('%s 0229674592 5400 NOTICE Failed-Attempt: Authentication failed, '
                'ConfigVersionId=86, Device IP Address=172.22.0.137, UserName=jnovak, '
                'Protocol=Radius, NetworkDeviceName=FTD-VPN, Calling-Station-ID=%s, '
                'AcsSessionID=ise2/569337134/%d,' % (when, ip, seq))
        two = ' AuthenticationMethod=PAP_ASCII, FailureReason=22056 Subject not found,'
        three = ' EndPointIPAddress=%s, Response={RadiusPacketType=AccessReject; }' % ip
        out += [line('ise2', 'CISE_Failed_Attempts', seq, 3, 0, head),
                line('ise2', 'CISE_Failed_Attempts', seq, 3, 1, two),
                line('ise2', 'CISE_Failed_Attempts', seq, 3, 2, three)]
    return out


def append(path, lines):
    with open(path, 'a') as f:
        f.write('\n'.join(lines) + '\n')


def count(store):
    return store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']


def sessions(store):
    return [r['session'] for r in store.db.execute('SELECT session FROM failed')]


# ---------------------------------------------------------------------------
title('logrotate the ordinary way: rename, make a new one')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(10))
daemon.restore_tails()
daemon.read_logs()
ok('the first read takes them all', count(store), 10)
append(live, records(5))               # written, not read yet
os.rename(str(live), str(live) + '.1')  # logrotate moves it aside
append(live, records(4))               # and the new file starts
daemon.read_logs()
ok('the five written before the move are not lost', count(store), 19)
ok('...and nothing is stored twice', len(set(sessions(store))), 19)
daemon.read_logs()
ok('reading again adds nothing', count(store), 19)

# ---------------------------------------------------------------------------
title('logrotate with copytruncate: copy it, then empty the original')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(10))
daemon.restore_tails()
daemon.read_logs()
append(live, records(6))               # written, not read yet
shutil.copy(str(live), str(live) + '.1')   # the copy keeps everything
open(str(live), 'w').close()               # and the original is emptied
append(live, records(3))
daemon.read_logs()
ok('the six in the copy are read', count(store), 19)
ok('...and none of the first ten is stored twice', len(set(sessions(store))), 19)
daemon.read_logs()
ok('reading again adds nothing', count(store), 19)

# ---------------------------------------------------------------------------
title('a rotation while the daemon is stopped')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(8))
daemon.restore_tails()
daemon.read_logs()
daemon.save_tails()
# ...the daemon stops here...
append(live, records(7))
os.rename(str(live), str(live) + '.1')
append(live, records(2))
# ...and starts again, with only what was written down to go on.
again = isemon.Daemon(store)
again.restore_tails()
again.read_logs()
ok('the seven written while it was down are read', count(store), 17)
ok('...exactly once each', len(set(sessions(store))), 17)

# ---------------------------------------------------------------------------
title('a rotation that compressed what it moved aside')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(9))
daemon.restore_tails()
daemon.read_logs()
append(live, records(5))
subprocess.run(['gzip', '-k', str(live)], check=True)
os.rename(str(live) + '.gz', str(live) + '.1.gz')
open(str(live), 'w').close()
append(live, records(3))
daemon.read_logs()
ok('the five in the compressed copy are read', count(store), 17)
ok('...exactly once each', len(set(sessions(store))), 17)

# ---------------------------------------------------------------------------
title('two rotations in a row')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(4))
daemon.restore_tails()
daemon.read_logs()
for round_n in range(3):
    append(live, records(3))
    if os.path.exists(str(live) + '.2'):
        os.remove(str(live) + '.2')
    if os.path.exists(str(live) + '.1'):
        os.rename(str(live) + '.1', str(live) + '.2')
    os.rename(str(live), str(live) + '.1')
    append(live, records(2))
    daemon.read_logs()
ok('every record from every generation is here', count(store), 4 + 3 * 5)
ok('...exactly once each', len(set(sessions(store))), 4 + 3 * 5)

# ---------------------------------------------------------------------------
title('the pass back over every log, run twice, over rotated files')
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(6))
append(Path(str(live) + '.1'), records(4))
append(Path(str(live) + '.2.gz.notgz'), records(2))   # a name it should still read
daemon.restore_tails()
daemon.read_logs()
first = daemon.rescan(read_files=True)
ok('the pass reads the rotated files too', count(store), 12)
ok('...and adds only what was missing', first['added'], 6)
second = daemon.rescan(read_files=True)
ok('a second pass adds nothing', second['added'], 0)
ok('...and the table is exactly as it was', count(store), 12)
ok('...with nothing stored twice', len(set(sessions(store))), 12)

# ---------------------------------------------------------------------------
title('stopped and started again: nothing lost, and it carries on')
folder, logs, store, daemon = fresh()
isemon.CONFIG['blacklist'] = 1
isemon.CONFIG['block_tries'] = 3
isemon.CONFIG['block_window_min'] = 60
isemon.CONFIG['block_bogus_tries'] = 0
isemon.CONFIG['feeds_ban'] = 0
isemon.CONFIG['judge_max_age_h'] = 0
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(4, ip='203.0.113.40'))
daemon.restore_tails()
daemon.read_logs()
was_banned = store.blocked_until('203.0.113.40') is not None
ok('it banned what it read', was_banned, True)
daemon.save_tails()
held = store.meta_json('tails', {})
ok('...and wrote down where it had read up to',
   any(v.get('offset') for v in held.values()), True)

# ...stopped. More arrives while nothing is running.
append(live, records(3, ip='203.0.113.41'))
append(live, records(2, ip='203.0.113.42'))

# ...and started again, with nothing but the database to go on.
again = isemon.Daemon(store)
again.restore_tails()
again.read_logs()
ok('what arrived while it was stopped is read', count(store), 9)
ok('...exactly once each', len(set(sessions(store))), 9)
ok('...and judged, not just written down',
   store.blocked_until('203.0.113.41') is not None, True)
ok('...while what was already judged is not judged again',
   store.blocked_until('203.0.113.40') is not None, True)
ok('the record count carries over rather than starting at nothing',
   sum(t.records for t in again._tails.values()), 9)
ok('...and so does when each file was last read',
   all(t.last_read for t in again._tails.values() if t.records), True)

# Nothing is read a third time.
again.read_logs()
ok('and a third start reads nothing again', count(store), 9)

# ---------------------------------------------------------------------------
title('the same record arriving from both ISE nodes')
folder, logs, store, daemon = fresh()
isemon.CONFIG['ise_paths'] = [str(logs), str(logs)]      # the same folder twice
live = logs / isemon.CONFIG['ise_failed_name']
append(live, records(5))
daemon.restore_tails()
daemon.read_logs()
ok('a file read down two paths is counted once', count(store), 5)

# ---------------------------------------------------------------------------
title('a rotated copy that has been compressed, read whole')
# The pass back over every log reads the rotated copies too, and a site that
# has been running a while has them compressed. It used to unpack the first
# 256 MB of one into memory and work from that copy - which cost most of a
# gigabyte on a busy site's log and, worse, stopped there: everything past
# 256 MB was silently not read. It is read a block at a time out of the file
# now, and the block is made small here so that a small file crosses several
# of them exactly as a real one crosses several of the real size.
import gzip                                              # noqa: E402
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
lines = records(400)
packed = Path(str(live) + '.1.gz')
with gzip.open(str(packed), 'wb') as f:
    f.write(('\n'.join(lines) + '\n').encode('utf-8'))
open(str(live), 'w').close()                             # the live one is empty
was, isemon.READ_BLOCK = isemon.READ_BLOCK, 4096
try:
    # What matters is how much comes OUT of it: the reader works on the
    # unpacked bytes, and this must cross several blocks of them.
    ok('what it unpacks to is bigger than several blocks',
       len(('\n'.join(lines) + '\n').encode('utf-8')) > 3 * isemon.READ_BLOCK)
    daemon.restore_tails()
    out = daemon.rescan(read_files=True)
    ok('every record in it is read, not the first block and no more',
       out['seen'], 400)
    ok('...and every one of them written down', count(store), 400)
    tail = isemon.LogTail(str(packed), parser=isemon.ise_parse_lines)
    got = 0
    for _ in range(10000):
        some = daemon.read_whole(tail)
        if not some:
            break
        got += len(some)
    ok('reading it by hand gives the same number', got, 400)
    ok('...and asking again once it is finished gives nothing rather than '
       'starting the file over', daemon.read_whole(tail), [])
    ok('...with the file handle let go', getattr(tail, 'packed', None), None)
finally:
    isemon.READ_BLOCK = was

# ...and the pass is idempotent over a compressed copy, as it is over a plain one
again = isemon.Daemon(store)
again.restore_tails()
out2 = again.rescan(read_files=True)
ok('a second pass over the same compressed copy adds nothing', out2['added'], 0)
ok('...having read every record again to find that out', out2['seen'], 400)

# ---------------------------------------------------------------------------
title('every naming and every packing at once, which is what a real folder is')
# A machine that has been running a while has two naming series beside each
# other - the day somebody adds or removes `dateext`, the old one stops being
# added to and stays where it is - and everything but the newest is packed.
# A full import has to take the lot, and it used to take twelve.
import bz2                                               # noqa: E402
import lzma                                              # noqa: E402
folder, logs, store, daemon = fresh()
live = logs / isemon.CONFIG['ise_failed_name']
want = 0
append(live, records(6)); want += 6

def packed(name, how, lines):
    out = Path(str(live) + name)
    text = ('\n'.join(lines) + '\n').encode('utf-8')
    if how is None:
        out.write_bytes(text)
    else:
        with how.open(str(out), 'wb') as f:
            f.write(text)
    return out

made = [packed('.1', None, records(5))]
want += 5
made.append(packed('.2.gz', gzip, records(5))); want += 5
made.append(packed('.3.bz2', bz2, records(5))); want += 5
made.append(packed('.4.xz', lzma, records(5))); want += 5
for day in range(1, 20):                                  # nineteen dateext days
    made.append(packed('-202609%02d.gz' % day, gzip, records(4)))
    want += 4
made.append(packed('-20260920', None, records(4))); want += 4

ok('more rotated copies than the twelve it used to stop at', len(made) > 12)
ok('...and every one of them is found',
   len(daemon.rotated_siblings(str(live))), len(made))
daemon.restore_tails()
out = daemon.rescan(read_files=True)
ok('a full import reads every record in every one of them', out['seen'], want)
ok('...and writes them all down', count(store), want)
ok('...whatever they are packed with',
   len({p.suffix for p in made}), 5)
again = isemon.Daemon(store)
again.restore_tails()
ok('a second full import adds nothing', again.rescan(read_files=True)['added'], 0)
ok('...and nothing is in there twice',
   len(sessions(store)), len(set(sessions(store))))

# ---------------------------------------------------------------------------
title('emptied in place and written again past where we were: copytruncate')
# The two tests for "this is not the file I was reading" are a changed inode
# and a file shorter than the offset. `copytruncate` defeats both: nothing is
# moved, so the inode holds, and a busy writer refills past the old offset
# before the next pass, so the file is not short either. Everything written up
# to that offset was skipped, silently. A fingerprint of the bytes just before
# the offset is what tells the two apart.
home = Path(tempfile.mkdtemp())
where = home / 'a.log'


def some(a, b):
    return ''.join('Sep 25 11:%02d:%02d ise2 CISE_Failed_Attempts %010d 1 0 x\n'
                   % (n // 60, n % 60, n) for n in range(a, b))


where.write_text(some(0, 30))
tail = isemon.LogTail(str(where), parser=lambda lines, hold: list(lines))
ok('the first pass reads what is there', len(tail.read()), 30)
ok('...and writes down a fingerprint of where it got to', bool(tail.mark), True)
(home / 'a.log.1').write_text(where.read_text())        # logrotate copies it aside
with open(where, 'r+') as f:
    f.truncate(0)                                       # ...and empties it in place
with open(where, 'a') as f:
    f.write(some(100, 190))                             # the writer carries on
ok('the file is now LONGER than where we had read, and the same file',
   where.stat().st_size > tail.offset, True)
ok('...and every line of it is read, not only the ones past the old offset',
   len(tail.read()), 90)
ok('...and the fingerprint is written down again for next time', bool(tail.mark), True)
# ...and the ordinary case is untouched: more lines added to the same file.
with open(where, 'a') as f:
    f.write(some(190, 200))
ok('a file simply carrying on is read from where it was, not from the beginning',
   len(tail.read()), 10)
# ...and a mark survives a restart, because that is where it has to work.
said = tail.state()
ok('the fingerprint is kept over a restart', bool(said.get('mark')), True)
back = isemon.LogTail(str(where), said['offset'], said['inode'], said['size'],
                      said['records'], said['hold'], said['read_at'],
                      parser=lambda lines, hold: list(lines), mark=said['mark'])
ok('...and a restart on an unchanged file reads nothing again', len(back.read()), 0)
with open(where, 'r+') as f:
    f.truncate(0)
with open(where, 'a') as f:
    f.write(some(300, 420))
ok('...while a restart on one emptied and refilled reads the lot', len(back.read()), 120)
shutil.rmtree(home, ignore_errors=True)

title('...and the same for a quiet log, read a line or two at a time')
# A read shorter than the fingerprint left it empty until 1.10.97, and an
# empty fingerprint is never checked: a copied-and-emptied token log refilled
# past the old offset was read on from the middle of its new lines.
home = Path(tempfile.mkdtemp())
where = home / 'q.log'
where.write_text(some(0, 2))
tail = isemon.LogTail(str(where), parser=lambda lines, hold: list(lines))
ok('a short first read', len(tail.read()), 2)
ok('...still leaves a fingerprint behind it', bool(tail.mark), True)
with open(where, 'a') as f:
    f.write(some(2, 3))
ok('...and so does the next line, read on its own', (len(tail.read()), bool(tail.mark)),
   (1, True))
(home / 'q.log.1').write_text(where.read_text())
with open(where, 'r+') as f:
    f.truncate(0)
with open(where, 'a') as f:
    f.write(some(500, 505))
ok('emptied and refilled past the offset, every new line is read', len(tail.read()), 5)
shutil.rmtree(home, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
