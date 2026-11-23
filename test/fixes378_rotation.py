#!/usr/bin/env python3
"""1.10.378: a log rotated two or more times while it was not being read -
the copies in between read whole, once - and a log path that is a link moved
on to a new file.

    ./test/fixes378_rotation.py
"""
import os, sys, tempfile, time, gzip, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import isemon
from pathlib import Path
d = tempfile.mkdtemp(prefix='isemon-378-')
BAD = []
isemon._LOG_PATH = Path(d)/'x.log'
def P(lines, hold=None, now=None):
    return [l.rstrip('\n') for l in lines if l.strip()]
def mk(p): return isemon.LogTail(p, parser=P)
def again(p, st): return isemon.LogTail(p, st['offset'], st['inode'], st['size'], st['records'], st['hold'], st['read_at'], parser=P, mark=st['mark'])
def w(p, s, mode='a'):
    with open(p, mode) as f: f.write(s)
def L(a,b,tag='L'): return ''.join('%s%06d %s\n' % (tag, i, 'x'*40) for i in range(a,b))
def Ls(a,b,tag='L'): return [x for x in L(a,b,tag).split('\n') if x]
def check(name, got, want):
    ok = sorted(got)==sorted(want) and len(got)==len(want)
    if not ok: BAD.append(name)
    print(('ok  ' if ok else 'BAD ')+name, '' if ok else 'got %d want %d missing %s dup %d' % (len(got), len(want), sorted(set(want)-set(got))[:3], len(got)-len(set(got))))
def drain(t, n=5):
    out=[]
    for _ in range(n): out += t.read()
    return out

def old(path, tag, n=3, packed=False):
    data = L(0, n, tag)
    if packed:
        with gzip.open(path, 'wt') as g: g.write(data)
    else: w(path, data, 'w')
    t0 = time.time() - 3*86400; os.utime(path, (t0, t0))
def gz(src, dst=None):
    dst = dst or src + '.gz'
    with open(src,'rb') as f, gzip.open(dst,'wb') as g: g.write(f.read())
    os.unlink(src)
def shift(p, n):            # logrotate numbering: .n-1 -> .n ...
    for i in range(n, 0, -1):
        for ext in ('', '.gz'):
            if os.path.exists('%s.%d%s' % (p, i, ext)):
                os.rename('%s.%d%s' % (p, i, ext), '%s.%d%s' % (p, i+1, ext))
def setup(name):
    p = os.path.join(d, name); os.makedirs(os.path.dirname(p), exist_ok=True)
    old(p+'.1', 'O1'); old(p+'.2', 'O2'); old(p+'.3.gz', 'O3', packed=True)
    w(p, L(0,3)); return p
def create(p):  shift(p, 4); os.rename(p, p+'.1')
def copytrunc(p):
    shift(p, 4); shutil.copyfile(p, p+'.1'); open(p,'w').close()
def run(name, body, want, down=True):
    p = setup(name); t = mk(p); got = t.read(); st = t.state()
    body(p)
    if down: t = again(p, st)
    got += drain(t, 6); check(name + (' (down)' if down else ' (running)'), got, want)

for down in (True, False):
    # single create rotation
    run('a%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), w(p, L(5,8))), Ls(0,8), down)
    # single copytruncate
    run('b%d/s.log' % down, lambda p: (w(p, L(3,5)), copytrunc(p), w(p, L(5,8))), Ls(0,8), down)
    # compress, no delay: .1.gz
    run('c%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), gz(p+'.1'), w(p, L(5,8))), Ls(0,8), down)
    # delaycompress: yesterday's .1 -> .2.gz, ours -> .1
    run('e%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), gz(p+'.2'), w(p, L(5,8))), Ls(0,8), down)
    # copytruncate + delaycompress
    run('f%d/s.log' % down, lambda p: (w(p, L(3,5)), copytrunc(p), gz(p+'.2'), w(p, L(5,8))), Ls(0,8), down)
    # no rotation at all
    run('g%d/s.log' % down, lambda p: w(p, L(3,8)), Ls(0,8), down)
    # two create rotations, unrelated files around
    def two(p):
        for junk in ('s.log.bak', 's.log.1.swp', 'other.log', 's.log-old'):
            w(os.path.join(os.path.dirname(p), junk), L(0,2,'J'))
        w(p, L(3,5)); create(p); w(p, L(5,8)); create(p); w(p, L(8,10))
    run('h%d/s.log' % down, two, Ls(0,10), down)
    # three create rotations
    run('i%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), w(p, L(5,8)), create(p), w(p, L(8,9)), create(p), w(p, L(9,10))), Ls(0,10), down)
    # two copytruncate rotations
    run('j%d/s.log' % down, lambda p: (w(p, L(3,5)), copytrunc(p), w(p, L(5,8)), copytrunc(p), w(p, L(8,10))), Ls(0,10), down)
    # two rotations, delaycompress
    run('k%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), gz(p+'.2'), w(p, L(5,8)), create(p), gz(p+'.2'), w(p, L(8,10))), Ls(0,10), down)
    # two rotations, the newer one compressed (compress, no delay) - ours .2.gz, .1.gz
    run('m%d/s.log' % down, lambda p: (w(p, L(3,5)), create(p), gz(p+'.1'), w(p, L(5,8)), create(p), gz(p+'.1'), w(p, L(8,10))), Ls(0,10), down)

# dateext, two rotations while down
p = os.path.join(d, 'n/s.log'); os.makedirs(os.path.dirname(p)); old(p+'-20261120', 'O1')
w(p, L(0,3)); t = mk(p); got = t.read(); st = t.state()
w(p, L(3,5)); os.rename(p, p+'-20261121'); w(p, L(5,8)); os.rename(p, p+'-20261122'); w(p, L(8,10))
got += drain(again(p, st), 6); check('dateext two rotations (down)', got, Ls(0,10))
# symlink repointed, across a restart
os.makedirs(os.path.join(d,'s'))
a = os.path.join(d,'s','ise-1.log'); b=os.path.join(d,'s','ise-2.log'); link=os.path.join(d,'s','current')
w(a, L(0,3)); os.symlink(a, link); old(os.path.join(d,'s','ise-0.log'), 'O')
t = mk(link); got=t.read(); st = t.state(); w(a, L(3,5)); w(b, L(5,8)); os.unlink(link); os.symlink(b, link)
got += drain(again(link, st)); check('symlink repointed (down)', got, Ls(0,8))
# symlink to a file that is rotated (create) - still works
os.makedirs(os.path.join(d,'r'))
a = os.path.join(d,'r','ise.log'); link=os.path.join(d,'r','cur')
w(a, L(0,3)); os.symlink(a, link); t = mk(link); got=t.read(); w(a, L(3,5)); os.rename(a, a+'.1'); w(a, L(5,8))
got += drain(t); check('symlink target rotated (running)', got, Ls(0,8))
# state round trip with a queue pending: restart in the middle of reading the queue
p = os.path.join(d, 'q/s.log'); os.makedirs(os.path.dirname(p)); w(p, L(0,3)); t = mk(p); got = t.read(); st = t.state()
w(p, L(3,5)); create(p); w(p, L(5,8)); create(p); w(p, L(8,10))
t = again(p, st); got += t.read(); st2 = t.state()
t = again(p, st2); t.prev = dict(st2['prev']) if st2['prev'] else None
got += drain(t, 6); check('queue kept over a restart', got, Ls(0,10))

shutil.rmtree(d, ignore_errors=True)
print('\n%d failed' % len(BAD))
sys.exit(1 if BAD else 0)
