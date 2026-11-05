#!/usr/bin/env python3
"""1.10.300: what plexmon found in the performance meter, fixed here too.

- Free space is never asked of a share of another machine: statvfs hangs
  on one that is down, and every ask of the meter with it. (drivetemp is read
  as before: waking a disk is not a matter on this server.)
- Each logical processor has the temperature of the core it is on, by its
  topology: hyperthreading, cores numbered 0, 4, ..., two packages.
- A bar is what it says: nothing at 0 %, and a process's bar is its real
  share, not a share of the busiest.

    ./test/fixes300_meter.py
"""
import io
import os
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


def put(root, path, text):
    p = root / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text + '\n')


work = Path(tempfile.mkdtemp(prefix='isemon-300-'))
was_sys = isemon.LOAD_SYS
try:
    print('drivetemp')
    sysfs = work / 'a'
    put(sysfs, 'devices/x/block/sda/size', '1')
    put(sysfs, 'class/hwmon/hwmon0/name', 'drivetemp')
    put(sysfs, 'class/hwmon/hwmon0/temp1_input', '36000')
    os.symlink(str(sysfs / 'devices/x'), str(sysfs / 'class/hwmon/hwmon0/device'))
    isemon.LOAD_SYS = str(sysfs)
    ok('read here as it is: a SATA disk\'s temperature',
       isemon.load_temps()['disks'], {'sda': 36.0})

    print('\nThe cores\' temperatures')
    for name, ids, labels in (('hyperthreading', [0, 1, 0, 1], ['Core 0', 'Core 1']),
                              ('cores 0 and 4', [0, 4, 0, 4], ['Core 0', 'Core 4'])):
        sysfs = work / name.replace(' ', '')
        hw = sysfs / 'class/hwmon/hwmon1'
        put(sysfs, 'devices/platform/coretemp.0/x', '')
        put(sysfs, 'class/hwmon/hwmon1/name', 'coretemp')
        os.symlink(str(sysfs / 'devices/platform/coretemp.0'), str(hw / 'device'))
        for i, lab in enumerate(labels):
            put(sysfs, 'class/hwmon/hwmon1/temp%d_input' % (i + 2), str(50000 + i * 5000))
            put(sysfs, 'class/hwmon/hwmon1/temp%d_label' % (i + 2), lab)
        for n, cid in enumerate(ids):
            put(sysfs, 'devices/system/cpu/cpu%d/topology/core_id' % n, str(cid))
            put(sysfs, 'devices/system/cpu/cpu%d/topology/physical_package_id' % n, '0')
        isemon.LOAD_SYS = str(sysfs)
        raw = {'at': 1.0, 'cores': {n: (0, 100) for n in range(4)}, 'disks': {}, 'nics': {},
               'procs': {}}
        keep = isemon._load_detail_raw
        isemon._load_detail_raw = lambda: dict(raw)
        isemon.LOAD_DETAIL.update(at=0.0, raw=dict(raw), out=None)
        try:
            cores = isemon.load_detail()['cores']
        finally:
            isemon._load_detail_raw = keep
        ok('%s: every logical processor has its core\'s' % name,
           [c['temp'] for c in cores], [50.0, 55.0, 50.0, 55.0])

    print('\nFree space')
    mounts = ('/dev/sda1 / ext4 rw 0 0\n'
              '/dev/sdb1 /data xfs rw 0 0\n'
              'nas:/v /mnt/nfs nfs4 rw 0 0\n'
              '//nas/s /mnt/smb cifs rw 0 0\n'
              '/dev/sdc1 /mnt/ntfs fuseblk rw 0 0\n'
              'mergerfs /pool fuse.mergerfs rw 0 0\n'
              '/dev/sdd1 /boot/efi vfat rw 0 0\n'
              'tank /tank zfs rw 0 0\n')
    asked = []
    real_open = open

    def fake_open(path, *a, **kw):
        if path == '/proc/mounts':
            return io.StringIO(mounts)
        return real_open(path, *a, **kw)

    class SV(object):
        f_blocks = f_bfree = f_bavail = 100
        f_frsize = 4096
    keep_sv = isemon.os.statvfs
    isemon.open = fake_open
    isemon.os.statvfs = lambda m: (asked.append(m), SV())[1]
    isemon.LOAD_SYS = was_sys
    isemon.LOAD_DETAIL.update(at=0.0, raw=None, out=None)
    try:
        fss = [f['mount'] for f in isemon.load_detail()['filesystems']]
    finally:
        del isemon.open
        isemon.os.statvfs = keep_sv
    want = ['/', '/boot/efi', '/data', '/mnt/ntfs', '/tank']
    ok('asked of the local ones - never of NFS or CIFS',
       (sorted(asked), sorted(fss)), (want, want))

    print('\nThe bars')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('every bar and ring through hlWidth, nothing at 0 %',
       (page.count('hlWidth(pct)'), "fill.style.width = hlWidth(x[3]) + '%';" in page,
        'Math.max(1, Math.min(100, pct || 0))' in page, 'Math.max(2, Math.min(100, x[3]))' in page),
       (4, True, False, False))
    ok('a process\'s bar its real share', ('100 * v / top' in page,
                                           'memAll ? 100 * (v || 0) / memAll : 0' in page),
       (False, True))
    ok('a ring at 0 % draws no dot', '.hl-ring-fg[stroke-dasharray^="0.0 "]' in page)
    print('\nSwitched off')
    src = (ROOT / 'isemon.py').read_text()
    a = src.index("if path == '/api/load':")
    body = src[a:a + 1400]
    ok('for the server, or by the person: answered off, nothing read',
       body.index("return self.send_json({'off': True})") < body.index('api_load('))
    ok('the switch in About, off as it comes',
       ("about:   ['site_name', 'perf_meter'," in page, isemon.DEFAULTS['perf_meter'],
        isemon.Daemon.__dict__ is not None), (True, 0, True))
    ok('...and the page told by the status', "'perf_meter': bool(int(CONFIG.get('perf_meter') or 0))," in src)
finally:
    isemon.LOAD_SYS = was_sys
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
