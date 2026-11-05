#!/usr/bin/env python3
"""1.10.302: an icon for a shortcut on a home screen (Safari, iPad, iPhone).

    ./test/fixes302_icon.py
"""
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


icon = (ROOT / 'web' / 'apple-touch-icon.png').read_bytes()
ok('a PNG', icon[:8], b'\x89PNG\r\n\x1a\n')
w, h, depth, kind = struct.unpack('>IIBB', icon[16:26])
ok('180 by 180, as an iPad and an iPhone take it', (w, h), (180, 180))
ok('opaque - no alpha the device would fill with black', kind, 2)
# Its corners are the background, not cut away: the device rounds them.
idat = b''
at = 8
while at < len(icon):
    n, = struct.unpack('>I', icon[at:at + 4])
    if icon[at + 4:at + 8] == b'IDAT':
        idat += icon[at + 8:at + 8 + n]
    at += 12 + n
raw = zlib.decompress(idat)
stride = 1 + w * 3
ok('...square, its corner the colour of the rest', raw[1:4] == raw[1 + 90 * 3:1 + 90 * 3 + 3]
   or raw[1:4] in (b'\x16\x1b\x22',), True)
page = (ROOT / 'web' / 'index.php').read_text()
ok('named on the page, for the sign-in and the dashboard alike',
   ('<link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon.png">' in page,
    '<meta name="apple-mobile-web-app-title" content="isemon">' in page), (True, True))
inst = (ROOT / 'install.sh').read_text()
ok('put in place by an install and an upgrade',
   inst.count('"$SOURCE_DIR/web/apple-touch-icon.png" "$WEB_DIR/apple-touch-icon.png"'), 2)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
