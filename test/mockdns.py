#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mockdns.py - a name server that answers exactly the way one does, so that the
half of this program which asks them can be tested without one.

It exists because the interesting cases are all failures, and none of them
can be arranged with a real server: a server that never answers, a server
that refuses, a server that has never heard of the address, a reply cut
short so it has to be asked again over TCP, and - the case the whole feature
is for - a site whose DMZ zone is on a different machine from its offices,
where the first server has to be given up on and the second asked.

    ZONE = {'203.0.113.9': 'nb-novak.example.loc'}
    port, stop = serve(ZONE)
    ...
    stop()

Answers both over UDP and over TCP, on the same port, the way a real one
does.
"""
import socket
import socketserver
import threading

# Which address has which name. Keyed by the address itself, not by the
# reversed name, because that is how a test reads. Each server started here
# gets a copy of its own: the whole point of the feature is a site with two
# of them holding different zones, and two servers sharing one dictionary
# could never show that.
ZONE = {}
# What to do instead of answering, where the test wants a failure:
#   'quiet'    - never answer at all, which is a server that is not there
#   'refused'  - answer REFUSED, which is a server that will not talk to us
#   'nxdomain' - answer "no such name", which is a server without that zone
#   'cut'      - answer with the cut-short bit set, so it is asked again
#                over TCP, where the whole answer is
HOW = 'answer'


def _name(said):
    out = bytearray()
    for label in str(said).strip('.').split('.'):
        raw = label.encode('ascii', 'replace')[:63]
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _read_name(data, at):
    parts = []
    while at < len(data):
        length = data[at]
        if length == 0:
            return '.'.join(parts), at + 1
        if length & 0xC0 == 0xC0:
            return '.'.join(parts), at + 2
        at += 1
        parts.append(data[at:at + length].decode('ascii', 'replace'))
        at += length
    return '.'.join(parts), at


def _address_of(name):
    """`9.113.0.203.in-addr.arpa` back to `203.0.113.9`."""
    said = str(name).lower().rstrip('.')
    if said.endswith('.in-addr.arpa'):
        parts = said[:-len('.in-addr.arpa')].split('.')
        if len(parts) == 4:
            return '.'.join(reversed(parts))
    return ''


def _reply(packet, over_tcp=False, box=None):
    box = box if box is not None else _MINE
    if len(packet) < 12:
        return b''
    ident = packet[0:2]
    name, at = _read_name(packet, 12)
    box.asked.append(name)
    qtype = int.from_bytes(packet[at:at + 2], 'big')
    question = packet[12:at + 4]
    how = box.how
    if how == 'quiet':
        return b''
    if how == 'cut' and not over_tcp:
        # The bit that says "there was more than this": no answer in the
        # body, so anything that reads the bit gets its answer and anything
        # that does not gets nothing.
        return ident + (0x8380).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
            + (0).to_bytes(6, 'big') + question
    if how == 'refused':
        return ident + (0x8185).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
            + (0).to_bytes(6, 'big') + question
    if qtype == 1:
        # The other way round: a name asked about, an address answered. The
        # zone is kept by address, so this is it read backwards - which is
        # exactly what a forward zone is beside a reverse one.
        want = str(name).strip('.').lower()
        for at, said in sorted(box.zone.items()):
            if str(said).strip('.').lower() == want and ':' not in at:
                try:
                    body = bytes(int(x) for x in at.split('.'))
                except ValueError:
                    continue
                answer = _name(name) + (1).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
                    + (300).to_bytes(4, 'big') + len(body).to_bytes(2, 'big') + body
                return ident + (0x8180).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
                    + (1).to_bytes(2, 'big') + (0).to_bytes(4, 'big') + question + answer
        return ident + (0x8183).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
            + (0).to_bytes(6, 'big') + question
    got = box.zone.get(_address_of(name), '')
    if how == 'nxdomain' or not got or qtype != 12:
        rcode = 3 if (how == 'nxdomain' or not got) else 0
        return ident + (0x8180 | rcode).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
            + (0).to_bytes(6, 'big') + question
    body = _name(got)
    answer = _name(name) + (12).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
        + (300).to_bytes(4, 'big') + len(body).to_bytes(2, 'big') + body
    return ident + (0x8180).to_bytes(2, 'big') + (1).to_bytes(2, 'big') \
        + (1).to_bytes(2, 'big') + (0).to_bytes(4, 'big') + question + answer


class _Udp(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        said = _reply(packet, box=self.server.box)
        if said:
            sock.sendto(said, self.client_address)


class _Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        head = self.request.recv(2)
        if len(head) < 2:
            return
        want = int.from_bytes(head, 'big')
        packet = b''
        while len(packet) < want:
            more = self.request.recv(want - len(packet))
            if not more:
                return
            packet += more
        said = _reply(packet, over_tcp=True, box=self.server.box)
        if said:
            self.request.sendall(len(said).to_bytes(2, 'big') + said)


class _UdpServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class _TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class Box(object):
    """One server's own zone, and what it does instead of answering."""

    def __init__(self, zone=None, how='answer'):
        self.zone = dict(zone or {})
        self.how = how
        self.asked = []
        self.port = 0
        self.stop = lambda: None


_MINE = Box()


def serve(zone=None, how='answer', port=0):
    """Start one. Returns the port, the way to stop it, and its own box.

    The box is how a test changes what that server does - `box.how =
    'quiet'` - without touching any other server started beside it.
    """
    box = Box(zone if zone is not None else ZONE, how)
    udp = _UdpServer(('127.0.0.1', port), _Udp)
    port = udp.server_address[1]
    tcp = _TcpServer(('127.0.0.1', port), _Tcp)
    for one in (udp, tcp):
        one.box = box
        threading.Thread(target=one.serve_forever, daemon=True).start()

    def stop():
        for one in (udp, tcp):
            try:
                one.shutdown()
                one.server_close()
            except Exception:
                pass
    box.port, box.stop = port, stop
    return port, stop, box


if __name__ == '__main__':
    port, _, _box = serve({'203.0.113.9': 'nb-novak.example.loc'})
    print('answering on 127.0.0.1:%d' % port)
    threading.Event().wait()
