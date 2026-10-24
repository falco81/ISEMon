# Reading a FreeRADIUS server of your own

Where a **FreeRADIUS** server answers the site's own doors - the switches
(802.1X and MAB on the sockets), the access points and wireless controllers,
and the VPN - isemon reads its `radius.log` and shows what it decided beside
what ISE and NPS decided, under buttons of its own: **FreeRADIUS VPN**,
**FreeRADIUS 802.1X LAN**, **FreeRADIUS 802.1X Wi-Fi**, **FreeRADIUS MAB
LAN**, **FreeRADIUS MAB Wi-Fi** (since 1.10.203).

This is not eduroam. A FreeRADIUS answering the visitors' network has its own
pane (*Settings → The eduroam logs*). One server doing both can be read by
both panes; leave the eduroam accounts out of this one with *Accounts to
leave out*, or the other way round.

**Banning.** Only a VPN refusal can earn a ban, only from an address on the
internet, and only while *Settings → Banning → Where the bans come from → The
VPN through a FreeRADIUS of your own* is on - it is **off** until switched on.
It is counted every minute, as the firewall's sign-ins are: so many refusals
from one address in *the window*, then the same ladder as everything else. A
socket or a radio never earns a ban.

---

## 1. On the FreeRADIUS server

`radius.log` has to say who was let in and who was refused. In
`/etc/raddb/radiusd.conf` (`/etc/freeradius/3.0/radiusd.conf` on Debian):

```
log {
    destination = files        # or syslog, see §2
    auth = yes                 # "Login OK" / "Login incorrect" lines
    auth_badpass = no          # isemon never keeps a password, but why write one
    auth_goodpass = no
}
```

A line then reads:

```
Sun Oct 18 13:36:52 2026 : Auth: (10) Login OK: [laptop.example.cz/<via Auth-Type = eap>] (from client AP port 1 cli 20-E2-A8-7D-9E-4D)
Sun Oct 18 14:01:01 2026 : Auth: (31) Login incorrect (mschap: MS-CHAP2-Response is incorrect): [jnovak/<via Auth-Type = eap>] (from client vpngw port 0 cli 203.0.113.9)
```

`from client` is the RADIUS client as `clients.conf` names it; `cli` is the
calling station - the machine's MAC on a socket or a radio, the person's own
address on the VPN.

The **accounting** files (`radacct/<client>/detail-YYYYMMDD`, the `detail`
module in the `accounting` section) are worth having too: they say what each
machine is - the address it was given, the access point and the network on a
radio - and which medium it is on.

## 2. Getting the files here

Either read them where FreeRADIUS writes them (isemon on the same machine:
*Where the FreeRADIUS logs are* = `/var/log/radius`, with the accounting in
`radacct/` beneath it), or ship them here with rsyslog as
[docs/freeradius-rsyslog-forwarding.md](freeradius-rsyslog-forwarding.md)
describes - one folder per server, `radius.log` and `detail-YYYYMMDD` in it.
`deploy/freeradius/` has the receiving side for this pane.

Lines as a syslog server writes them (`Oct 18 13:36:52 radius radiusd: Sun Oct
18 ... : Auth: ...`) and as FreeRADIUS writes its own file (`Sun Oct 18 ...
: Auth: ...`) are both read. A line of the server's own file names no host,
so the folder's name is the server's.

## 3. Which door

`radius.log` does not say which door a sign-in came through. It is worked
out, in this order:

1. a calling station that is an **address** is the **VPN**, and so is
   anything through a client named in *The RADIUS clients that are the VPN*;
2. a name that is the machine's own **MAC** (`aabbccddeeff`, `AA-BB-...`) is
   **MAB**, everything else **802.1X**;
3. **LAN or Wi-Fi** is the client's, as *The RADIUS clients that are radios* /
   *...that are switches* name them (comma separated, `*` a wildcard: `AP,
   wlc*`, `sw*`), or else what the accounting said of that machine - its
   `NAS-Port-Type`, or a network name in `Called-Station-Id` on a radio;
4. what is still unknown is **FreeRADIUS other**. Name the clients and the
   rows from then on go to their own doors; a row the accounting speaks of
   later is moved to its door then.

Clients named `AP`, `AP-…`, `wlc…`, `…wifi…` are radios and `sw`, `sw-…`,
`switch…` switches unless the two settings say otherwise (1.10.204).

What the accounting said of each machine - its network, access point, the
address it was given, the box that asked, the VLAN - is written on every
sign-in of it; on the VPN the address inside. Today's and yesterday's
accounting files are followed.

## 3a. The zone of its clock

A FreeRADIUS writes its times in its own zone, with nothing saying which.
Each accounting record says the same moment twice - its header as the clock
showed it, `Timestamp` as a number - so the zone is worked out from them
(1.10.204) and radius.log is read in it. *The zone its times are written in*
sets it outright; without accounting files and without that, `log_zone`.
Rows read in a wrong zone keep their time: erase the FreeRADIUS records
under Settings → The database and they are read again.

The inner half of an EAP conversation (`... via TLS tunnel`) is left out, and
the pair of lines FreeRADIUS writes about one refusal is one refusal - as on
eduroam.

## 4. Checking it

```bash
isemon --set radius=1
isemon --set radius_paths=/var/log/remote/radius
isemon --passed --kind radius        # what it let in
isemon --failed --kind radius-vpn    # what it refused at the VPN
isemon --rescan --logs radius        # every file still there, from the beginning
```
