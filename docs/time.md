# Time (NTP)

Every record isemon reads is filed by this machine's clock, and a log is judged
*too old to judge* or *dated ahead of the clock* against it. A clock that is
off by more than a second or so makes both say what is not so, and puts the
records of one moment minutes apart from the firewall's and ISE's own. *Settings
→ Time* watches the clock of this server and, when you want it to, sets its
time servers. It uses chrony, as AlmaLinux and Rocky 9 do. (After otp's page of
the same name, 1.0.120, without its cluster parts.)

## What the page shows

- **The card of this server**:
  - how far off the time servers it is (chrony's system time offset), and
    whether it is synchronised;
  - the source it follows, its stratum, the last correction, the frequency
    error, root delay and dispersion, the leap status;
  - its time zone, and its own time now.

  *Read it again* asks root at once (it is read by itself every minute).
  *Step it now* sets the clock to the servers' time at once (`chronyc
  makestep`), for a clock that is far off. Both are for a full administrator.
- **Where the time comes from**: the sources, as `chronyc sources` lists them:
  - the state (*followed*, *combined*, *not combined*, *unreachable*, *false
    ticker*, *too variable*);
  - the stratum, how often it is asked, the last eight tries (reach), when it
    was last heard, and its offset with the error.
  - While isemon does not set the servers, the `server`/`pool` lines of the
    machine's own `/etc/chrony.conf` are shown under it.

A clock that is not synchronised, or is more than a second off, is said in the
header of the dashboard (*the clock is not synchronised*, *the clock is 2.3 s
off*) and in `isemon --status` - after every other trouble, which comes first.

## The time servers

**isemon sets the time servers** off (the default): the machine keeps its own
`/etc/chrony.conf` - AlmaLinux's pool, or what was set by hand. It is shown and
checked here, never changed.

**On**: the settings below are put in.

| Setting | |
|---|---|
| Servers | a host name or address each; *one server* or *a pool* (several addresses behind one name); **iburst** (synchronised in seconds after a start), **preferred**, **NTS** (Network Time Security - the server proves who it is; needs TCP 4460 out, e.g. time.cloudflare.com). Ready-made: cz.pool.ntp.org, pool.ntp.org, time.cloudflare.com, tik.cesnet.cz, tak.cesnet.cz |
| Step when off by more than / in the first updates | chrony's `makestep` - further off than this, the clock jumps instead of being slewed; 3 updates is after a boot, -1 is any time |
| Sources that have to agree | `minsources` |
| Serve the time to | networks that may ask this server for the time (`allow`, UDP 123) - the switches, or the VPN concentrators, say. When isemon looks after the firewall (Settings → Firewall and access), it opens it by itself as *NTP (time served)*, a rule that can be turned off there like the others. |
| Time zone | `timedatectl set-timezone`. The logs and the times on the pages use it. Set on its own, it is put in whether isemon sets the servers or not. |

The settings are saved with the save bar at the bottom of the page, as every
other setting is. They are kept in the database (so a copy of it carries them),
and root's helper (`isemon_web.py`, through `isemon-web.path`) puts them in
within seconds; the card says when it did, and what failed if anything did.

How it is written: in `/etc/chrony.conf`, the file's own `server`, `pool`,
`peer`, `sourcedir`, `makestep`, `allow`, `minsources` and `maxdistance` lines
are commented out (`#isemon# …`), and isemon's lines go between two marks at
the end:

```
# ---- isemon: the time servers, set on its pages (Settings - Time) ----
pool cz.pool.ntp.org iburst
server time.cloudflare.com iburst nts
allow 192.0.2.0/24
makestep 1 3
# ---- isemon: end ----
```

The file as it was is kept in `/etc/chrony.conf.isemon-before`. chronyd is
enabled and restarted, and `timedatectl set-ntp true` is set. Switched off
again, the marked lines go and the file's own lines come back as they were.
chrony is installed by the helper when it is missing and the servers are to be
set.

## The command line

```
isemon --time          the clock as chrony sees it: offset, synchronised, sources
isemon --time-step     step it to the time servers now (chronyc makestep)
```

Both ask the running daemon, which asks root; `--json` gives the whole answer.

## install.sh

A fresh install puts chrony in when it is missing, and starts it (unless
systemd-timesyncd is running). An upgrade does nothing at all to chrony or to
`/etc/chrony.conf`: it only says so when chronyd is not running. Root's helper
of 1.10.228 or later (put in by `./install.sh --upgrade`) is what answers the
page; before it, the page says that root did not answer.
