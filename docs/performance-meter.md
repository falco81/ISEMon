# The performance meter (1.10.298)

How busy this server is - the processor, memory, the disks and the network -
in the header of the page, every 5 s while the page is shown and live.

- **For a full admin only.** What the server is doing is not for a read-only
  or ban admin: the header has no meter for them and `GET /api/load` refuses
  them.
- **Off unless switched on.** Settings → About → *The performance meter in
  the header* (`isemon --set perf_meter=1`): off - as it comes - there is no
  meter on any page and the daemon reads nothing of it, not one file.
- **Each full admin's own look.** Your account → *Performance meter*: how
  the numbers look (a graph of the last two minutes - the default - pills
  with a bar, one plain line, rings, or not shown, and then nothing is asked
  for them) and how their details look when a
  number is pointed at or tapped (tiles, a table as htop, a map of the cores
  with rings, one wide panel, or only a short tip). Each choice is kept with
  the account, so it is the same in every browser.
- **Read only while a page shows it.** While a page shows the meter, the
  daemon reads it itself every 5 s - however many pages there are, one
  reading - and writes each reading down as one small row of `load_samples`
  (one row per node every 5 s, kept a quarter of an hour). Nobody asking for
  45 s - the page closed or hidden - it stops by itself; switched off in
  About, at once. Nothing else is read or written. The details - each core
  with its frequency and temperature, the sensors, each disk, the
  filesystems, each card, the processes taking most - are read only while a
  panel is open.
- **Smooth graphs.** Each graph is drawn by time and slid to the left by one
  SVG animation, at the speed time passes; it is drawn again only when a
  reading arrives, nothing is redrawn by a timer.
- **The graphs survive F5**, and a restart of the daemon: a page loaded
  again is handed the last two minutes as written down, and goes on where
  it was.
- **In step with the daemon** (1.10.308): the page asks just after the
  daemon has read (the answer says when it reads next) and is handed every
  reading since the newest one it has, so none is missed and the line does
  not jerk.
- **The last state at once** (1.10.308): the browser keeps the last answer
  and the two minutes (for the same person, ten minutes at most), so a page
  opened again shows them before the daemon has answered; a page come back
  to is drawn again for the time it is now and then brought up to date. The
  first answer after a quiet while, which has no rate of its own yet, gives
  the newest reading written down.

Where the header has no room for the four numbers beside everything else
(below 1850 px), the meter is a row of its own under it; up to 2050 px it is
a little narrower.

Temperatures come from hwmon (`coretemp`, `k10temp`, `zenpower`, `nvme`, …)
and the thermal zones; each logical processor is given the temperature of
the core it is on, by its topology. A virtual machine has none, and the
panel says so; a SATA disk's temperature needs `drivetemp` (`modprobe
drivetemp`). Free space is never asked of a share of another machine (NFS,
CIFS, sshfs, …): one that is down would hang the meter.

## API

`GET /api/load` (full admin): `cpu` (%), `cores`, `load`, `mem_total`,
`mem_used`, `swap_used`, `disk_rd`, `disk_wr`, `net_rx`, `net_tx` (B/s),
`over_s`. `&detail=1` adds `detail`; `&hist=1` adds `hist`, the last two
minutes as `[{at, cpu, mem, disk, net}]`, oldest first; `now` is the
daemon's clock. The first answer after the daemon starts has no rates: there
is nothing to tell them from yet.
