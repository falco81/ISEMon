# The performance meter (1.10.298)

How busy this server is - the processor, memory, the disks and the network -
in the header of the page, every 3 s while the page is shown and live.

- **For a full admin only.** What the server is doing is not for a read-only
  or ban admin: the header has no meter for them and `GET /api/load` refuses
  them.
- **Off unless chosen.** Your account → *Performance meter*: how the numbers
  look (a graph of the last two minutes, pills with a bar, one plain line,
  rings, or not shown - the default) and how their details look when a
  number is pointed at or tapped (tiles, a table as htop, a map of the cores
  with rings, one wide panel, or only a short tip). Each choice is kept with
  the account, so it is the same in every browser.
- **Nothing in the background.** The daemon reads `/proc` and `/sys` only when
  a page asks; pages asking within the same second share one reading. The
  details - each core with its frequency and temperature, the sensors, each
  disk, the filesystems, each card, the processes taking most - are read only
  while a panel is open. Off, the page asks nothing at all.
- **The graphs survive F5.** The daemon keeps the readings of the last two
  minutes (one every 2.5 s at most, from those the pages ask for anyway) and
  a page loaded again is handed them with its first answer: the graphs go on
  where they were.

Where the header has no room for the four numbers beside everything else
(below 1850 px), the meter is a row of its own under it; up to 2050 px it is
a little narrower.

Temperatures come from hwmon (`coretemp`, `k10temp`, `zenpower`, `nvme`,
`drivetemp`, …) and the thermal zones. A virtual machine has none, and the
panel says so; a SATA disk needs `modprobe drivetemp`.

## API

`GET /api/load` (full admin): `cpu` (%), `cores`, `load`, `mem_total`,
`mem_used`, `swap_used`, `disk_rd`, `disk_wr`, `net_rx`, `net_tx` (B/s),
`over_s`. `&detail=1` adds `detail`; `&hist=1` adds `hist`, the last two
minutes as `[{at, cpu, mem, disk, net}]`, oldest first. The first answer
after the daemon starts has no rates: there is nothing to tell them from yet.
