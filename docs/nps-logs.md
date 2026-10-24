# Reading a Windows NPS server's logs

Network Policy Server (NPS) is the RADIUS server that comes with Windows
Server. On a site without ISE it is what answers the switches (802.1X and
MAB on the sockets), the wireless controllers and sometimes the VPN. isemon
reads the log NPS writes of every request and every answer. It shows what NPS
decided beside what ISE decided, under buttons of its own.

**The VPN through NPS is judged exactly as the VPN through ISE is (since
1.10.99); nothing else read from NPS ever is.** A FortiGate, an ASA or any
gateway that asks NPS about a password asks on a *Virtual* port (NAS-Port-Type
5) and for a network rather than a shell, and puts the address the person came
from in *Calling-Station-Id* (or *Tunnel-Client-Endpt*). Those refusals are
counted with the same bar, window and ladder, and they earn the same bans. The
sockets and the Wi-Fi (802.1X, MAB) are machines inside the building and are
never judged. An EAP conversation the client walked away from decided nothing
and is not counted either.

*Settings → Banning → Judge the VPN through NPS as well* switches it off, and
then a VPN refusal at NPS is only written down, as before 1.10.99. The list of
devices under *Logs* (`watch_devices`, `FTD-VPN` by default) names ISE's
devices and does not apply to NPS.

Lines forwarded by rsyslog end in `#015`, which is rsyslog's way of writing
the carriage return NPS ends each line with. It is dropped before the line is
read (1.10.99; before that it showed up as the value of the last column).

---

## 1. On the NPS server: what to log, and in which shape

*Network Policy Server* console → **Accounting** → **Change Log File
Properties**:

| Setting | Value |
|---|---|
| Settings tab | tick **Accounting requests**, **Authentication requests** and **Periodic accounting status** |
| Log File tab → Format | **ODBC (Legacy)** — sometimes labelled *DTS compliant* = off, *database-compatible* |
| Create a new log file | **Monthly** (or daily; either works) |
| When disk is full, delete older log files | as your policy says |
| Directory | the default `C:\Windows\System32\LogFiles` is fine |

isemon needs **Authentication requests** above all. It covers both the
request and the response, and they are two lines:

```
"NPS02","IAS",09/01/2026,06:11:50,1,"pc.terminal","EXAMPLE\pc.terminal","00-D6-FE-5E-70-85","00-30-04-13-AA-C8",,"192.168.4.21",,"192.168.200.22",50305,9,"192.168.200.22","SW_B2_SW2_STACK",,,15,,,2,5,"802.1x VLAN4 Terminaly",0,"311 1 172.29.136.9 07/23/2026 07:23:32 815915",...
"NPS02","IAS",09/01/2026,06:11:50,2,,"EXAMPLE\pc.terminal",,,,,,,,9,"192.168.200.22","SW_B2_SW2_STACK",,,,,,2,5,"802.1x VLAN4 Terminaly",0,"311 1 172.29.136.9 07/23/2026 07:23:32 815915",...,"4",...
```

The fifth column is the packet: `1` a request, `2` accepted, `3` refused,
`4` accounting, `11` a challenge. isemon joins each answer to its request by
the `Class` column (the long `311 1 …` value), because each line knows only
half the story:

* the **request** says which door it was: the port type (15 Ethernet,
  19 wireless, 5 a VPN), whether the switch asked on a MAC's behalf (MAB,
  Service-Type 10) or passed 802.1X credentials, the machine's MAC, the
  switch and its port, and the address the machine had;
* the **answer** says yes or no, the reason code, the network policy that
  matched, and the VLAN it handed down.

An answer whose request was never seen is not shown. What it was cannot be
known, and a refusal of nobody in particular is worse than a gap. This only
happens to the first line or two of a file read from its middle.

The **IAS** (legacy) format and the **DTS/XML** format are not read. Only
ODBC (Legacy).

---

## 2. Getting the files to the isemon machine

isemon reads plain files from a folder, one folder per NPS server. There are
two ways to get them there.

### 2.1 NXLog (recommended): every line as it is written

This is how the domain controllers already ship their Security logs
([windows-security-log.md](windows-security-log.md)). The configuration is
ready in [`nxlog-nps.conf`](nxlog-nps.conf), and the rsyslog rule for the
receiving side is in [`deploy/nps/06-nps-store.conf`](../deploy/nps/06-nps-store.conf).

```
NPS log files (IN*.log) → NXLog im_file → syslog TCP 514 → rsyslog → /var/log/remote/<host>/IN.log
```

**On each NPS server:**

1. Install NXLog Community Edition. Its default path is
   `C:\Program Files\nxlog`, as the file assumes.
2. Copy `nxlog-nps.conf` over `C:\Program Files\nxlog\conf\nxlog.conf`. On a
   server that already runs NXLog for the Security log, add its `Input`,
   `Output` and `Route` to the existing file instead. The names do not clash.
3. Change the three `define`s at the top:

   | Define | What it is |
   |---|---|
   | `ISEMON` | the isemon machine, by address or name |
   | `SYSLOGHOST` | the folder name on the isemon machine: `/var/log/remote/<SYSLOGHOST>/` |
   | `NPSLOGS` | where NPS writes its logs (*Accounting → Change Log File Properties → Log File → Directory*) |

4. Restart the service (`Restart-Service nxlog`) and check
   `C:\Program Files\nxlog\data\nxlog.log` for errors.

What the file does:

- It reads every `IN*.log` in the folder, following a new one when NPS starts
  it. It remembers where it got to (`SavePos`), and on the very first start
  sends only what is written from then on (`ReadFromLast`).
- It drops accounting (4) that carries no address on the NPS server already,
  because isemon never reads it. Most of that is the switches' own probes.
  Accounting that carries the address a machine was given is sent, because
  it is where a wireless controller says it (§3.1). Requests, answers and
  challenges go unchanged: isemon needs both halves of every pair, and a
  challenge nothing followed is an abandoned conversation (§3.2). A
  configuration from before 1.10.95 dropped the challenges; take the new
  file, or remove the line with `,11,` from the `Exec`.
- It sends over **TCP**. A request and its answer are two lines, and losing
  one loses the pair. A UDP variant is in the file, commented out, for where
  TCP 514 cannot be opened.

**On the isemon machine:**

```bash
cp deploy/nps/06-nps-store.conf /etc/rsyslog.d/
rsyslogd -N1 && systemctl restart rsyslog
ls -la /var/log/remote/nps01/          # IN.log appears with the first line
```

The listeners on port 514 (UDP and TCP) are in `10-ise.conf`
([deploy/rsyslog-ise.conf](../deploy/rsyslog-ise.conf)). The file is rotated
by the same rule as everything else under `/var/log/remote`
(`deploy/remote-logs.logrotate`). isemon follows it across a rotation and
loses nothing.

**The history.** NXLog sends only what is new. To have the months already on
the NPS server as well, copy those files once into the same folder (for
example `IN2608.log`, `IN2607.log`) and run:

```bash
isemon --rescan --logs nps
```

It reads every `IN*.log` in the folder and the rotated copies of `IN.log`.
Nothing is read twice, because every answer is stored under its own id, so
a month that overlaps what NXLog already sent is fine. Alternatively, set
`ReadFromLast FALSE` before NXLog's first start and it sends the whole of every
file itself, once. That is about half a gigabyte a month through syslog.

### 2.2 A share, read where it is

On the isemon machine, mount the NPS server's log folder read-only (for
example with a `cifs` entry in `/etc/fstab`, using an account that can only
read that folder). Point isemon at the mount point. The files are read as they
grow, and nothing is copied.

```
//nps02.example.int/LogFiles$  /var/log/remote/nps/nps02  cifs  ro,credentials=/etc/isemon/nps.cred,uid=isemon,gid=isemon,file_mode=0440,dir_mode=0550  0 0
```

Here the files keep the names NPS gives them (`IN2609.log` for a month,
`IN260929.log` for a day). isemon follows the **newest two** in each folder,
because the end of last month's file may still be arriving after the new one
has appeared.

Either way, the daemon runs as `isemon`, so the files must be readable by that
account.

---

## 3. Switching it on

**Settings → The NPS logs:**

| Setting | Value |
|---|---|
| Read a Windows NPS server's logs | on |
| Where the NPS logs are | the folder(s) from step 2, comma separated — one per NPS server |
| Which files in each are NPS's | `IN*.log` (the default) |
| Accounts to leave out altogether | e.g. `testaccount, svc-scanner` — optional |
| What the switches call their ports | `GigabitEthernet` (the default), or per switch: `SW_OLD_*=FastEthernet, GigabitEthernet` |

**Switch ports.** NPS writes a port as the switch's own number for it. On a
Cisco switch that is five digits: 5, 0, the stack member and the port. `50124`
is member 1, port 24. Its name (`NAS-Port-Id`, `GigabitEthernet1/0/24`) is not
one of the columns of the ODBC (Legacy) format, so whether a port is Gigabit,
Fast or Ten Gigabit is not in the log. *What the switches call their ports*
supplies it, and the port is then written as ISE writes it:
`GigabitEthernet1/0/24`. A single name applies to every switch. Switches that
differ are named by a pattern, and the first rule that matches wins. Changing
the setting renames the ports already stored, in place. Left empty, a port is
shown as `1/0/24`.

**Accounts to leave out** are never written down at all: not a row, not a
count, not a door. A name matches whole and ignores case. It matches with or
without the domain in front (`testaccount` also leaves out
`EXAMPLE\testaccount`), and a name written with a domain
(`EXAMPLE\svc`) leaves out only that domain's account. The switches' own
probes are left out whether or not they are named here (section 4). Changing
the list changes what is read from then on. What is already stored stays
until it is erased.

The times on the lines are the NPS server's local time, with no zone. They
are read in the zone set in **Settings → The ISE logs → The zone the logs
without one are written in**, the same as the token server's and tac_plus's.

**What appears.** Buttons appear on *Failed attempts* and *Logins*:

| Button | What is behind it |
|---|---|
| **NPS VPN** | VPN sign-ins (NAS-Port-Type Virtual) |
| **NPS 802.1X LAN** | machines on a socket, by certificate or domain account |
| **NPS 802.1X Wi-Fi** | machines and people on the wireless |
| **NPS MAB LAN** | endpoints on a socket let on, or not, by their MAC alone |
| **NPS MAB Wi-Fi** | the same on the wireless |
| **NPS other** | anything that came through no socket, no radio and no VPN |

**Each one appears only once NPS has really answered something through that
door.** A site whose NPS has no VPN behind it never sees an NPS VPN button.
The front page gets **802.1X / MAB · NPS** and **VPN · NPS** doors under the
chart on the same rule, and the chart has two bands of NPS's own.

The rows are drawn the way ISE's network rows are: the MAC, the address the
machine had, the name, the switch (by the name NPS knows it by) and its port,
the network policy that matched, the VLAN, and the NPS server that answered.
A refusal carries NPS's own reason code, with its meaning in words: 16 is
*wrong password, or an account that does not exist*, 23 is *the EAP exchange
failed (usually the certificate)*, 48 is *no network policy matched*.
Opening a row shows every column of the request and the answer together.

Names are looked up in Active Directory, and addresses turned back into names,
exactly as they are for ISE's rows.

---

## 3.1 The address a machine was given, and its VLAN, on the wireless

A sign-in does not carry the address the machine *will* get, because the
address is handed out after it. A switch writes the address it already knows
into the request (`Framed-IP-Address`), which is why the LAN rows have one.
A wireless controller says it only in **RADIUS accounting**. isemon reads
NPS's accounting lines for exactly that: the newest one per MAC is kept and
put beside that machine's sign-ins of the same day. The row's hover says the
address came from there.

So on the Wi-Fi the address appears only if the controller sends accounting
to NPS. On an Aruba Instant cluster this is the SSID's **Security →
Accounting** option (send to the authentication servers, with an interim
interval). On a controller, it is the AAA profile's *RADIUS Accounting Server
Group*. NPS must also log accounting (*Accounting requests*, step 1).

The **VLAN** column shows what NPS itself handed down: `Tunnel-Pvt-Group-ID`
from a network policy with VLAN attributes. A policy without them, like a
typical "Secure Wireless Connections", hands none down, and the VLAN is then
decided on the controller by the SSID. NPS never learns it, so it is blank.
If the controller's accounting carries it, it is used.

NPS writes accounting for the wired side too: the switches' interim updates,
one per port every few minutes. It is kept the same way, one line per machine
at a time, so it costs almost nothing.

## 3.2 Conversations a machine walked away from

802.1X is a conversation: the machine asks, NPS answers with a
**challenge** (the next question of the EAP exchange), the machine asks
again, and so on until NPS says yes or no. NPS writes a conversation that
reaches a verdict as its request and that answer. One the machine walks
away from half way (a supplicant that gave up, a certificate it could not
present, a zero client that timed out) is written as its request and the
**challenge** (packet type 11), and nothing after it.

isemon shows those as refusals at their door, with the machine, the switch
and the port, and *the machine stopped answering in the middle
of EAP; nothing was decided* as the reason, the reason code being
`abandoned`. It is the same thing ISE writes as 5440 *Endpoint abandoned
EAP session*, and it is treated the same way: a machine that walked away
and got on a moment later raises no card on the front page, and one that
never got on is on the card of machines that never got on.

A challenge is only known to be the end of a conversation once nothing has
followed it, so each is written down **five minutes** after it was read.
On the site this was written against it was 109,750 in ten months: zero
clients about a hundred times a month each, and in June one access point
23,599 times. They are not on the eduroam page (FreeRADIUS does not write
them either).

---

## 4. What is left out on purpose

* **The switches' own probes.** A switch configured with
  `radius-server test username …` asks every few seconds, for ever, as an
  account that does not exist, and is refused every time. On the site this
  was written against that was six million of 21 million lines, and none of
  them was anybody signing in to anything. They are recognised (a Login with
  no port and no calling station) and are never rows.
* **Accounting** (packet type 4) is never a row, because it is not an
  authentication. It is read only for the address and VLAN a machine was
  given (§3.1).

---

## 5. Checking it

```bash
isemon --passed --kind nps --limit 10          # what NPS let on, every door
isemon --passed --kind nps-network --limit 10  # sockets and radios only
isemon --failed --limit 20                     # refusals: NPS's show the NPS server as the node
```

*Settings → The database → What is in it* says how many answers are stored
and how far back they go. **Erase collected data → the records read from the
Windows NPS logs** removes them and reads the newest two files again from the
beginning.

To read **every** month still in the folders, not only the newest two:

```bash
isemon --rescan --logs nps
```

Only the NPS files are read, nothing is weighed, and nothing can be banned by
it. Reading the same file twice adds nothing: every answer is stored under
its own id.

**How fast.** Ten months of one NPS server (21 million lines, 5.4 GB) took
128 seconds to read, about 13 seconds a month. They made 122,635 rows: 13,983
802.1X and 13,103 MAB let on at the sockets, 95,123 MAB refused, 184 802.1X
refused, 49 accepted and 188 refused on the wireless, and 5 others.

---

## If something is not right

| What you see | What it is |
|---|---|
| no NPS buttons at all | the module is off, or nothing has been answered yet: the buttons appear with the first answer at each door |
| *Permission denied* on the front page | the files are not readable by `isemon` (step 2) |
| the files are there, nothing appears | the log is not in **ODBC (Legacy)** format, or *Authentication requests* is not ticked (step 1) |
| every time an hour or two out | the zone setting (step 3) |
| refusals reading *abandoned* | a machine that stopped answering half way through 802.1X (§3.2). A zero client does it every few days; one machine doing it all day long is a supplicant or a certificate to look at |
| a MAB door full of refusals | ordinary: every endpoint nobody has put in the directory, asked about again every few minutes. The front page's card leaves out the machines that got on by 802.1X a moment later |
