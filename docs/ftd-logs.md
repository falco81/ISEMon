# Cisco FTD and ASA: the firewall's own log

isemon reads the syslog messages of a Cisco Firepower Threat Defense (or an ASA)
for the **Traffic** tab, the same way it reads a FortiGate: sessions let through
and refused, what was dropped on the way, the remote-access VPN, the site-to-site
tunnels, failover. Nothing read here is ever judged and nothing here can earn
anybody a ban.

## Setting it up

*Settings → The firewall log*, one row per firewall:

| Name | Kind | Where its log is | Which files there are its |
|------|------|------------------|---------------------------|
| `hq-ftd` | Cisco FTD / ASA | `/var/log/remote/ftd1.example.cz` and `/var/log/remote/ftd2.example.cz` | `*.log` |

A **pair in failover is one firewall with a folder for each unit**. Use the `+`
beside the first folder to add the second.

From the command line:

```
isemon --set fwlog=1
isemon --set fwlog_sources='[{"name":"hq-ftd","type":"ftd","paths":["/var/log/remote/ftd1.example.cz","/var/log/remote/ftd2.example.cz"],"files":"*.log"}]'
```

The syslog server may file the messages however it likes:

- all of them in one file;
- a file per message id, such as `%FTD-6-302014.log`, which is the usual rsyslog
  template keyed on the program name.

Every file in the folder that matches the pattern is followed, not only the
newest two (that rule is for FortiGate's one file a day).

## What the management centre has to send

Out of the box FTD sends only its own messages over syslog. Intrusions, the
connection events with Security Intelligence and decryption, and the file and
malware events reach syslog only where the management centre is told to send
them:

- the access control policy: *Logging → Send using specific syslog settings*,
  and on each rule *Log at End of Connection* with *Syslog Server*;
- the intrusion policy: *Syslog*;
- the file policy: the rule's logging, also sent over syslog.

What the sample sent so far was only 430004 (files). Nothing reads 430001-430003
until those are switched on, and nothing else changes when they are.

## The time

The syslog header carries no year and no zone. FTD writes it in **UTC** unless
told otherwise, so set the firewall's *zone of its clock* to `UTC` (Settings →
The firewall log). Left empty, it is read in `log_zone` (*Settings → The ISE
logs*), or in this machine's own zone where that is empty. Lines that keep
arriving a whole number of hours old are said in the log and beside the
firewall in the settings. Where the firewall writes its own stamp (`logging
timestamp`), that stamp is used instead; an RFC 5424 stamp carries its zone and
is read in it.

## What becomes of the messages

| Messages | Read as |
|----------|---------|
| 302013 / 302015 / 302020 *Built* | Not rows of their own. The session is counted once, when it ends. Their direction (an *outbound* session is written far end first and is turned round), their address translation and the identity user are carried onto the line that ends it. |
| 302014 / 302016 / 302021 / 419006 *Teardown* | The session: interfaces, addresses, ports, duration and bytes. FTD writes one figure for both ways, so the page shows it as `⇅`. The reason it ended is a card of its own. |
| 106023 *by access-group* | Refused, with the access-control entry's hash as the rule. |
| 106100 / 106102 / 106103 *access-list … for user* | Refused by the downloadable ACL, with the person's name. |
| 106015 / 313005 / 500004 *no connection* | Said rather than refused: packets of sessions already closed. They age with the sessions let through. |
| 106016, 110002 / 110003, 209005 / 209006, 313008, 710003 | Dropped on the way: spoofing, no route, fragments, ICMP, to the box. |
| 507003 / 508001 / 607001 / 607002 | Protocol inspection. A SIP pinhole is read with both ends, the far one often written without a port. |
| 113004 / 113005 / 113019, 716xxx, 722xxx, 109210, 737016 | The remote-access VPN: who signed in or was refused, how long a session lasted and how much it carried each way, which address inside the VPN it had, a session that lost its connection (716058) and came back (716059). |
| 750xxx–752xxx, 713xxx | Site-to-site tunnels (IKEv2, IKEv1). The tunnel group is a group, not a person. |
| 725xxx | TLS to the firewall's own portal. |
| 105xxx | Failover. |
| 733100 | Threat detection. |
| 430001 *intrusion* | The intrusion policy (IPS): the signature (GID:SID:revision), message, classification, priority and intrusion policy, and whether it was blocked or only detected. It has a card of its own, *Intrusions (IPS)*. |
| 430002 / 430003 *connection* | The management centre's view of a session: both directions' bytes, the application, the URL and its category, the DNS query, the user and the rule. On top of that: **Security Intelligence** (address, URL or DNS on a feed) and the **decryption policy** (`SSLActualAction`, `SSLFlowStatus`, the server's name from SNI), each with a card of its own. Where the firewall writes its own session ends (302014) as well, the session is counted from those and this only adds what it knows. |
| 430004 / 430005 *file, malware* | The file and malware policy (AMP): the file, its type, what the cloud said of it (`SHA_Disposition`), the malware's name and what was done. Cards *Files looked at* and *Malware*. |
| 805001 / 805002 *offloaded* | Skipped. |
| 113009 / 113011, 734001 | The group policy and the DAP records a VPN session was given. |
| 411001–411004 | An interface's link or configuration up or down. |
| 321001 / 321002 | A resource limit reached. |
| 202010 / 305006 | No address left to translate to: a session that could not be made. |
| 111008 / 111010, 111001 / 111004 | A command on the firewall: a change (and the part of the configuration it touched), a save, or one that only looked. |
| 199017 | SSH to the box; the management centre's deployment steps (sudo `policy_apply.pl`). |
| 746016 | A name in a network object the firewall could not resolve. |
| 317077 / 317078 | A route put in or taken out: network, gateway, interface. |
| 324303 | Advice about a RADIUS server, naming it. |
| anything else | Kept as what the firewall said, with its message id, on the *Other* page of the Traffic tab. |

## The pages of the Traffic tab

Every line is filed under one page as it is read, the same way for a
FortiGate and an FTD:

| Page | Holds |
|------|-------|
| Sessions | Sessions let through or refused, drops on the way |
| Web | Web filter, DNS filter, SSL inspection or decryption |
| Threats | Intrusions, antivirus, files and malware, Security Intelligence |
| Client VPN | AnyConnect, the SSL VPN, FortiClient |
| Site-to-site VPN | IKEv1, IKEv2, IPsec SAs |
| Administrators | 111xxx, 605xxx, 611xxx, SSH to the device |
| The firewall | Failover, threat detection, TLS to its portal, routes, connections |
| Everything | All of the above |

Search one page with `area:` (`session`, `web`, `threat`, `client-vpn`,
`s2s-vpn`, `admin`, `system`).

## A very busy firewall

A pair like the one these pages were written against writes about 90 million
lines a day. A few settings and habits keep that manageable:

- **Keep what it let through as rows for a day (the default), or not at all.**
  The cards and the chart count every session either way.
- Packets of sessions already closed (106015) age with the sessions let
  through, not with the refusals.
- The lines that only open a session are never rows, and the standby unit's
  copies are dropped before anything is written.
- On PostgreSQL the per-table autovacuum settings in
  [postgresql-tuning.md](postgresql-tuning.md) matter for `fw_events` as much
  as for the domain events.

## Connected now

*Traffic → Connected now* lists who is on the remote-access VPN and which
site-to-site tunnels are up. Syslog gives no list of what is up, so the page
puts it together from the lines kept:

- **A remote-access session** is up from its beginning (113039, 716001,
  722022, the address given out in 722051) until its end (113019, 716002,
  721018, or its address given back in 737016 / 109210). The group policy
  (113009) and DAP records (734001) are said just before it begins and are
  carried onto it.
- **A tunnel** is up from coming up (750006) or its SAs being made (602303)
  until it goes down (750007, not a rekey) or every SA is deleted (602304) with
  no new one within three minutes. Its networks come from the negotiation
  (750001), which FTD writes when the tunnel is built, not at a rekey.
- **Since before the oldest line kept:** a tunnel is known only by its rekeys,
  and the page says "at least since".

What helps it most, where the syslog does not send them yet: 113039, 113009,
734001, 716001 and 750001. In the management centre: *Devices → Platform
Settings → Syslog → Syslog Settings*, enable the ids and give them a level the
syslog host is sent.

## The cards

The cards are on the overview of the Traffic tab. Pressing a row opens the
page it belongs to on exactly those lines.

*Why tunnels fail* gives the firewall's words and what they mean:

| The firewall says | Which means |
|-------------------|-------------|
| Failed to locate an item in the database; No pre-shared key or trustpoint configured | no tunnel is set up for this peer (it lands in `DefaultL2LGroup`) |
| Crypto Map Policy not found; no IPSEC policy found for received TS | the two sides ask for different networks; the line carries both sides' traffic selectors |
| Maximum number of retransmissions reached | the peer stopped answering |
| Failed to receive the AUTH msg | the peer never finished signing in |

## A pair in failover

The standby unit writes its own copy of every session the active unit closes:
TCP with `Failover primary closed`, UDP with nothing to say so. Those copies are
left out.

The active unit is the one opening sessions through the firewall. A closing line
from the other unit within ten minutes of that is taken to be a copy. Lines the
standby writes about itself (its own interfaces, TLS to its own address) are kept.

## The person behind an address inside the VPN

A refusal "for user", a session the identity firewall put a name on, or the
address being given out (109210, 722051) tie an address inside the VPN to a
person. Sessions from that address are then given the name, and the line says
where it came from (`user_from: its VPN address`).

## Read beside ISE

Where the ISE logs are read too:

- **Masked names.** A VPN sign-in FTD refused as `*****` is given the name ISE
  recorded for the same attempt from the same address (`user_from: ISE`).
- **A line's popup** shows the person's last ISE VPN sign-in: groups, profile,
  policy set and the downloadable ACL, the same ACL a 106103 line names.
- **A name looked up at the top** shows what the firewall saw of it.

Without ISE, or without FTD, each works on its own.

## Rotating the files

`/var/log/remote/ftd*/*.log`, see the logrotate example in
[log-rotation-and-permissions.md](log-rotation-and-permissions.md).

Watch out for one thing: rsyslog files a message it can find no program name in
(the management centre's `host  : %FTD-6-430004`) as **`.log`**, a hidden file.
logrotate's `*.log` does not match a name starting with a dot. Add
`/var/log/remote/ftd*/.log` to the same stanza, or fix the template.
