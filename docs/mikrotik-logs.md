# Reading a MikroTik's own log

Since 1.10.203 a MikroTik router running **RouterOS** is one of the kinds of
firewall *Settings → The firewall log* reads (Kind: *MikroTik RouterOS*). Its
lines become the **Traffic** tab, as a FortiGate's or an FTD's do.

This is the router's log of what crossed it. The MikroTik that carries the
bans (*Settings → Reaching the router*) is a different thing and is set up on
its own; one router can be both.

## 1. On the router

A logging action that sends to this machine, and a rule per topic:

```
/system logging action add name=isemon target=remote remote=192.0.2.10 remote-port=514 bsd-syslog=no
/system logging add action=isemon topics=firewall
/system logging add action=isemon topics=account
/system logging add action=isemon topics=system,info
/system logging add action=isemon topics=critical
/system logging add action=isemon topics=ssh
/system logging add action=isemon topics=ovpn,!debug
/system logging add action=isemon topics=l2tp,!debug
/system logging add action=isemon topics=sstp,!debug
/system logging add action=isemon topics=dhcp
```

A firewall line only says that a rule logged the packet - never what became
of it. That is read off the rule's **log prefix**: one with `DROP`, `REJECT`,
`DENY`, `BLOCK`, `BAN` or `TARPIT` in it is a refusal, `ACCEPT`, `ALLOW`,
`PERMIT` or `PASS` a pass. So log on the rules that decide, and say so in the
prefix:

```
/ip firewall filter set [find comment="drop the rest"] log=yes log-prefix="DROP-IN"
```

Every other line - no prefix at all, `LOG-FORWARD`, `OVPN -` - is a rule that
only logs (`action=log`) or one that lets through with `log=yes`, and is shown
as **let through**: a packet such a rule logged that a logging `DROP` rule
behind it then refused is written by both in the same second, and is counted
once, as that refusal. A packet the router found `invalid` is only *said*.
If a rule that refuses *without* logging stands behind a rule that only logs,
set *MikroTik: a line whose log prefix names no verdict* to `info` and those
lines are only said.

The clearest is to give every rule a prefix that is its action - `accept`,
`drop`, `v6-accept`, `v6-drop`, and `nat-masquerade`, `nat-dst-nat` on the
NAT rules: each line is then said for what it is. A NAT rule's line is the
address translation, only *said* (the filter rule's line about the same
packet is the session), and so is a rule whose action goes on to the next
rule (`add-src-to-address-list`, `mark-connection`, `jump`...). A change made
by a script says which script, and who ran it from where.

The router writes every packet the way it is going; a packet of the answer
(`established`, from a service's port back to a client's) is shown the way
its session was opened - client first, the service it asked for, `direction
reply` in its details and its MAC as the other end's. The address translation
is read in all three shapes RouterOS writes (`NAT (a->b)->c`, `NAT a->(c->d)`,
`NAT (a->b)->(c->d)`): the address the source was made (`transip`) and the one
the destination was made (`tranip`).

## 2. On this machine

rsyslog files the lines; `deploy/mikrotik/12-mikrotik.conf` writes them one
folder per router, a file per topic - `/var/log/remote/gw.example.net/firewall,info.log`
- which is what the sample lines this was written against look like. All in
one file works as well. Every file in the folder is followed.

In *Settings → The firewall log* add a row: a name, Kind *MikroTik RouterOS*,
the folder, files `*.log`, and the zone of the router's clock.

## 3. What is read

| Topic | Becomes |
|---|---|
| `firewall` | a session on the Traffic tab: the chain, in/out interface, the source MAC, protocol and flags, both ends, NAT, the connection state and marks, the length; the prefix as the policy |
| `account`, `critical` | sign-ins to the router itself - winbox, ssh, the web, the API - and **refused** ones, which count towards a ban under *Logins at the firewall itself* |
| `system,info` | every change to the configuration: what, by whom, from where, and the command |
| `ovpn`, `l2tp`, `sstp`, `pptp` | the VPN of people (who, from where, which address inside, how long, how much) and the tunnels to other sites by their interface |
| `ssh` | which key was accepted for whom |
| `dhcp` | the **DHCP** page of the Traffic tab: which address went to which MAC and name, from which server, and when it was given back |

The NAT rules' own lines (`srcnat`, `dstnat` chains, `log=yes` on the NAT
rules) are on a page of their own, **NAT**, not among the sessions: the
connection, the kind of translation (masquerade, src-nat, dst-nat, or *not
translated* for a NAT rule's `accept`) and the address it was made. A NAT
rule logs a connection's first packet before it is translated, so that
address is the one the router's other lines show for that way out (marked
≈), with the port RouterOS keeps when it can; a dst-nat's line says the
server inside (`→ 192.168.43.17:443`), out of the filter's lines about the
same connection. A session the filter logged
through a translation stays under Sessions, with the translation in its
details and in the column *Translated* (right button on a heading).

Each packet of a tunnel written out (`ovpn,debug,packet`) is left out.

## 4. More through its API or over ssh (read-only)

The log says which packets a rule wrote down, never how much went where:
RouterOS writes a packet, not a session. Its API does know. Switch on
*Read more of it through its API or over ssh* under the router's row in
*Settings → The firewall log*, and isemon keeps one session open to the
router with an account that may only read, and asks it a few cheap questions
a minute. *How it is reached*: its API (api-ssl with its certificate pinned,
api-ssl with a certificate an authority signed - checked against the
authorities this machine trusts or one of yours, for the router's name, or
not checked at all if you switch that off - api-ssl without a certificate,
or the plain API), or ssh - with a key made
here, exactly as the banning signs in, or a password. Over ssh the same
questions are asked on its console (`print as-value`, a line an entry); with a
key the ssh connection is shared between the rounds, with a password each
question is a sign-in of its own, so the API or a key is lighter.

| What | How often | Becomes |
|---|---|---|
| the connection tracking tables, IPv4's and IPv6's (only the fields wanted) | every round (30 s by default, 10-600) | each connection gone since the last round is a session that ended: both ends, the service, the bytes and packets each way, how long it was seen, what its source was made and the server inside a dst-nat sent it to - on the Sessions page (`via:api`), the NAT page, and every card and chart that counts bytes |
| who is on its VPN (`/ppp/active`), its IPsec peers, its tunnels' interfaces | about once a minute | *Connected now* on the Traffic tab shows this router as its API says it is, instead of as its log tells it |
| how the router is (`/system/resource`) | every five minutes | a line on *The firewall* page: CPU, memory, uptime, version |
| its DHCP leases | every five minutes | what each machine is called and which address it has, for the FreeRADIUS sign-ins beside them, and the *Router* page |
| its interfaces (state, bytes, packets, errors, drops, link downs) | about once a minute | the *Router* page, with what each carries now from the last two looks |
| its addresses and routes, its ARP table and IPv6 neighbours, its DHCPv6 bindings, its neighbours (MNDP/CDP/LLDP), the counters of every filter/NAT/raw/mangle rule - IPv4 and IPv6 alike - its sensors | every five minutes | the *Router* page |
| its WireGuard peers | about once a minute | the *Router* page |

What is read also tells the rest of the Traffic tab more, for this router
only: each session gets the interfaces it came in and went out by (from the
router's own networks and its routes), the name the router's DNS answered
for where it went (`/ip/dns/cache`, read every five minutes), the MACs and
the machines' names from its ARP table and DHCP leases, and the person on
its VPN whose address it was - so the busiest interfaces, names and people
on the overview count it. *Connected now* has its PPP people with their
bytes, its WireGuard peers heard from in the last three minutes, and every
VPN it dials out on (OpenVPN, PPTP, L2TP, SSTP, PPPoE clients, WireGuard
peers it goes to) as a tunnel. The overview has *Through it now*: what goes
through its default route's interface this minute.

The *Router* page of the Traffic tab - there only while a router is read this
way - shows all of it as it stood at the last look, with one search box
narrowing every table. Nothing of it is written as lines: the log keeps doing
that. A table of more than 3,000 entries (a router with the whole internet's
routing table, say) is counted first and not read, and says so.

A table of more than 150,000 connections is not read on that round (it would
be work the router notices), and says so. A connection is seen at each
round, so what it carried after the last look before it ended is not
counted, and one that began and ended between two rounds is not seen at all:
a shorter round catches more of them. Connections that are fasttracked are
counted with their fasttrack bytes.

The settings are drawn the way *Settings → Reaching the firewall* draws the
banning's router: its fields, the lines saying how it is (right now, the
address, the account, the last read, the connections, its certificate), *How
to set it up on the router…*, and the same panel the banning's ssh key has.
With the switch off, the switch is all there is of it.

On the router - *How to set it up on the router…* gives these with your
account's name and this machine's address:

```
/user group add name=isemon-read policy=read,api,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api
/user add name=isemon-read group=isemon-read password="..."
/certificate import file-name=isemon-api.pem passphrase=""
/ip service set api-ssl certificate=isemon-api.pem_0 disabled=no address=<this machine>
```

*Make a certificate* makes the key and the certificate here and pins its
fingerprint; like the banning's ssh key it is kept on this machine (the key
sealed) and never leaves it except through *Download it*, which gives both
in one file, `isemon-api.pem`, and writes into Events that it was downloaded
and by whom. *Use my own* takes a PEM certificate you already have (with its
key under it, if it should be downloadable from here again) and pins it.
Without either, the first connection pins whatever certificate the router
shows, and a router answering with another one later is refused (*Forget
it* for one replaced on purpose). *TLS without a certificate* is what
RouterOS speaks when api-ssl has none assigned: encrypted, but nothing says
it is that router. The plain API (8728) sends the password in the clear.
*Try reaching it* signs in, says which RouterOS it is and how many
connections it tracks, and warns when the account's group may change
anything. The password is kept sealed and never shown back. This is its own
connection and its own account, apart from the router the banning writes its
address lists to.

