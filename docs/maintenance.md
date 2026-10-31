# Maintenance

*Settings → Monitoring and updates → Upgrades* (the pane **Upgrades and
maintenance**) → *The nodes* → **Maintenance**, or `isemon --maintenance on`.
isemon 1.10.266 and later, after otp's maintenance of a node - for one server:
no other node, no VIP address handed over, no "one at a time".

## What it does

- **`healthz.php` says 503** (`maintenance`; `?json=1`:
  `{"ok":false,"database":true,"maintenance":true,"said":"maintenance"}`), so
  a load balancer or the monitoring (Zabbix, Nagios, Uptime Kuma) leaves the
  server alone until it is back. The health check says only *that* it is in
  maintenance, never why: anybody on its list may ask it.
- **Everything else goes on.** The daemon reads the logs and bans as always -
  an attack does not wait for an upgrade, and the bans are what isemon is for;
  the dashboard works, so the server can be looked at and brought back. (otp's
  node stops answering RADIUS: that is the service its users reach. isemon's
  service to anybody but its administrators is the health check, and the
  firewall's ban list, which must not stop.)
- The header says **THIS SERVER IS IN MAINTENANCE**, with why, who and since
  when, and the state pill says *in maintenance* (unless something worse is
  wrong) - only when it is. *The nodes* says IN SERVICE or IN MAINTENANCE.
- An event each way: *HOST: in maintenance - healthz.php says 503 - why*,
  *HOST: back in service*.

It is kept in `/var/lib/isemon/maintenance.json` (who, when, why), not in the
database: it survives a restart of the daemon, and putting a backup back,
switching the database engine or importing another machine's export carries no
other machine's maintenance in.

## What puts the server into maintenance

| | |
|---|---|
| *Maintenance* on the page, `isemon --maintenance on [--why TEXT]`, the console (*Upgrades → Maintenance of this server*) | until *Back in service* / `--maintenance off` |
| An upgrade, or going back to an older version, from the page | until the new version answers and root said it was done; see [upgrades.md](upgrades.md) for a failure |
| `./install.sh --upgrade` by hand, when it was in service | until the new version answers |
| A backup being put back (from the page, a destination, an uploaded copy or dump) | for as long as it takes - not written down |

Not, as otp on a server alone: a restart, the system's updates (*System
updates*), a change of the network. With one server there is no other node to
answer meanwhile; maintenance would only add a 503 to a minute in which nothing
answers anyway.

Going back to a version older than 1.10.266 does not put the server into
maintenance: that version knows nothing of it and would never take it out. A
maintenance put on by hand stays in the file and holds again once a version
that knows it runs.

## On the command line

```
isemon --maintenance on --why "the disk is replaced"   # out of service
isemon --maintenance status                            # in service: exit 0; in maintenance: exit 3
isemon --maintenance off                               # back in service
isemon --status                                        # state: in service / IN MAINTENANCE (why · who · since)
isemon --check                                         # says it, not counted as trouble
```

With the daemon stopped, `--maintenance on|off` writes the file itself; the
daemon reads it when it starts.
