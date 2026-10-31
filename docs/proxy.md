# Proxy

*Settings → Proxy* (under *Server*, a full administrator's; 1.10.268, after
otp 1.0.166 - 1.0.172) is for a server that may reach the web only through an
HTTP proxy. The proxy and **each of its uses** are switched on by themselves,
and all of them are **off until switched on**: a use goes through the proxy
only when the proxy is on *and* that use's own switch is on. Otherwise it goes
exactly as it always went - straight, or through `https_proxy` in the
service's environment where somebody put one there (`systemctl edit
isemon`). The use switches are greyed while the proxy is off.

## The settings

| Setting | | |
|---|---|---|
| `proxy` | Go out through a proxy | off (0) until switched on |
| `proxy_url` | The proxy | `http://host:port` (`http://[v6]:port`; 3128 when no port is given) - no user name or password in it |
| `proxy_user` | User name at the proxy | where the proxy asks for one (Basic); empty: none. No spaces, `:`, `@` or `/` |
| `proxy_password` | Password at the proxy | kept sealed in the database, like every other password; shown back masked |
| `proxy_no` | Straight, not through the proxy | names and addresses separated by commas: `localhost`, `.example.cz` (every name under it, and itself), `*.example.cz` (the same), `10.0.0.0/8`, `::1`, `*` (everything). Default `localhost, 127.0.0.1, ::1` |
| `proxy_upgrade` | The new versions of isemon through it | *Upgrades - From the web*: the look for new versions (by hand and once a day) and their download |
| `proxy_os` | The updates of the system through it | dnf or apt of *System updates*, by hand and on a schedule |
| `proxy_acme` | Automatic certificates: the ACME CA through it | the directory, the account, the orders, the certificates, ARI |
| `proxy_acme_dns` | Automatic certificates: the DNS APIs through it | deSEC, Cloudflare, acme-dns (RFC 2136 is DNS, never through it) |
| `proxy_lists` | The public lists through it | the blocklists of *Public lists*, by hand and by *Automatic updates* |
| `proxy_geo` | The country database (GeoIP) through it | db-ip.com's monthly file |
| `proxy_mac` | The register of network cards through it | the IEEE's registers of MAC prefixes (standards-oui.ieee.org) |

Every use switch is 0 (off) by default.

Every change is an event (*Events*, kind *settings*) saying what the way out
is now - the proxy's address, the user name and whether there is a password,
what goes straight, whether the system updates use it - never the password.

## Every connection isemon opens to the web, and its switch

| What | Where in isemon.py | Switch |
|---|---|---|
| the look for new versions and their download | `Upgrades.online_get` | `proxy_upgrade` |
| dnf / apt (look for updates, update), by hand and on a schedule | `_osup_job` → root's helper `osup_job` | `proxy_os` |
| the ACME CA: directory, nonces, account, orders, authorizations, finalize, certificate, ARI | `acme_fetch` (`_acme_open`) | `proxy_acme` |
| Cloudflare, acme-dns, deSEC APIs | `_acme_api_call` (`_acme_open`) | `proxy_acme_dns` |
| the public lists (FireHOL, Spamhaus, DShield...) | `Daemon._feed_fetch` | `proxy_lists` |
| the country database (db-ip) | `Daemon.geo_fetch` | `proxy_geo` |
| the IEEE registers of network cards | `Daemon.mac_fetch` | `proxy_mac` |

Each request is asked again against `proxy_no` - a redirect too: a redirect
to an address reached straight goes there straight, without the password.
With the proxy and a use on, `no_proxy` and `https_proxy` of the environment
are not looked at for that use; `proxy_no` alone says what goes straight.

HTTPS goes through a tunnel (`CONNECT host:443`): the proxy sees the name and
the port, never what is said inside, and the certificate at the end is
checked as it always is. The user name and the password go to the proxy in
`Proxy-Authorization` (Basic), on the connection to the proxy - which, as with
every HTTP proxy, is plain HTTP: a proxy on a network of your own, then.

## What never goes through it

Offered nowhere, always as before: the firewalls and routers (MikroTik's API
and ssh, OPNsense's and pfSense's APIs and ssh - `fw_http`, `RosApi`, ssh),
Active Directory (LDAP), the database, syslog, the destinations of the
backups (FTP, FTPS, SFTP, SCP, SMB), DNS (the names of addresses, the ACME
checks of the TXT record, deSEC's name servers, nsupdate for RFC 2136), the
time servers (chrony), *Automatic certificates → Try port 80* (this server's
own name on port 80, asked as the CA would - `ProxyHandler({})`, as otp), the
dashboard's own API (PHP to the daemon) and the command line's road to the
daemon (`api_call`, 127.0.0.1). isemon sends no mail.

## dnf and apt

The daemon hands the proxy - with the user name and the password - to root's
helper in its request (`osup.ask`, a file of the isemon account's alone,
0600, taken away as it is read). The helper keeps it for the work about to
start in `/run/isemon-osup-proxy.json` (root's, 0600); the work - a unit of
its own - reads it into its own environment (`http_proxy`, `https_proxy`,
`HTTP_PROXY`, `HTTPS_PROXY`, and `no_proxy` from `proxy_no`) and takes the
file away at once. dnf, `dnf needs-restarting`, apt-get and
unattended-upgrade read the proxy from there. It is never on a command line,
never in what the work writes (`osup.json`), and only root reads a root
process's environment (`/proc/PID/environ`). A proxy that is not an
`http(s)://` address is refused by the helper.

## Try it

Below the settings, *Try it* asks an address from this server through the
proxy as it is saved - whichever uses are switched on - or straight where none
is set (or it is off) or the address is in `proxy_no`; it always tries, and
says why it went straight. Empty: where the new versions are
looked for (`upgrade_url`). It draws the way it went - this server, the proxy
(with a password or not), the address - each link green, or red where it
stopped, and every step with its time:

- the proxy looked up, connected to the proxy, a tunnel through the proxy to
  host:port (CONNECT), TLS and the certificate of the host checked, asked for
  the path (HEAD) - through the proxy;
- the host looked up, connected to it, TLS, asked for the path - straight.

What went wrong is said in words: the name not known, nothing answers on that
port, no answer in time, the certificate not trusted, *the proxy asks for a
user name and a password (407) - they are missing / wrong*, *the proxy said
403 Forbidden*. With the setting off and `https_proxy` in the service's
environment, the way drawn is that proxy's (*https_proxy of the service*).

From the command line:

    isemon --proxy-test                       # the upgrades' address
    isemon --proxy-test https://example.cz/   # an address of your own
    isemon --proxy-test URL --json            # the same, as JSON

It prints the way and each step with its time, and ends 0 when the address
answered, 1 when it did not. The console has it under *Network, time and
power → 10 The way out (proxy): try it*.

## Differences from otp

- One server: no nodes - *Try it* is asked of this server and answered at
  once, not of every node.
- A switch for every use, all off by default (otp has the proxy for its web
  requests and two switches, `proxy_os` and `proxy_sms`, on by default): the
  new versions, the system updates, the ACME CA, the DNS APIs, the public
  lists, GeoIP, the register of network cards. No SMS gateway here.
- Off, the service's environment (`https_proxy`) still holds, as it did
  before 1.10.268: an installation that set one keeps it.
- The helper's file is taken away as soon as the work has read it (otp keeps
  it until the next request).
- No *High security* here, so no rule about a proxy without a password.
