# Automatic certificates - ACME (1.10.251)

*Settings → Access → Automatic certificates*, for a full administrator, off
until switched on. The certificate the dashboard answers with is ordered from
an ACME CA and renewed by itself when fewer than `acme_days` (30) days are left
- or, for a certificate that lasts less (short-lived certificates, a test CA),
when a third of its life is left. It is looked at once an hour; a failed try is
tried again after 6 hours. The certificate and its key go exactly where an
uploaded one goes ([certificates-and-tls.md](certificates-and-tls.md)): kept in
the database, the key sealed, put into nginx by root's helper. The TLS settings
(protocols, ciphers, DH, HSTS) stay as they are, whichever way the certificate
came, ACME's renewals too.

This is otp's *Automatic certificates* (otp 1.0.169 - 1.0.187) for one server:
there is one certificate - the dashboard's - and no VIP address, no other node.

| Setting | |
|---|---|
| `acme` | on or off |
| `acme_ca` | Let's Encrypt, its staging (to try - browsers do not trust it), or another (`acme_url`, `acme_ca_pem` for its root): step-ca, an internal CA |
| `acme_email` | where the CA writes when a certificate runs out unrenewed |
| `acme_name` | the DNS name of the certificate; empty: the name of the certificate it has now, else this machine's full host name |
| `acme_days` | renewed when fewer days are left (7 - 60) |
| `acme_key` | ECDSA P-256 or RSA 2048 |
| `acme_challenge` | HTTP-01 or DNS-01 |
| `acme_resolvers` | DNS servers for ACME (below) |

The account key (ECDSA P-256) is made once and kept sealed in the database;
every request is signed with it (ES256, with openssl - nothing to install). An
account the CA no longer knows (deleted, deactivated, a CA of the same address
started anew) is made anew by itself, with a new key, and the request asked
again. Every order is an event - who asked it (or `isemon (renewal)`), what
came, or why nothing did.

## The page

- **The card of the dashboard**: the days left, the name, who issued it, when it
  was last ordered, how the CA checks it; *What the last order did*, step by
  step with the seconds; the last failure in words.
- While it is ordered, the line above the card says **what is waited for now**
  - root putting port 80's location in, *Wait for DNS to carry it* with the
  seconds left, deSEC's name servers (which have the record so far, how long),
  the minute for deSEC's other places, *It is in DNS* by hand.
- *Try port 80* (HTTP-01): `http://NAME/.well-known/acme-challenge/` asked from
  this server, as the CA will - whether it reaches isemon. A firewall in front of
  the server may still stop the CA from outside.
- *Order it now*; *Look after it* / *Leave it alone*; *Its name…*; *Back to the
  one before…* (below).
- **In your DNS**: what the name needs there for the way chosen, with the steps
  and *Check DNS*, which looks each record up from this server as the CA will.

## Who renews it

The card - and Certificates and TLS - says who renews the certificate: *ACME
renews it*, or *its own certificate is kept*.

- Switching ACME on takes in a dashboard with no certificate of isemon's (the one
  `install.sh` made) or a self-signed one.
- **One uploaded, or answered to a request (a CA of your own), is kept as it is**:
  ACME does not replace it until *Look after it* (or *Order it now*).
- Putting a certificate in by hand on *Certificates and TLS* - upload,
  self-signed - while ACME renews it takes it out of ACME's care (the page asks
  first); *Let go* too.
- A certificate ACME replaced is kept, its key as sealed as it was: **Back to the
  one before…** (on the card, and on Certificates and TLS) puts it back, and ACME
  then leaves it alone. Not offered once it has run out.

The certificate has the name as its subject (CN) and among its alternative names
(SAN). An ACME CA checks only names: the request isemon makes has nothing else.
For a certificate with an organisation, a unit or a city, use *Certificates and
TLS → Request (CSR)* and a CA of your own.

## HTTP-01 - the CA asks port 80

nginx's port-80 server sends `http://NAME/.well-known/acme-challenge/TOKEN` to
`acme.php`, which asks the daemon (`/api/acme/challenge`) for the answer kept in
the database while an order waits on that token - nothing else is ever said.
Root's helper puts in, while HTTP-01 is chosen:

```
    # isemon-acme-begin (Settings - Automatic certificates)
    location ^~ /.well-known/acme-challenge/ {
        allow all;
        limit_req zone=isemon_all burst=20 nodelay;
        fastcgi_pass   unix:/run/php-fpm/www.sock;      # as the HTTPS server's .php has it
        include        fastcgi_params;
        fastcgi_param  SCRIPT_FILENAME /var/www/isemon/acme.php;
        fastcgi_read_timeout 10s;
    }
    # isemon-acme-end
    location / {
        return 301 https://$host$request_uri;
    }
```

- **For everybody**, whoever *Who may reach which page* lets in: the CA asks from
  wherever it is. The redirect to HTTPS of the server itself is moved into
  `location /` - a `return` of the server's own is done before any location is
  looked at.
- The name goes into that server's `server_name`.
- **isemon's own firewall** lets tcp 80 in from anywhere by itself while HTTP-01
  is used - its own card under *Firewall and access → What isemon lets in by
  itself*, *Automatic certificates (HTTP-01)*, which can be turned off like the
  others. A firewall in front of the server has to let it in too.
- Before the CA is asked, the order waits for root to have put it in (two
  minutes at most).

The name must point at this server (or at the address in front of it that
reaches its port 80).

## DNS-01 - nothing open to the internet

For a server the CA cannot see: the CA reads `_acme-challenge.NAME TXT`. Who puts
it there (`acme_dns`):

- **RFC 2136** (BIND, PowerDNS, Knot, ...): `nsupdate` (`dnf install bind-utils`)
  with a TSIG key - `acme_dns_server`, `acme_dns_zone`, `acme_dns_tsig_name`,
  `acme_dns_tsig_alg`, `acme_dns_tsig_secret` (sealed). The key is written to a
  file only isemon reads (0600) for the moment nsupdate runs - never on its
  command line. On BIND, a key allowed to change only that record:

  ```
  tsig-keygen -a hmac-sha256 isemon-acme. > /etc/named/isemon-acme.key
  zone "example.cz" {
      ...
      update-policy { grant isemon-acme. name _acme-challenge.isemon.example.cz. TXT; };
  };
  ```
- **Cloudflare**: `acme_dns_token` (sealed), a token with *Zone - DNS - Edit*.
- **acme-dns**: `acme_dns_url`, `acme_dns_user`, `acme_dns_key` (sealed),
  `acme_dns_subdomain` from its registration; `_acme-challenge.NAME` a CNAME to
  `SUBDOMAIN.auth.example.cz` once.
- **deSEC** (free - desec.io): `acme_desec_domain` (your domain there,
  `yourname.dedyn.io` or one of your own whose DNS is at deSEC) and
  `acme_desec_token` (sealed). A name outside that domain gets a CNAME in your
  DNS, once - see below. deSEC's records live at least an hour (its minimum TTL).
  isemon asks deSEC's own name servers (`ns1.desec.io`, `ns2.desec.org` - asked
  straight, never through a resolver) until both have the record, then waits a
  minute more before it asks the CA: deSEC is anycast, and the CA checks from
  several places of the world - one deSEC had not reached yet answers
  `During secondary validation: NXDOMAIN`.
- **By hand**: the record is shown on the page; the order waits up to an hour
  for *It is in DNS* (or *Give the order up*). Renewals wait for you the same way.

After the record is put in, `acme_dns_wait` seconds (30) are waited for DNS to
carry it, and - except by hand and for deSEC - the record is looked for at the
DNS servers for ACME for up to two minutes before the CA is asked. It is taken
away again once the CA has looked (RFC 2136, Cloudflare, deSEC).

### A CNAME in your DNS, once

The CA follows a CNAME at `_acme-challenge.NAME`. So the TXT record can go into a
zone isemon may write to - deSEC, a zone at Cloudflare, one your BIND serves
(`acme_dns_alias`, *The TXT records go into*) - while your own DNS, wherever it
is and whether or not it has an API, only has one CNAME, put in once:

```
_acme-challenge.isemon.example.cz.   CNAME  _acme-challenge.isemon.yourname.dedyn.io.
```

**A domain of your own at deSEC** (`acme.example.cz` rather than a free
`yourname.dedyn.io`): the zone above it must send the internet there - once, in
`example.cz`, wherever its DNS is kept:

```
acme.example.cz.   NS   ns1.desec.io.
acme.example.cz.   NS   ns2.desec.org.
```

(and the DS records deSEC shows, if `example.cz` is signed with DNSSEC). Without
them the CA follows the CNAME into a name nobody serves and says `NXDOMAIN looking
up TXT for _acme-challenge.NAME` - though the record is there at deSEC. A
`dedyn.io` domain is delegated by deSEC itself. An order that fails so says where
to look.

The card **In your DNS** lists exactly these (and, for HTTP-01, where the name is
to point), with the steps of the way chosen and **Check DNS**.

## DNS servers for ACME

`acme_resolvers` - public ones (`1.1.1.1, 9.9.9.9`) are asked for everything on
this page: the address of the CA and of the DNS API, *Check DNS*, *Try port 80*,
and whether the TXT record can be seen before the CA is asked. Empty: the
machine's own (`/etc/resolv.conf`). *Check DNS* done with the machine's own says
that they may see what the internet does not. Every other name the daemon looks
up stays the machine's.

The CA and the DNS APIs are reached over HTTPS, through the proxy in the
service's environment (`https_proxy`) where there is one.

## No DNS server of your own, nothing open to the internet

DNS-01 needs the CA to read a TXT record of the name - so whoever keeps the DNS
of the domain has to let isemon put it there:

- **deSEC** (free): an account and a free domain (`yourname.dedyn.io`), a token,
  and one CNAME in your own DNS - once. isemon needs only to reach `desec.io` and
  the CA over HTTPS. Renewals go by themselves.
- **Cloudflare** (free plan): move the DNS of the domain to Cloudflare, make an
  API token with *Zone - DNS - Edit* for that zone, choose *Cloudflare*.
- **acme-dns**: one CNAME, put in once, and the acme-dns server takes the records
  from then on.
- **The DNS provider's own API** (other than Cloudflare): not built in - delegate
  `_acme-challenge.NAME` by a CNAME to a zone at deSEC or Cloudflare instead.
- **A CA of your own** (step-ca, an internal ACME CA): HTTP-01 inside the network,
  nothing on the internet at all - for browsers that trust that CA.

## The command line and the console

```
isemon --acme                 # the certificate: its name, its end, who looks after it, its last order
isemon --acme --json
isemon --acme-order this      # order it now, followed until it is done (`all` is the same: one server)
isemon --set acme=1 --set acme_ca=letsencrypt-staging ...
```

The console: *Network, time and power → Automatic certificates (ACME)*.

## Kept in the database (meta)

| Key | What |
|---|---|
| `acme:account` | the account at the CA: its key (sealed), its URL, the mail |
| `acme:state` | the last order: when, by whom, what came, its steps, why it failed |
| `acme:care` | whether ACME looks after the certificate, when said on either page |
| `acme:before` | the certificate ACME replaced, its key sealed, for *Back to the one before* |
| `acme:chal:TOKEN` | the HTTP-01 answer while an order waits on it |
| `acme:manual` | the TXT record waiting to be put in by hand |

Nothing of it is in a log line or an event; nothing of it is on a command line.
