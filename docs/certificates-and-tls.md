# The certificate, and how the dashboard speaks TLS

*Settings → This server → Certificates and TLS* (isemon 1.10.222). A full
administrator, put in place by root (`isemon_web.py`, see
[firewall-and-access.md](firewall-and-access.md) for how). Until something is
done there, nginx keeps the certificate `install.sh` made (or the one the site
put in) and the TLS lines the vhost has.

The certificate can also be ordered from an ACME CA (Let's Encrypt) and renewed
by itself: *Settings → Automatic certificates*
([automatic-certificates.md](automatic-certificates.md), 1.10.251). It goes in
here exactly as an uploaded one does, and the card says who renews it. Uploading
one or making one self-signed while ACME renews it takes it out of ACME's care -
asked first.

## What is kept, and where

The certificate, its chain and its root are kept in the database; **its key
too, sealed** with `settings.key` like every other secret. So a copy of the
database carries the certificate, and a full backup carries the key that
opens it ([the-database.md](the-database.md)). Root writes:

| File | What |
|---|---|
| `/etc/nginx/certs/isemon.pem` | the certificate and the chain (nginx sends it as it is) |
| `/etc/nginx/certs/isemon.key` | its key, 0600 |
| `/etc/nginx/certs/isemon-ecdsa.pem` | dual-cert only: the ECDSA certificate beside the RSA one, and its chain ([automatic-certificates.md](automatic-certificates.md)) |
| `/etc/nginx/certs/isemon-ecdsa.key` | its key, 0600 - both taken away when there is no second certificate |
| `/etc/nginx/certs/isemon-ca.pem` | the root and the chain, for `ssl_trusted_certificate` |
| `/etc/nginx/certs/isemon-dh.pem` | the DH parameters, when chosen |
| `/etc/nginx/certs/isemon.pem.before-isemon` | the pair that was there, kept once, the first time |

The lines `ssl_certificate`, `ssl_certificate_key`, `ssl_trusted_certificate`,
`ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `ssl_dhparam`
and `add_header Strict-Transport-Security` of the HTTPS server are set where
they are (or added after `server_name`); nothing else in the vhost changes.
With a second certificate (dual-cert, by ACME) there are two `ssl_certificate`
and two `ssl_certificate_key` lines, the RSA pair first, each certificate
followed by its key; without, exactly one pair. The card's *Key* says both
(`RSA 2048 bit + EC 256 bit (a second certificate beside it)`); an upload or a
self-signed certificate takes the second one away.
`nginx -t` is asked before the reload, and every file goes back as it was
when it says no.

## Upload

*Upload* on the card. Drop the files, or paste PEM:

| You have | Send |
|---|---|
| `.pfx` / `.p12` (Windows, an export from a CA) | the file, with its password (old RC2/3DES files are read too) |
| `.crt` / `.cer` / `.pem` + `.key` | both; add the chain (intermediate) and the root if you have them |
| one `.pem` with everything | that file |
| a `.cer` that is DER | the file |
| a key with a passphrase | the key, and the passphrase as the password |

The certificates are sorted by themselves: the one that belongs to the key,
the chain up from it in order, the root (the one that signed itself). The
chain is checked against the root when a root is given. The password is used
once to open the file and is not kept. A certificate that ran out is refused.

## The chain

The web server sends the certificate **followed by its intermediate
authorities, nearest first** - never the root. Clients other than browsers
(Python, curl, openssl, Java, Go, rsyslog, acme's push, monitoring agents,
phone apps) trust only the roots of their own system: without the
intermediate they refuse the connection with *unable to get local issuer
certificate*. Browsers fetch a missing intermediate themselves, so they show
nothing wrong.

- **Upload** puts whatever was sent in order, from the certificate up (by
  subject and issuer, and by key id where two have one name), and leaves the
  root out of what is sent. When the chain is missing, or a link of it is,
  it is completed as a browser completes it: the *CA Issuers* address
  (Authority Information Access) of the last certificate is read - DER, PEM
  or PKCS#7 (`.p7c`), over http, at most four steps - until the chain leads
  to a root of the system (`/etc/pki/tls/certs/ca-bundle.crt`). What was read
  is kept only when the chain then checks out with `openssl verify
  -untrusted`, as a client checks it. When it cannot be completed (no CA
  Issuers address, the address cannot be reached), the certificate is still
  put in, with the warning in the message and in the events.
- **Certificates from acme** (push) and from **Automatic certificates** are
  served as `cert_pem + chain_pem` - the second one (`alt`, the other key
  type) too; a link the CA did not send is read the same way.
- **A company CA** (a certificate answered to a *Request (CSR)*): send the
  company's intermediates with it, and its root if you like - the root is
  kept to check the chain against, never sent. Clients must trust the
  company's root.

The card has a **Chain** line, in green or red:

| The line | When |
|---|---|
| `complete - 2 certificates up to DigiCert Global Root G2` | it checks out against the system's roots |
| `… (fetched: RapidSSL TLS RSA CA G1 - it was not sent with the certificate)` | completed from CA Issuers |
| `… - a private root: only clients that trust it take it` | it checks out only with the root kept beside it (a company CA) |
| `incomplete - the authority X is not sent and could not be completed (…)` | a link is missing and cannot be read |
| `it leads to X, a root the system does not trust (a private CA?)` | the chain is whole, but its root is not one of the system's |
| `self-signed - no chain; …` | the certificate signs itself (no chain buttons) |

**Root** names the root kept beside it (to check with; it is never sent), or
says *not given*.

- **Complete the chain** (when it is incomplete; otherwise **Check the
  chain**) checks the certificate in place again and reads what is missing
  from CA Issuers. An answer of *not complete* is a warning, not an error.
- **Upload the missing authority** (when it is incomplete): a dialog that
  names the authority missing and takes its certificate - PEM, or a
  `.cer`/`.crt`/`.p7c` file. Only certificates of authorities, never a key;
  the certificate and its key stay as they are. A root given there is kept
  to check with (a private CA) and never sent.

When isemon does not look after the certificate, the line tells what nginx
sends now.

After every change of the certificate the web server is asked **from this
machine** (`127.0.0.1` on its TLS port, with the certificate's name), as a
client that fetches no missing link asks it. The result is the card's
*Checked from here* line; a failure is an event (a warning), and so is the
first good answer after one. *Check from here* asks again now. By hand:

```bash
openssl s_client -connect monitor.example:443 -servername monitor.example -showcerts </dev/null
```

Two certificates or more (`0 s:CN=monitor.example`, `1 s:CN=…CA…`) and
`Verify return code: 0 (ok)` - the chain is complete; one certificate and
`Verify return code: 21 (unable to verify the first certificate)` - it is
not.

## Request (CSR)

*Request (CSR)*: the name (CN), other names (names or addresses), the key
(RSA 2048/3072/4096 or EC P-256), organisation, unit, city, country. The key
is made here and stays here, sealed; copy or download the request, give it
to your CA, then *Upload* only the certificate it sends back - it is matched
to the waiting key. *Drop the request* throws the key away.

## A dual certificate (RSA and ECDSA)

Two certificates for the same pages, each with its own key: RSA is answered
with by default, ECDSA to every client that takes it. *Upload* both pairs at
once - their PEM files (the two certificates, the two keys, the chains) in any
order, or two PFX files under one password; the RSA one is kept as the
certificate and the ECDSA one beside it. One RSA and one ECDSA only. One
certificate uploaded alone replaces both.

*Download* asks which: the first (RSA), the second (ECDSA), or both - a ZIP
with each in the format chosen, its chain and its own key. That ZIP (or one a
CA sends) goes back up as it is: *Upload* takes a ZIP and its files as though
each had been chosen (not one locked with a password).

## Self-signed

*Self-signed*: for a test, or until the real one comes; valid for 1 year to
10 years. Browsers warn until it is trusted by hand.

## TLS settings

| Choice | Protocols | Ciphers |
|---|---|---|
| **Standard** (what `install.sh` writes) | TLS 1.2, 1.3 | ECDHE with AES-GCM and ChaCha20 |
| **Mozilla intermediate** | TLS 1.2, 1.3 | the same plus DHE (for old clients), with ffdhe2048 |
| **Mozilla modern** | TLS 1.3 only | chosen by TLS 1.3 itself |
| **Custom** | TLS 1.2 and/or 1.3 | any OpenSSL cipher list (checked with `openssl ciphers`) |

- **DH parameters** - only DHE ciphers use them: none; an RFC 7919 group
  (ffdhe2048/3072/4096, ready at once); or made here (2048 bits takes
  seconds, 4096 up to ten minutes - the card shows how far it is).
- **The server chooses the cipher** (`ssl_prefer_server_ciphers`).
- **HSTS** - off, 6 months, 1 year, 2 years (`install.sh` sets two years).

*Let go* (on the card): isemon no longer changes TLS; nginx keeps the files it
has.

## When it runs out

The card says how many days are left (orange under 21). `isemon --check`
says it too, and fails once it has run out.

## Certificates from acme

acme - the certificate manager of ours - can give and renew this certificate
by itself: *Certificates from acme* on this pane, paired once with a code.
What it pushes goes in as an upload does. See [acme-push.md](acme-push.md).
