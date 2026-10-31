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
| `/etc/nginx/certs/isemon-ca.pem` | the root and the chain, for `ssl_trusted_certificate` |
| `/etc/nginx/certs/isemon-dh.pem` | the DH parameters, when chosen |
| `/etc/nginx/certs/isemon.pem.before-isemon` | the pair that was there, kept once, the first time |

The lines `ssl_certificate`, `ssl_certificate_key`, `ssl_trusted_certificate`,
`ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `ssl_dhparam`
and `add_header Strict-Transport-Security` of the HTTPS server are set where
they are (or added after `server_name`); nothing else in the vhost changes.
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

## Request (CSR)

*Request (CSR)*: the name (CN), other names (names or addresses), the key
(RSA 2048/3072/4096 or EC P-256), organisation, unit, city, country. The key
is made here and stays here, sealed; copy or download the request, give it
to your CA, then *Upload* only the certificate it sends back - it is matched
to the waiting key. *Drop the request* throws the key away.

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
