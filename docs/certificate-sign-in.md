# Signing in with a certificate (a smart card, a YubiKey)

isemon can sign an administrator in with a certificate issued by the domain's
own authority (AD CS). The certificate can be on a smart card, on a YubiKey
(PIV), or in the computer. No password is typed: the browser offers the
certificate, and Windows asks for the card's PIN. Built after otp 1.0.275.

## The rules it keeps

1. **Off by default.** While it is off, nothing is offered and no port is
   opened.
2. **A port of its own** (8443). nginx asks for a certificate only there,
   never on 443. Nobody who opens the pages is asked for one, and nothing but
   the sign-in is served on that port.
3. **isemon checks the certificate**, not nginx:
   - the chain to the authorities put in;
   - the dates;
   - a key usage for signing in (Client Authentication or Smart Card Logon);
   - revocation, by the CRL at the certificate's CRL Distribution Point;
   - the person in AD, found by the UPN in the certificate, with the SID of
     KB5014754.
4. **The second step stays.** With Face ID on, it is asked after the
   certificate exactly as after a password.
5. **Only people of the directory**, with the role their groups give. One
   person is one account: the same `sAMAccountName` account as a password or
   Windows (Kerberos) sign-in. A local account of isemon keeps its password.
6. **"No password at all"** (optional): see below.

## Setting it up

### 1. AD CS (once)

1. A certificate template made from *Smartcard Logon* (or *User*):
   - *Subject Name* built from AD, with the *User principal name (UPN)* in the
     Subject Alternative Name;
   - the key usages *Client Authentication* and *Smart Card Logon*;
   - published on the issuing authority.
2. The authority's *Extensions*: a CRL Distribution Point over **http** that
   the isemon server can reach. The default `http://<server>/CertEnroll/...`
   is fine.
3. A YubiKey (PIV): enrol it from Windows with the template (smart card
   enrolment, `certreq`), or with YubiKey Manager: a request from slot 9a,
   signed by the authority and imported back to 9a.

### 2. isemon

*Settings → Active Directory*, with the directory set up for administrators:

- **Sign in with a certificate (a smart card, a YubiKey)**: the switch.
- **The certificate's own port**: 8443 by default. SELinux already allows it
  as `http_port_t`. 80, 443 and the ports of the logs and databases are
  refused.
- **Which account a certificate is**:
  - `compat` (default): if the certificate carries the SID that AD CS writes
    since KB5014754, it must be the account's;
  - `strong`: the certificate must carry that SID (Microsoft's full
    enforcement);
  - `upn`: the UPN alone.
- **...by itself when the sign-in page opens**: the page goes to the
  certificate's port at once. The browser offers its certificate, the card
  asks for its PIN, and the form is shown only when that did not work. Off:
  a button "Sign in with a certificate" under the form.
- **Check that a certificate is not revoked (CRL)**: on by default. The CRL is
  kept until its next update. If no CRL can be fetched, nobody signs in (fail
  closed). The last CRL is used until its next update while the address is
  down for a moment.

The card **Signing in with a certificate** shows:

- **the authorities**: *Put in an authority…* takes PEM, `.cer` or `.p7b`. A
  person's certificate is refused. Each authority can be taken away again.
  Put in the issuing authority **and** its root.
- **the CRLs fetched**, with their next update or what went wrong;
- **nginx**: whether its server on the port is in place;
- **Try my certificate**: goes to the port, where the browser offers its
  certificate, and says who it would sign in and as what. Nobody is signed in.
  This is the best way to find a wrong template before telling people.

When the sign-in is switched on and an authority is in, the root helper does
three things within a minute:

1. It adds a **server of isemon's own** at the end of the dashboard's nginx
   file, between two marked lines. It is taken away whole when the sign-in is
   switched off. Nothing else in the file is touched. The server:
   - listens on the certificate's port;
   - uses the dashboard's own name, certificate, PHP and *Who may reach which
     page* lines;
   - sends the authorities' names (`ssl_client_certificate`), so the browser
     offers only fitting certificates;
   - uses `ssl_verify_client optional_no_ca`: nginx asks, isemon checks;
   - serves only `index.php?api=cert-login` and `cert-check`, and 404 for
     everything else.
2. It writes the authorities to `/etc/nginx/certs/isemon-client-ca.pem`.
3. It opens the port in isemon's firewall from where the dashboard is reached
   (*Settings → Firewall and access*).

Run `./install.sh --upgrade` once, for the new root helper.

### 3. The browsers and the network

- The browsers need no setting. Edge and Chrome can pick the certificate by
  themselves with the policy `AutoSelectCertificateForUrls`.
- Behind a load balancer, the port must reach the server as plain TCP (TLS
  passthrough). A balancer that ends TLS cannot hand on the browser's
  certificate.

## How it works

```
browser (443)                    browser (:8443)                       isemon
 │ "Sign in with a certificate"
 │ POST ?api=cert-nonce ──► a nonce in an HttpOnly SameSite=Strict cookie, the port's address
 │ location.href = https://name:8443/index.php?api=cert-login&n=<nonce>
 │                               │ TLS: nginx sends the authorities' names; the browser offers a
 │                               │ certificate of them - the card's PIN
 │                               │ nginx (optional_no_ca) ─► PHP: SSL_CLIENT_CERT (escaped PEM)
 │                               │ PHP: the nonce == its cookie? ─► /api/auth/cert {cert} ──────► │
 │                               │                       chain to the authorities, dates, key usage
 │                               │                       the CRL at its CDP (kept until next update)
 │                               │                       UPN ─► AD: one entry, on, not locked,
 │                               │                       not expired, SID == objectSid, groups
 │                               │ ◄─────────────────────────── {token, second} │ a session
 │                               │ Set-Cookie session (cookies are not kept apart by port)
 │ ◄──── 303 https://name/ (signed in, or ?certsaid=<why>)
 │ second step owed? → Face ID
```

- **Why the nonce**: it stops a page of somebody else's from signing a
  browser in with whatever certificate the browser has (login CSRF). It is
  used once, lasts five minutes, and is HttpOnly and SameSite=Strict.
- **Why the CRL comes after the chain**: the CRL's address is read only from
  a certificate that one of the authorities signed.
- **Why the SID**: a UPN can be given to somebody else; the SID in the
  certificate cannot be moved.

What is refused, and said on the sign-in page and in *Events* as a warning:

- the certificate: of an authority, of another authority, run out, revoked,
  not for signing in, with no UPN, or whose CRL cannot be fetched;
- the person: not in the directory, more than one entry, switched off, locked
  out or expired in the directory, or in no group with a role;
- the SID: another account's SID (`compat`, `strong`), or no SID at all
  (`strong`);
- here: an account switched off here, or a local account of the same name;
- the request: no nonce or a nonce of another browser, or no certificate
  offered.

## With Windows (Kerberos) as well

Both can be on together. Each is a button under the form, or is tried by
itself when the page opens. When both are tried by themselves:

1. Windows goes first, silently.
2. The certificate is tried only when this computer has no Windows ticket -
   a computer outside the domain with a smart card.
3. A refusal of either stops there and says why.

Nothing is tried by itself again in that tab after *Sign out* or after a
refusal. The card *The sign-in page* shows what a person meets.

## No password at all

**...and no password at all - only Windows or a certificate**:

- the sign-in page offers no name and password;
- a password sign-in is refused, local accounts' too;
- no password is set or changed on the pages.

It can be switched on only from a session opened by Windows or by a
certificate, and it is in effect only while one of the two is on. The last
authority cannot be taken away while it alone signs people in. **The way
back**, as root on the server:

```bash
isemon --set password_off=0
```

or `isemon --set certlogin=0`.

## Testing without a domain

`test/fixes341_certlogin.py` makes an AD CS of its own with openssl
(`test/pki_certlogin.sh`): a root, an issuing authority, its CRL served over
http, and a person's certificate for every case. It checks every refusal
above, the authorities, `compat`/`strong`/`upn`, the CRL switched off, the
second step, and "no password". It then checks nginx's server as the root
helper writes it, put in and taken away. Where nginx and php-fpm are
installed, it also makes the whole round through them with a client
certificate: the nonce on 443, the sign-in on the port, the session back on
443, the refusals, and nothing else served on the port. In Playwright:
`newContext({clientCertificates: [{origin: 'https://name:8443', certPath,
keyPath}]})`.
