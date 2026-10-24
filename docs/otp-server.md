# otp: the token server that replaced totpcgi

isemon reads two kinds of token server through the same two files, and needs
no setting to tell them apart:

- **totpcgi** behind FreeRADIUS, as it always has. The token lines come from
  totpcgi and the packets from FreeRADIUS's detail files, shipped as
  described in [otp-radius-detail.md](otp-radius-detail.md).
- **otp** (1.0.x), which is both of those at once: a RADIUS server and a token
  server in one program. It writes the same two lines itself (`totp.cgi` and
  `radius-detail`) and sends them over syslog. Its own `docs/isemon.md` says
  how.

Settings → *The OTP logs*: switched on, the folder of each server in its
paths (`/var/log/remote/otp1`, `/var/log/remote/otp2`, ...), and *RADIUS
detail* switched on.

## What otp writes that totpcgi never did

otp 1.0.76 and later can send a **code by SMS or by mail** instead of using
an app. The VPN asks twice: first the directory password, then (in a second
window) the code. In RADIUS terms that is an Access-Challenge with a `State`,
and a second Access-Request that carries the same `State` back:

```
radius-detail: ... Packet-Type = Access-Challenge, State = 0x6f747031..., \
    Reply-Message = "Type the code sent by SMS to +420******123", Totp-Request-Id = "..."
totp.cgi: Success: user=jnovak@example.local, mode=PAM_SM_AUTH, host=127.0.0.1, \
    rid=127.0.0.1:33033, message=Code sent by SMS accepted
```

isemon 1.10.226 reads all of it:

| What otp writes | What the page shows |
|---|---|
| `Code sent by SMS accepted`, `Code sent by mail accepted` | *a code by SMS / by mail was right* (Logins → OTP) |
| a wrong code in the second window (`Not a valid token`) | *the token was wrong*, marked **by SMS** / **by mail** / **from the app** |
| the question in the second window | *How the code came* in the opened record, with the masked number or address |
| `mode=PROVISION`, `ADMIN`, `…-DRY` | marked *on the enrolment page*, *confirmed by an administrator*, *a test by an administrator*: not a sign-in |
| `Rate-limit reached…`, `Locked out…`, `This token is switched off`, `…not been confirmed yet`, `The key of this token cannot be opened…`, `No token is enrolled…` | each in words of its own, translated |
| the four sentences written while a new token is confirmed, `Token confirmed`, `Not in the groups of the realm …: may not enrol` | each in words of its own |
| an Access-Reject with no reason and no token line | *refused before a code was looked at*: a wrong directory password, an account outside the realm's groups, a code that ran out. otp sends no reason back unless `radius_reject_reason` is on; the reason itself is in otp's own log |
| a code sent and never typed (no request ever came back with that `State`, 15 minutes on) | *a code by SMS / by mail was sent and never typed*: the SMS that did not arrive |

A question asked by one node and answered on the other (otp keeps the
`State` in its database so that either node of a cluster takes the answer)
is still put together: the `State` is looked for on every server.

## A request and its reply a second apart

FreeRADIUS writes a request and its reply with the same second, the one the
request came in. otp writes the reply with the moment it went out, which
after a directory, a group lookup or an SMS gateway is often the next second.
Up to 1.10.225 isemon kept those as two rows - a request nobody answered and
an answer to nobody. From 1.10.226 the two halves are one row whenever they
are up to 15 seconds apart, from the same server and the same client port; a
one-time repair puts the rows already written together.

## Nothing is judged

Exactly as before: no address in either file counts towards a ban, and
nothing here is ever blocked.
