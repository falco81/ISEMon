#!/bin/bash
# kdc_krb5.sh DIR PORT - a Kerberos realm CORPNET.LOC of its own for
# test/fixes340_kerberos.py (MIT krb5-kdc on 127.0.0.1:PORT), made in DIR and
# started; its pid in DIR/kdc.pid. The people of the test's made-up directory,
# the web service's names (one keytab, http.keytab), a name in another keytab
# (other.keytab), and a ticket cache for each person (DIR/<name>.cc).
# From the Kerberos SSO kit of otp 1.0.274 (testing/kdc.sh).
set -e
PEOPLE='falco pkolar nogroups gone edvorak jnovak ghost admin twice'
D=$1
PORT=${2:-18888}
mkdir -p "$D"
cd "$D"
export KRB5_CONFIG=$D/krb5.conf KRB5_KDC_PROFILE=$D/kdc.conf
cat > krb5.conf <<EOC
[libdefaults]
  default_realm = CORPNET.LOC
  dns_lookup_kdc = false
  dns_lookup_realm = false
  rdns = false
[realms]
  CORPNET.LOC = {
    kdc = 127.0.0.1:$PORT
  }
EOC
cat > kdc.conf <<EOC
[kdcdefaults]
  kdc_ports = $PORT
  kdc_tcp_ports = $PORT
[realms]
  CORPNET.LOC = {
    database_name = $D/principal
    key_stash_file = $D/stash
    acl_file = $D/kadm5.acl
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  }
EOC
if [ ! -f "$D/principal" ]; then
  kdb5_util create -s -r CORPNET.LOC -P "$(head -c 18 /dev/urandom | base64)" >/dev/null 2>&1
  for p in HTTP/isemon.corpnet.loc HTTP/isemon2.corpnet.loc HTTP/other.corpnet.loc; do
    kadmin.local -q "addprinc -randkey $p" >/dev/null 2>&1
  done
  kadmin.local -q "ktadd -k $D/http.keytab HTTP/isemon.corpnet.loc HTTP/isemon2.corpnet.loc" >/dev/null
  kadmin.local -q "ktadd -k $D/other.keytab HTTP/other.corpnet.loc" >/dev/null
  for p in $PEOPLE; do
    kadmin.local -q "addprinc -randkey $p" >/dev/null 2>&1
    kadmin.local -q "ktadd -k $D/$p.keytab $p" >/dev/null
  done
fi
if ! { [ -f "$D/kdc.pid" ] && kill -0 "$(cat "$D/kdc.pid")" 2>/dev/null; }; then
  krb5kdc -r CORPNET.LOC -P "$D/kdc.pid"
  sleep 1
fi
for p in $PEOPLE; do
  KRB5CCNAME=FILE:$D/$p.cc kinit -k -t "$D/$p.keytab" "$p"
done
echo "kdc ready in $D"
