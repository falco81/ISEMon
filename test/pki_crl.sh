#!/bin/bash
# (isemon 1.10.347, test/fixes347_crl.py: from the CRL revocation kit of acme 1.0.104.)
# crl-pki.sh DIR [PORT] - a test PKI with CRLs, as AD CS publishes them, made with openssl alone.
# Adapted from acme 1.0.104 test/test_cert_login.py (PKI_SH) and the earlier kit's testing/pki.sh.
#
#   root.pem      "Corp Root CA"     - no CDP of its own (a root is its own anchor: never checked)
#   issuing.pem   "Corp Issuing CA"  - CDP  http://127.0.0.1:PORT/root.crl   (the root's CRL)
#   cas.pem       issuing + root     - what the administrator "puts in"
#   people (all with UPN in the SAN, Client Authentication + Smart Card Logon):
#     alice        good                                   CDP issuing.crl
#     bob-revoked  revoked in the BASE CRL                CDP issuing.crl
#     carol-old    run out (2020-2021)                    CDP issuing.crl
#     dave-nocdp   CDP at a port nobody answers on        CDP http://127.0.0.1:PORT+1/nowhere.crl
#     erin-delta   revoked in the DELTA CRL only          CDP issuing.crl + Freshest CRL issuing-delta.crl
#     frank-sub    issued by "Corp Old CA", which the ROOT revoked (root.crl)  CDP sub.crl
#   www/          the CRLs in DER as AD CS serves them: issuing.crl, issuing-delta.crl, root.crl, sub.crl
#
# Serve them:  python3 -m http.server --bind 127.0.0.1 --directory DIR/www PORT
# Check them:  ./check.sh DIR [PORT]      (every case, by openssl verify -crl_check_all -use_deltas)
# Only test data: names under corp.example, made-up SIDs, keys made here and nowhere else.
set -e
D=$(readlink -f "${1:?usage: crl-pki.sh DIR [PORT]}")
PORT=${2:-18890}
NOPORT=$((PORT + 1))
U="http://127.0.0.1:$PORT"
mkdir -p "$D"
cd "$D"
if [ -f done ]; then echo "pki ready in $D (rm -rf it to make it again)"; exit 0; fi
cat > ca.cnf <<EOF
[ca]
default_ca = issuing
[issuing]
dir = $D/db
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $D/issuing.pem
private_key = $D/issuing.key
default_md = sha256
default_days = 365
default_crl_days = 7
policy = anything
copy_extensions = none
unique_subject = no
[anything]
commonName = supplied
[root_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[issuing_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:$U/root.crl
[person]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
[person_nocdp]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:http://127.0.0.1:$NOPORT/nowhere.crl
[person_delta]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
freshestCRL = URI:$U/issuing-delta.crl
[person_sub]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/sub.crl
EOF
mkcnf() { # file folder certificate key - a small "openssl ca" of another authority
  sed -e "s#^dir = .*#dir = $D/$2#" -e "s#^certificate = .*#certificate = $D/$3#" \
      -e "s#^private_key = .*#private_key = $D/$4#" -e 's#^default_crl_days = .*#default_crl_days = 30#' ca.cnf > "$1"
  mkdir -p "$2/new"; : > "$2/index.txt"; echo 2000 > "$2/serial"; echo 2000 > "$2/crlnumber"
}
mkdir -p db/new www
: > db/index.txt
echo 1000 > db/serial
echo 1000 > db/crlnumber
export UPN=x
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/DC=example/DC=corp/CN=Corp Root CA" -config ca.cnf -extensions root_ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout issuing.key -out issuing.csr \
  -subj "/DC=example/DC=corp/CN=Corp Issuing CA" 2>/dev/null
openssl x509 -req -in issuing.csr -CA root.pem -CAkey root.key -CAcreateserial -out issuing.pem \
  -days 1825 -extfile ca.cnf -extensions issuing_ext 2>/dev/null
cat issuing.pem root.pem > cas.pem
person() {   # name upn extensions [startdate enddate] [config]
  local n=$1 cnf=${6:-ca.cnf}
  export UPN=$2
  openssl req -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$n" 2>/dev/null
  if [ -n "$4" ]; then
    openssl ca -batch -config "$cnf" -extfile ca.cnf -extensions "$3" -in "$n.csr" -out "$n.pem" \
      -notext -startdate "$4" -enddate "$5" >/dev/null 2>&1
  else
    openssl ca -batch -config "$cnf" -extfile ca.cnf -extensions "$3" -in "$n.csr" -out "$n.pem" \
      -notext >/dev/null 2>&1
  fi
}
person alice alice@corp.example person
person bob-revoked bob@corp.example person
person carol-old carol@corp.example person 20200101000000Z 20210101000000Z
person dave-nocdp dave@corp.example person_nocdp
person erin-delta erin@corp.example person_delta
# The BASE CRL: bob revoked.
openssl ca -config ca.cnf -revoke bob-revoked.pem >/dev/null 2>&1
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
# The DELTA CRL (Delta CRL Indicator = the base's number): erin revoked after the base was published.
openssl ca -config ca.cnf -revoke erin-delta.pem >/dev/null 2>&1
BASE=$(openssl crl -in issuing.crl.pem -noout -crlnumber | cut -d= -f2)
( cat ca.cnf; printf '[delta_ext]\n2.5.29.27 = critical,ASN1:INTEGER:%s\n' "$BASE" ) > delta.cnf
openssl ca -config delta.cnf -gencrl -crlexts delta_ext -crldays 1 -out delta.crl.pem >/dev/null 2>&1
openssl crl -in delta.crl.pem -outform DER -out www/issuing-delta.crl
# An issuing authority the ROOT revokes, and a person of it (the authority above is checked too).
mkcnf root.cnf rdb root.pem root.key
openssl req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "/DC=example/DC=corp/CN=Corp Old CA" 2>/dev/null
openssl x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -out sub.pem \
  -days 1000 -extfile ca.cnf -extensions issuing_ext 2>/dev/null
mkcnf sub.cnf sdb sub.pem sub.key
person frank-sub frank@corp.example person_sub "" "" sub.cnf
openssl ca -config sub.cnf -gencrl -out sub.crl.pem >/dev/null 2>&1
openssl crl -in sub.crl.pem -outform DER -out www/sub.crl
openssl ca -config root.cnf -revoke sub.pem >/dev/null 2>&1
openssl ca -config root.cnf -gencrl -out root.crl.pem >/dev/null 2>&1
openssl crl -in root.crl.pem -outform DER -out www/root.crl
cat issuing.pem root.pem sub.pem > cas-sub.pem
rm -f ./*.csr
touch done
echo "pki ready in $D - serve it: python3 -m http.server --bind 127.0.0.1 --directory $D/www $PORT"
