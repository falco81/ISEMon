#!/bin/bash
# (isemon 1.10.348, test/fixes348_ocsp.py.)
# pki_ocsp.sh DIR PORT - a test PKI with OCSP responders and a CDP in the directory:
#   root.pem     "Corp Root CA"     its responder: openssl ocsp on PORT+1 (index rootdb)
#   issuing.pem  "Corp Issuing CA"  issued by the root through `openssl ca` (so its responder knows
#                                    it); AIA OCSP http://127.0.0.1:PORT+1/, CDP http .../root.crl
#   ocsp-i.pem / ocsp-r.pem          the responders' signing certificates (OCSP Signing, noCheck)
#   people (UPN in the SAN, Client Authentication + Smart Card Logon):
#     alice    good                     AIA OCSP :PORT+2   CDP http :PORT/issuing.crl
#     bob      revoked (both)           AIA OCSP :PORT+2   CDP http
#     dan      responder dead           AIA OCSP :PORT+3   CDP http
#     eve      no AIA                   -                  CDP http
#     gina     CDP in LDAP only         -                  CDP ldap:///CN=Corp Issuing CA,...CN=CDP...
#     hal      revoked in the CRL only  AIA OCSP :PORT+2   CDP http   (the responder's index is older)
#     ida      not known to responder   AIA OCSP :PORT+2   CDP http
# Serve: DIR/www over http on PORT; the responders:
#   openssl ocsp -index DIR/ocsp-index.txt -port 127.0.0.1:$((PORT+2)) -rsigner DIR/ocsp-i.pem \
#     -rkey DIR/ocsp-i.key -CA DIR/issuing.pem -ndays 1
#   openssl ocsp -index DIR/rootdb/index.txt -port 127.0.0.1:$((PORT+1)) -rsigner DIR/ocsp-r.pem \
#     -rkey DIR/ocsp-r.key -CA DIR/root.pem -ndays 1
# Only test data: names under corp.example, keys made here and nowhere else.
set -e
D=$(readlink -f "${1:?usage: pki_ocsp.sh DIR PORT}")
P=${2:?port}
U="http://127.0.0.1:$P"
LDAPCDP='ldap:///CN=Corp%20Issuing%20CA,CN=pki,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=example?certificateRevocationList?base?objectClass=cRLDistributionPoint'
# A URI of commas can be written into a certificate only as DER: the CRL
# Distribution Points of it, made here.
LDAPDER=$(python3 -c '
import sys
def tl(t, b):
    n = len(b)
    h = bytes([n]) if n < 128 else (bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255]))
    return bytes([t]) + h + b
u = sys.argv[1].encode()
print(tl(0x30, tl(0x30, tl(0xa0, tl(0xa0, tl(0x86, u))))).hex().upper())' "$LDAPCDP")
mkdir -p "$D"
cd "$D"
if [ -f done ]; then echo "pki ready in $D"; exit 0; fi
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
[rootca]
dir = $D/rootdb
database = \$dir/index.txt
new_certs_dir = \$dir/new
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $D/root.pem
private_key = $D/root.key
default_md = sha256
default_days = 1825
default_crl_days = 30
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
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+1))/
[signer]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
1.3.6.1.5.5.7.48.1.5 = ASN1:NULL
[person]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+2))/
[person_dead]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$((P+3))/
[person_noaia]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:$U/issuing.crl
[person_ldap]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = DER:$LDAPDER
EOF
mkdir -p db/new rootdb/new www
: > db/index.txt; : > rootdb/index.txt
echo 1000 > db/serial; echo 1000 > db/crlnumber; echo 5000 > rootdb/serial; echo 5000 > rootdb/crlnumber
export UPN=x
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/DC=example/DC=corp/CN=Corp Root CA" -config ca.cnf -extensions root_ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout issuing.key -out issuing.csr \
  -subj "/DC=example/DC=corp/CN=Corp Issuing CA" 2>/dev/null
openssl ca -batch -config ca.cnf -name rootca -extensions issuing_ext -in issuing.csr \
  -out issuing.pem -notext >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout ocsp-r.key -out ocsp-r.csr -subj "/CN=Corp Root OCSP" 2>/dev/null
openssl ca -batch -config ca.cnf -name rootca -extensions signer -in ocsp-r.csr -out ocsp-r.pem \
  -notext >/dev/null 2>&1
cat issuing.pem root.pem > cas.pem
openssl req -newkey rsa:2048 -nodes -keyout ocsp-i.key -out ocsp-i.csr -subj "/CN=Corp Issuing OCSP" 2>/dev/null
openssl ca -batch -config ca.cnf -extensions signer -in ocsp-i.csr -out ocsp-i.pem -notext >/dev/null 2>&1
person() {   # name upn extensions
  export UPN=$2
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  openssl ca -batch -config ca.cnf -extensions "$3" -in "$1.csr" -out "$1.pem" -notext >/dev/null 2>&1
}
person alice alice@corp.example person
person bob bob@corp.example person
person dan dan@corp.example person_dead
person eve eve@corp.example person_noaia
person gina gina@corp.example person_ldap
person hal hal@corp.example person
openssl ca -config ca.cnf -revoke bob.pem -crl_reason keyCompromise >/dev/null 2>&1
cp db/index.txt ocsp-index.txt            # what the responder knows: hal good, ida not at all
person ida ida@corp.example person
openssl ca -config ca.cnf -revoke hal.pem >/dev/null 2>&1
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
openssl ca -config ca.cnf -name rootca -gencrl -out root.crl.pem >/dev/null 2>&1
openssl crl -in root.crl.pem -outform DER -out www/root.crl
rm -f ./*.csr
touch done
echo "pki ready in $D"
