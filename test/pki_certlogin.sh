#!/bin/bash
# (isemon 1.10.341, test/fixes341_certlogin.py: from the client certificate kit of otp 1.0.275;
#  CRLPORT and DEADPORT set the CRL addresses, written into the certificates.)
# pki.sh DIR - an authority of the test domain corpnet as AD CS makes it (1.0.275): a root, an
# issuing authority under it, its CRL at http://127.0.0.1:${CRLPORT:-18890}/issuing.crl, and people's
# certificates from it - the UPN in the Subject Alternative Name, Client Authentication and Smart
# Card Logon, the SID extension of KB5014754 - one of each case the sign-in has to tell apart:
#   falco        right (UPN falco@corpnet.cz, its SID)            nested      right, a full admin
#   falco-nosid  no SID extension                                  falco-sid2  the SID of another account
#   falco-rev    revoked in the CRL                                falco-old   run out (2020-2021)
#   falco-srv    Server Authentication only                        noupn       no UPN in it
#   outsider     no group of a role                                gone        switched off in AD
#   ghost        not in the directory                              stranger    from an authority not put in
#   falco-nocdp  its CRL at an address that does not answer
# Every key and certificate as DIR/<name>.key / .pem; DIR/cas.pem the two authorities (to put in).
set -e
D=${1:?dir}
mkdir -p "$D"
cd "$D"
if [ -f done ]; then echo "pki ready in $D"; exit 0; fi
SID_FALCO=S-1-5-21-1111-2222-3333-1105
SID_NESTED=S-1-5-21-1111-2222-3333-1106
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
[person]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN},email:\${ENV::UPN}
crlDistributionPoints = URI:http://127.0.0.1:${CRLPORT:-18890}/issuing.crl
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[person_nosid]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:http://127.0.0.1:${CRLPORT:-18890}/issuing.crl
[person_nocdp]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,1.3.6.1.4.1.311.20.2.2
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:http://127.0.0.1:${DEADPORT:-18891}/nowhere.crl
1.3.6.1.4.1.311.25.2 = ASN1:SEQUENCE:sidext
[person_srv]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:\${ENV::UPN}
crlDistributionPoints = URI:http://127.0.0.1:${CRLPORT:-18890}/issuing.crl
[person_noupn]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = email:noupn@corpnet.cz
crlDistributionPoints = URI:http://127.0.0.1:${CRLPORT:-18890}/issuing.crl
[sidext]
gn = IMPLICIT:0C,SEQUENCE:othername
[othername]
oid = OID:1.3.6.1.4.1.311.25.2.1
val = EXPLICIT:0,OCTETSTRING:\${ENV::SID}
EOF
mkdir -p db/new
: > db/index.txt
echo 1000 > db/serial
echo 1000 > db/crlnumber
export UPN=x SID=S-1-0-0
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3650 \
  -subj "/DC=loc/DC=corpnet/CN=Corpnet Root CA" -config ca.cnf -extensions root_ext 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout issuing.key -out issuing.csr \
  -subj "/DC=loc/DC=corpnet/CN=Corpnet Issuing CA" 2>/dev/null
openssl x509 -req -in issuing.csr -CA root.pem -CAkey root.key -CAcreateserial -out issuing.pem \
  -days 1825 -extfile ca.cnf -extensions issuing_ext 2>/dev/null
cat issuing.pem root.pem > cas.pem
person() {   # name upn sid extensions [startdate enddate]
  local n=$1
  export UPN=$2 SID=$3
  openssl req -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$n" 2>/dev/null
  if [ -n "$5" ]; then
    openssl ca -batch -config ca.cnf -extensions "$4" -in "$n.csr" -out "$n.pem" -notext \
      -startdate "$5" -enddate "$6" >/dev/null 2>&1
  else
    openssl ca -batch -config ca.cnf -extensions "$4" -in "$n.csr" -out "$n.pem" -notext >/dev/null 2>&1
  fi
}
person falco falco@corpnet.cz $SID_FALCO person
person nested nested@corpnet.cz $SID_NESTED person
person falco-nosid falco@corpnet.cz - person_nosid
person falco-sid2 falco@corpnet.cz $SID_NESTED person
person falco-rev falco@corpnet.cz $SID_FALCO person
person falco-old falco@corpnet.cz $SID_FALCO person 20200101000000Z 20210101000000Z
person falco-srv falco@corpnet.cz $SID_FALCO person_srv
person falco-nocdp falco@corpnet.cz $SID_FALCO person_nocdp
person noupn - - person_noupn
person outsider outsider@corpnet.cz S-1-5-21-1111-2222-3333-1200 person
person gone gone@corpnet.cz S-1-5-21-1111-2222-3333-1201 person
person ghost ghost@corpnet.cz S-1-5-21-1111-2222-3333-1202 person
openssl ca -config ca.cnf -revoke falco-rev.pem >/dev/null 2>&1
openssl ca -config ca.cnf -gencrl -out issuing.crl.pem >/dev/null 2>&1
mkdir -p www
openssl crl -in issuing.crl.pem -outform DER -out www/issuing.crl
# an authority of somebody else's, and a person of it
openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 3650 \
  -subj "/CN=Somebody Else CA" -config ca.cnf -extensions root_ext 2>/dev/null
export UPN=falco@corpnet.cz SID=$SID_FALCO
openssl req -newkey rsa:2048 -nodes -keyout stranger.key -out stranger.csr -subj "/CN=stranger" 2>/dev/null
openssl x509 -req -in stranger.csr -CA other.pem -CAkey other.key -CAcreateserial -out stranger.pem \
  -days 365 -extfile ca.cnf -extensions person 2>/dev/null
for f in *.pem; do openssl x509 -in "$f" -noout 2>/dev/null || true; done
touch done
echo "pki ready in $D"
