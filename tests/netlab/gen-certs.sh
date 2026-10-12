#!/usr/bin/env bash
# Generate a throwaway lab CA and leaf certificates (TEST ONLY).
set -euo pipefail
out=${1:-.lab/certs}
mkdir -p "$out"
cd "$out"
[[ -f ca.crt ]] && exit 0
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj "/CN=ConnRelay netlab TEST ONLY CA" -keyout ca.key -out ca.crt 2>/dev/null
for name in api turn; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=$name.lab.invalid" -keyout $name.key -out $name.csr 2>/dev/null
  printf "subjectAltName=DNS:%s.lab.invalid\nextendedKeyUsage=serverAuth\n" "$name" > $name.ext
  openssl x509 -req -in $name.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 \
    -extfile $name.ext -out $name.crt 2>/dev/null
  rm -f $name.csr $name.ext
done
chmod 644 ./*.key ./*.crt
echo "lab certificates in $out"
