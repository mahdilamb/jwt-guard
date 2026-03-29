#!/usr/bin/env bash
# Generate an RSA key pair and JWKS for the benchmark.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p jwks

# Generate RSA private key
openssl genrsa -out jwks/private.pem 2048 2>/dev/null

# Extract public key
openssl rsa -in jwks/private.pem -pubout -out jwks/public.pem 2>/dev/null

# Extract modulus (n) and exponent (e) as base64url
N=$(openssl rsa -in jwks/public.pem -pubin -modulus -noout 2>/dev/null \
    | sed 's/Modulus=//' \
    | xxd -r -p \
    | base64 \
    | tr '+/' '-_' \
    | tr -d '=\n')

E=$(printf 'AQAB')  # standard RSA exponent 65537

# Write JWKS
cat > jwks/jwks.json <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "bench-key-1",
      "n": "${N}",
      "e": "${E}"
    }
  ]
}
EOF

echo "Generated keys in bench/jwks/"
echo "  private.pem  - for signing JWTs"
echo "  public.pem   - public key"
echo "  jwks.json    - JWKS endpoint payload"
