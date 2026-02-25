#!/bin/bash
# Encrypt password using RSA-OAEP with openssl
# The password is wrapped in a JSON payload with timestamp before encryption
# Usage: ./encrypt_password_openssl.sh "<public_key_pem>" "<password>"

PUBLIC_KEY="$1"
PASSWORD="$2"

if [ -z "$PUBLIC_KEY" ] || [ -z "$PASSWORD" ]; then
    echo "Usage: $0 <public_key_pem> <password>" >&2
    exit 1
fi

# Create JSON payload with password and timestamp
TIMESTAMP=$(date +%s)
JSON_PAYLOAD=$(python3 -c "
import json, sys
payload = {
    'password': '''$PASSWORD''',
    'timestamp': $TIMESTAMP
}
print(json.dumps(payload, separators=(',', ':')))
")

# Save public key to temp file
TEMP_KEY=$(mktemp)
TEMP_DATA=$(mktemp)
echo "$PUBLIC_KEY" > "$TEMP_KEY"
echo -n "$JSON_PAYLOAD" > "$TEMP_DATA"

# Encrypt payload using RSA-OAEP
ENCRYPTED=$(openssl pkeyutl -encrypt -pubin -inkey "$TEMP_KEY" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in "$TEMP_DATA" | base64)

# Clean up
rm -f "$TEMP_KEY" "$TEMP_DATA"

# Output encrypted password (remove newlines from base64)
echo "$ENCRYPTED" | tr -d '\n'
