#!/bin/bash
#
# Wazuh Indexer SSL Health Check Script
# Diagnoses certificate_unknown and SSL handshake issues
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default paths (adjust if your installation differs)
INDEXER_CERTS_DIR="/etc/wazuh-indexer/certs"
INDEXER_CONFIG="/etc/wazuh-indexer/opensearch.yml"
INDEXER_SECURITY_CONFIG="/etc/wazuh-indexer/opensearch-security"
INDEXER_PORT=9200
INDEXER_HOST="127.0.0.1"

# Certificate files to check
ADMIN_CERT="admin.pem"
ADMIN_KEY="admin-key.pem"
ROOT_CA="root-ca.pem"
NODE_CERT="indexer.pem"
NODE_KEY="indexer-key.pem"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  Wazuh Indexer SSL Health Check${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

ERRORS=0
WARNINGS=0

# Helper functions
check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ERRORS=$((ERRORS + 1))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

check_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

section() {
    echo ""
    echo -e "${BLUE}--- $1 ---${NC}"
}

# ============================================
# 1. Check if wazuh-indexer service is running
# ============================================
section "Service Status"

if systemctl is-active --quiet wazuh-indexer 2>/dev/null; then
    check_pass "wazuh-indexer service is running"
else
    check_fail "wazuh-indexer service is NOT running"
    echo "       Try: systemctl status wazuh-indexer"
    echo "       Logs: journalctl -u wazuh-indexer -n 50"
fi

# ============================================
# 2. Check certificate directory exists
# ============================================
section "Certificate Directory"

if [ -d "$INDEXER_CERTS_DIR" ]; then
    check_pass "Certificate directory exists: $INDEXER_CERTS_DIR"

    echo ""
    echo "  Directory contents:"
    ls -la "$INDEXER_CERTS_DIR" 2>/dev/null | head -20 | sed 's/^/       /'
else
    check_fail "Certificate directory does not exist: $INDEXER_CERTS_DIR"
fi

# ============================================
# 3. Check certificate files exist
# ============================================
section "Certificate Files"

for cert_file in "$ROOT_CA" "$ADMIN_CERT" "$ADMIN_KEY" "$NODE_CERT" "$NODE_KEY"; do
    full_path="$INDEXER_CERTS_DIR/$cert_file"
    if [ -f "$full_path" ]; then
        check_pass "Found: $cert_file"
    else
        check_fail "Missing: $cert_file"
    fi
done

# ============================================
# 4. Check certificate permissions
# ============================================
section "Certificate Permissions"

INDEXER_USER="wazuh-indexer"
if id "$INDEXER_USER" &>/dev/null; then
    check_pass "User $INDEXER_USER exists"
else
    INDEXER_USER="opensearch"
    if id "$INDEXER_USER" &>/dev/null; then
        check_warn "Using opensearch user instead of wazuh-indexer"
    else
        check_fail "Neither wazuh-indexer nor opensearch user exists"
    fi
fi

for cert_file in "$ROOT_CA" "$ADMIN_CERT" "$NODE_CERT"; do
    full_path="$INDEXER_CERTS_DIR/$cert_file"
    if [ -f "$full_path" ]; then
        if [ -r "$full_path" ]; then
            check_pass "$cert_file is readable"
        else
            check_fail "$cert_file is NOT readable"
        fi

        # Check ownership
        owner=$(stat -c '%U' "$full_path" 2>/dev/null)
        if [ "$owner" = "$INDEXER_USER" ] || [ "$owner" = "root" ]; then
            check_pass "$cert_file owned by $owner"
        else
            check_warn "$cert_file owned by $owner (expected $INDEXER_USER or root)"
        fi
    fi
done

# Key files should have restricted permissions
for key_file in "$ADMIN_KEY" "$NODE_KEY"; do
    full_path="$INDEXER_CERTS_DIR/$key_file"
    if [ -f "$full_path" ]; then
        perms=$(stat -c '%a' "$full_path" 2>/dev/null)
        if [ "$perms" = "600" ] || [ "$perms" = "640" ] || [ "$perms" = "400" ]; then
            check_pass "$key_file has secure permissions ($perms)"
        else
            check_warn "$key_file has permissions $perms (recommended: 600 or 640)"
        fi
    fi
done

# ============================================
# 5. Check certificate validity
# ============================================
section "Certificate Validity"

check_cert_validity() {
    local cert_path="$1"
    local cert_name="$2"

    if [ ! -f "$cert_path" ]; then
        return
    fi

    # Check expiration
    if openssl x509 -in "$cert_path" -noout -checkend 0 2>/dev/null; then
        expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
        check_pass "$cert_name is valid (expires: $expiry)"

        # Warn if expiring within 30 days
        if ! openssl x509 -in "$cert_path" -noout -checkend 2592000 2>/dev/null; then
            check_warn "$cert_name expires within 30 days!"
        fi
    else
        check_fail "$cert_name is EXPIRED!"
    fi

    # Show subject
    subject=$(openssl x509 -in "$cert_path" -noout -subject 2>/dev/null | sed 's/subject=//')
    echo "       Subject: $subject"

    # Show issuer
    issuer=$(openssl x509 -in "$cert_path" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    echo "       Issuer: $issuer"
}

check_cert_validity "$INDEXER_CERTS_DIR/$ROOT_CA" "Root CA"
check_cert_validity "$INDEXER_CERTS_DIR/$NODE_CERT" "Node certificate"
check_cert_validity "$INDEXER_CERTS_DIR/$ADMIN_CERT" "Admin certificate"

# ============================================
# 6. Verify certificate chain
# ============================================
section "Certificate Chain Verification"

if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ] && [ -f "$INDEXER_CERTS_DIR/$NODE_CERT" ]; then
    if openssl verify -CAfile "$INDEXER_CERTS_DIR/$ROOT_CA" "$INDEXER_CERTS_DIR/$NODE_CERT" 2>/dev/null | grep -q "OK"; then
        check_pass "Node certificate is signed by Root CA"
    else
        check_fail "Node certificate is NOT signed by Root CA!"
        echo "       This is likely the cause of 'certificate_unknown' error"
        openssl verify -CAfile "$INDEXER_CERTS_DIR/$ROOT_CA" "$INDEXER_CERTS_DIR/$NODE_CERT" 2>&1 | sed 's/^/       /'
    fi
fi

if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ] && [ -f "$INDEXER_CERTS_DIR/$ADMIN_CERT" ]; then
    if openssl verify -CAfile "$INDEXER_CERTS_DIR/$ROOT_CA" "$INDEXER_CERTS_DIR/$ADMIN_CERT" 2>/dev/null | grep -q "OK"; then
        check_pass "Admin certificate is signed by Root CA"
    else
        check_fail "Admin certificate is NOT signed by Root CA!"
        echo "       This is likely the cause of 'certificate_unknown' error"
        openssl verify -CAfile "$INDEXER_CERTS_DIR/$ROOT_CA" "$INDEXER_CERTS_DIR/$ADMIN_CERT" 2>&1 | sed 's/^/       /'
    fi
fi

# ============================================
# 7. Check key matches certificate
# ============================================
section "Key-Certificate Matching"

check_key_matches_cert() {
    local cert="$1"
    local key="$2"
    local name="$3"

    if [ ! -f "$cert" ] || [ ! -f "$key" ]; then
        return
    fi

    cert_modulus=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | md5sum | cut -d' ' -f1)
    key_modulus=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | md5sum | cut -d' ' -f1)

    if [ "$cert_modulus" = "$key_modulus" ]; then
        check_pass "$name: Certificate and key match"
    else
        check_fail "$name: Certificate and key DO NOT match!"
    fi
}

check_key_matches_cert "$INDEXER_CERTS_DIR/$NODE_CERT" "$INDEXER_CERTS_DIR/$NODE_KEY" "Node"
check_key_matches_cert "$INDEXER_CERTS_DIR/$ADMIN_CERT" "$INDEXER_CERTS_DIR/$ADMIN_KEY" "Admin"

# ============================================
# 8. Check Extended Key Usage (EKU)
# ============================================
section "Extended Key Usage (EKU)"

check_eku() {
    local cert_path="$1"
    local cert_name="$2"
    local required_eku="$3"  # "clientAuth", "serverAuth", or "both"

    if [ ! -f "$cert_path" ]; then
        return
    fi

    eku_output=$(openssl x509 -in "$cert_path" -noout -ext extendedKeyUsage 2>/dev/null || true)

    if [ -z "$eku_output" ] || echo "$eku_output" | grep -q "No extensions"; then
        check_fail "$cert_name: Missing Extended Key Usage extension!"
        echo "       This certificate cannot be used for TLS authentication"
        return
    fi

    echo "  $cert_name EKU:"
    echo "$eku_output" | sed 's/^/       /'

    has_client=$(echo "$eku_output" | grep -qi "clientAuth\|TLS Web Client" && echo "yes" || echo "no")
    has_server=$(echo "$eku_output" | grep -qi "serverAuth\|TLS Web Server" && echo "yes" || echo "no")

    case "$required_eku" in
        clientAuth)
            if [ "$has_client" = "yes" ]; then
                check_pass "$cert_name has clientAuth EKU"
            else
                check_fail "$cert_name missing clientAuth EKU - required for TLS client authentication!"
            fi
            ;;
        serverAuth)
            if [ "$has_server" = "yes" ]; then
                check_pass "$cert_name has serverAuth EKU"
            else
                check_fail "$cert_name missing serverAuth EKU"
            fi
            ;;
        both)
            if [ "$has_client" = "yes" ] && [ "$has_server" = "yes" ]; then
                check_pass "$cert_name has both serverAuth and clientAuth EKU"
            else
                [ "$has_server" != "yes" ] && check_fail "$cert_name missing serverAuth EKU"
                [ "$has_client" != "yes" ] && check_fail "$cert_name missing clientAuth EKU - needed for inter-node communication"
            fi
            ;;
    esac
}

# Admin cert needs clientAuth for security-init to work
check_eku "$INDEXER_CERTS_DIR/$ADMIN_CERT" "Admin certificate" "clientAuth"

# Node cert needs both for serving HTTPS and inter-node TLS
check_eku "$INDEXER_CERTS_DIR/$NODE_CERT" "Node certificate" "both"

# ============================================
# 9. Check SAN/CN for hostname
# ============================================
section "Subject Alternative Names (SAN)"

if [ -f "$INDEXER_CERTS_DIR/$NODE_CERT" ]; then
    echo "  Node certificate SAN entries:"
    openssl x509 -in "$INDEXER_CERTS_DIR/$NODE_CERT" -noout -ext subjectAltName 2>/dev/null | sed 's/^/       /' || echo "       No SAN extension found"

    # Check if localhost or 127.0.0.1 is in SAN
    san_output=$(openssl x509 -in "$INDEXER_CERTS_DIR/$NODE_CERT" -noout -ext subjectAltName 2>/dev/null || true)
    if echo "$san_output" | grep -qE "(localhost|127\.0\.0\.1)"; then
        check_pass "Certificate includes localhost/127.0.0.1 in SAN"
    else
        check_warn "Certificate may not include localhost/127.0.0.1 in SAN"
        echo "       This could cause issues when connecting to $INDEXER_HOST"
    fi

    # Get hostname and check
    current_hostname=$(hostname)
    if echo "$san_output" | grep -qi "$current_hostname"; then
        check_pass "Certificate includes current hostname ($current_hostname)"
    else
        check_warn "Certificate may not include current hostname ($current_hostname)"
    fi
fi

# ============================================
# 10. Check opensearch.yml configuration
# ============================================
section "OpenSearch Configuration"

if [ -f "$INDEXER_CONFIG" ]; then
    check_pass "Config file exists: $INDEXER_CONFIG"

    echo ""
    echo "  SSL/TLS related settings:"
    grep -E "(ssl|pem|key|ca|certificate|security)" "$INDEXER_CONFIG" 2>/dev/null | head -30 | sed 's/^/       /'

    # Check if certificate paths in config exist
    echo ""
    echo "  Checking certificate paths in config..."

    for path in $(grep -oE '/[^ ]+\.pem' "$INDEXER_CONFIG" 2>/dev/null | sort -u); do
        if [ -f "$path" ]; then
            check_pass "Config path exists: $path"
        else
            check_fail "Config path missing: $path"
        fi
    done
else
    check_fail "Config file missing: $INDEXER_CONFIG"
fi

# ============================================
# 11. Admin DN Configuration Check
# ============================================
section "Admin DN Configuration"

if [ -f "$INDEXER_CONFIG" ] && [ -f "$INDEXER_CERTS_DIR/$ADMIN_CERT" ]; then
    # Get the actual DN from the admin certificate
    # OpenSSL outputs in a specific format, we need to handle both old and new formats
    actual_admin_dn=$(openssl x509 -in "$INDEXER_CERTS_DIR/$ADMIN_CERT" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//' | sed 's/^[[:space:]]*//')

    echo "  Admin certificate DN (RFC2253 format):"
    echo "       $actual_admin_dn"

    # Also show the "compat" format which some configs use
    actual_admin_dn_compat=$(openssl x509 -in "$INDEXER_CERTS_DIR/$ADMIN_CERT" -noout -subject 2>/dev/null | sed 's/subject=//' | sed 's/^[[:space:]]*//')
    echo ""
    echo "  Admin certificate DN (OpenSSL compat format):"
    echo "       $actual_admin_dn_compat"

    # Extract configured admin_dn from opensearch.yml
    # This handles both single-line and multi-line YAML array formats
    echo ""
    echo "  Configured admin_dn in opensearch.yml:"

    configured_dns=$(grep -A 10 'plugins.security.authcz.admin_dn' "$INDEXER_CONFIG" 2>/dev/null | head -11)
    echo "$configured_dns" | sed 's/^/       /'

    # Try to extract the actual DN values from config
    # Handle format: plugins.security.authcz.admin_dn: ["CN=admin,..."]
    # Or format with array on next lines starting with -
    if echo "$configured_dns" | grep -q '\['; then
        # Inline array format
        config_dn=$(echo "$configured_dns" | grep -oP '\[\s*"\K[^"]+' | head -1)
    else
        # YAML list format (lines starting with -)
        config_dn=$(echo "$configured_dns" | grep '^\s*-' | head -1 | sed 's/.*-\s*//' | tr -d '"' | tr -d "'" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
    fi

    echo ""
    echo "  Extracted configured DN:"
    echo "       $config_dn"

    # Compare DNs - this is tricky because format can vary
    # Normalize both by removing spaces around = and ,
    normalize_dn() {
        echo "$1" | sed 's/[[:space:]]*=[[:space:]]*/=/g' | sed 's/[[:space:]]*,[[:space:]]*/,/g' | tr '[:upper:]' '[:lower:]'
    }

    norm_actual=$(normalize_dn "$actual_admin_dn")
    norm_config=$(normalize_dn "$config_dn")

    echo ""
    if [ -z "$config_dn" ]; then
        check_fail "Could not extract admin_dn from config"
        echo "       Make sure plugins.security.authcz.admin_dn is configured"
    elif [ "$norm_actual" = "$norm_config" ]; then
        check_pass "Admin DN in certificate matches config (exact match)"
    else
        # Try comparing with compat format too
        norm_actual_compat=$(normalize_dn "$actual_admin_dn_compat")
        if [ "$norm_actual_compat" = "$norm_config" ]; then
            check_pass "Admin DN in certificate matches config (compat format)"
        else
            # Check if they contain the same CN at least
            cert_cn=$(echo "$actual_admin_dn" | grep -oP 'CN=[^,]+' | head -1)
            config_cn=$(echo "$config_dn" | grep -oP 'CN=[^,]+' | head -1)

            if [ -n "$cert_cn" ] && [ -n "$config_cn" ]; then
                norm_cert_cn=$(normalize_dn "$cert_cn")
                norm_config_cn=$(normalize_dn "$config_cn")

                if [ "$norm_cert_cn" = "$norm_config_cn" ]; then
                    check_warn "Admin DN CN matches but full DN differs"
                    echo "       Certificate: $actual_admin_dn"
                    echo "       Config:      $config_dn"
                    echo "       This MAY work but exact match is recommended"
                else
                    check_fail "Admin DN MISMATCH - This will cause security init to fail!"
                    echo ""
                    echo "       Certificate DN: $actual_admin_dn"
                    echo "       Configured DN:  $config_dn"
                    echo ""
                    echo "       FIX: Update plugins.security.authcz.admin_dn in opensearch.yml to:"
                    echo "       plugins.security.authcz.admin_dn:"
                    echo "         - \"$actual_admin_dn\""
                fi
            else
                check_warn "Could not compare CNs, manual verification needed"
                echo "       Certificate DN: $actual_admin_dn"
                echo "       Configured DN:  $config_dn"
            fi
        fi
    fi

    # Also check nodes_dn if present
    echo ""
    echo "  Checking nodes_dn configuration..."
    if grep -q 'plugins.security.nodes_dn' "$INDEXER_CONFIG" 2>/dev/null; then
        nodes_dn_config=$(grep -A 5 'plugins.security.nodes_dn' "$INDEXER_CONFIG" 2>/dev/null | head -6)
        echo "$nodes_dn_config" | sed 's/^/       /'

        if [ -f "$INDEXER_CERTS_DIR/$NODE_CERT" ]; then
            node_cert_dn=$(openssl x509 -in "$INDEXER_CERTS_DIR/$NODE_CERT" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//')
            echo ""
            echo "  Node certificate DN: $node_cert_dn"

            if echo "$nodes_dn_config" | grep -qi "$(echo "$node_cert_dn" | grep -oP 'CN=[^,]+')"; then
                check_pass "Node certificate CN appears in nodes_dn config"
            else
                check_warn "Node certificate CN may not be in nodes_dn - verify manually"
            fi
        fi
    else
        check_info "No nodes_dn configuration found (may use wildcards or not required)"
    fi
else
    if [ ! -f "$INDEXER_CONFIG" ]; then
        check_fail "Cannot check admin DN - config file missing"
    fi
    if [ ! -f "$INDEXER_CERTS_DIR/$ADMIN_CERT" ]; then
        check_fail "Cannot check admin DN - admin certificate missing"
    fi
fi

# ============================================
# 12. Test SSL connection
# ============================================
section "SSL Connection Test"

echo "  Testing SSL connection to $INDEXER_HOST:$INDEXER_PORT..."

if command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout 10"
else
    TIMEOUT_CMD=""
fi

# Test with openssl s_client
ssl_test_output=$($TIMEOUT_CMD openssl s_client -connect "$INDEXER_HOST:$INDEXER_PORT" -servername "$INDEXER_HOST" </dev/null 2>&1 || true)

if echo "$ssl_test_output" | grep -q "CONNECTED"; then
    check_pass "SSL connection established"

    # Show certificate info from connection
    echo ""
    echo "  Server certificate info:"
    echo "$ssl_test_output" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | sed 's/^/       /' || echo "       Could not parse certificate"

    # Check verify return
    verify_result=$(echo "$ssl_test_output" | grep "Verify return code" || true)
    if echo "$verify_result" | grep -q "0 (ok)"; then
        check_pass "Certificate verification: OK"
    else
        check_warn "Certificate verification issue: $verify_result"
    fi
else
    check_fail "Could not establish SSL connection to $INDEXER_HOST:$INDEXER_PORT"
    echo "       Is wazuh-indexer running and listening on port $INDEXER_PORT?"
fi

# Test with curl if available
if command -v curl &>/dev/null; then
    echo ""
    echo "  Testing HTTPS endpoint..."

    curl_output=$(curl -s -k --connect-timeout 5 "https://$INDEXER_HOST:$INDEXER_PORT" 2>&1 || true)
    if echo "$curl_output" | grep -qi "wazuh\|opensearch\|name.*node\|unauthorized"; then
        check_pass "HTTPS endpoint responds (with -k/insecure flag)"
        echo "       Response: ${curl_output:0:100}"
    else
        check_warn "HTTPS endpoint did not respond as expected"
        echo "       Response: ${curl_output:0:200}"
    fi

    # Try with CA cert
    if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ]; then
        curl_ca_output=$(curl -s --cacert "$INDEXER_CERTS_DIR/$ROOT_CA" --connect-timeout 5 "https://$INDEXER_HOST:$INDEXER_PORT" 2>&1 || true)
        if echo "$curl_ca_output" | grep -qi "wazuh\|opensearch\|name.*node\|unauthorized"; then
            check_pass "HTTPS endpoint responds with CA verification"
            echo "       Response: ${curl_ca_output:0:100}"
        else
            check_fail "HTTPS endpoint fails with CA verification"
            echo "       This confirms the certificate trust issue"
            echo "       Error: ${curl_ca_output:0:200}"
        fi
    fi
fi

# ============================================
# 13. Check indexer logs for SSL errors
# ============================================
section "Recent Indexer Log Errors"

INDEXER_LOG_DIR="/var/log/wazuh-indexer"
if [ -d "$INDEXER_LOG_DIR" ]; then
    echo "  Recent SSL/certificate related errors:"
    grep -iE "(ssl|certificate|handshake|trust|pem|key)" "$INDEXER_LOG_DIR"/*.log 2>/dev/null | tail -20 | sed 's/^/       /' || echo "       No recent SSL errors found in logs"
else
    # Try journalctl
    echo "  From journalctl:"
    journalctl -u wazuh-indexer --no-pager -n 50 2>/dev/null | grep -iE "(ssl|certificate|handshake|trust|error)" | tail -10 | sed 's/^/       /' || echo "       No relevant entries found"
fi

# ============================================
# 14. Check for common certificate mismatches
# ============================================
section "Certificate Consistency Check"

if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ]; then
    # Get Root CA subject
    root_subject=$(openssl x509 -in "$INDEXER_CERTS_DIR/$ROOT_CA" -noout -subject 2>/dev/null)
    echo "  Root CA Subject: $root_subject"

    # Check all certs have same issuer as root subject
    for cert_file in "$NODE_CERT" "$ADMIN_CERT"; do
        if [ -f "$INDEXER_CERTS_DIR/$cert_file" ]; then
            cert_issuer=$(openssl x509 -in "$INDEXER_CERTS_DIR/$cert_file" -noout -issuer 2>/dev/null)
            echo "  $cert_file Issuer: $cert_issuer"

            # Simple comparison (not perfect but catches obvious issues)
            root_cn=$(echo "$root_subject" | grep -oP 'CN\s*=\s*\K[^,/]+' || true)
            cert_issuer_cn=$(echo "$cert_issuer" | grep -oP 'CN\s*=\s*\K[^,/]+' || true)

            if [ -n "$root_cn" ] && [ -n "$cert_issuer_cn" ] && [ "$root_cn" = "$cert_issuer_cn" ]; then
                check_pass "$cert_file was issued by Root CA (CN match)"
            else
                check_warn "$cert_file issuer CN may not match Root CA CN"
                echo "       Root CN: $root_cn"
                echo "       Issuer CN: $cert_issuer_cn"
            fi
        fi
    done
fi

# ============================================
# Summary
# ============================================
echo ""
echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}Checks completed with $WARNINGS warning(s)${NC}"
else
    echo -e "${RED}Checks completed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
fi

echo ""
echo -e "${BLUE}Common fixes for 'certificate_unknown' error:${NC}"
echo ""
echo "  1. CRITICAL: Ensure certificates have correct Extended Key Usage (EKU):"
echo "     - Admin cert needs: extendedKeyUsage = clientAuth"
echo "     - Node cert needs:  extendedKeyUsage = serverAuth, clientAuth"
echo "     Check with: openssl x509 -in CERT.pem -noout -ext extendedKeyUsage"
echo ""
echo "  2. Verify admin_dn in opensearch.yml matches the admin certificate DN exactly"
echo "     - Get cert DN: openssl x509 -in /etc/wazuh-indexer/certs/admin.pem -noout -subject -nameopt RFC2253"
echo "     - Update plugins.security.authcz.admin_dn to match"
echo ""
echo "  3. Regenerate certificates ensuring all certs use the same Root CA"
echo "  4. Ensure the admin cert is signed by the same CA as the node cert"
echo "  5. Check that certificate paths in opensearch.yml are correct"
echo "  6. Verify the Root CA file contains the correct CA certificate"
echo "  7. Restart wazuh-indexer after any certificate changes:"
echo "     systemctl restart wazuh-indexer"
echo ""
echo "  8. If using Chef, ensure certificates are generated BEFORE the"
echo "     indexer-security-init.sh script runs. Check recipe order."
echo ""
echo "  9. Manual security init (after fixing certs):"
echo "     /usr/share/wazuh-indexer/bin/indexer-security-init.sh"
echo ""

exit $ERRORS
