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

    curl_output=$(curl -s -k --noproxy "$INDEXER_HOST" --connect-timeout 5 "https://$INDEXER_HOST:$INDEXER_PORT" 2>&1 || true)
    if echo "$curl_output" | grep -qi "wazuh\|opensearch\|name.*node\|unauthorized"; then
        check_pass "HTTPS endpoint responds (with -k/insecure flag)"
        echo "       Response: ${curl_output:0:100}"
    else
        check_warn "HTTPS endpoint did not respond as expected"
        echo "       Response: ${curl_output:0:200}"
    fi

    # Try with CA cert
    if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ]; then
        curl_ca_output=$(curl -s --noproxy "$INDEXER_HOST" --cacert "$INDEXER_CERTS_DIR/$ROOT_CA" --connect-timeout 5 "https://$INDEXER_HOST:$INDEXER_PORT" 2>&1 || true)
        if echo "$curl_ca_output" | grep -qi "wazuh\|opensearch\|name.*node\|unauthorized"; then
            check_pass "HTTPS endpoint responds with CA verification"
            echo "       Response: ${curl_ca_output:0:100}"
        else
            # Distinguish SAN/hostname mismatch from CA trust issues
            if echo "$curl_ca_output" | grep -qi "subject alternative name\|server certificate verification\|match\|hostname"; then
                check_warn "HTTPS CA verification fails due to hostname/SAN mismatch"
                echo "       Certificate SAN does not include $INDEXER_HOST"
                echo "       This is expected if connecting via IP but cert only has DNS names"
                echo "       The -k test above confirms the endpoint is functional"
            else
                check_fail "HTTPS endpoint fails with CA verification"
                echo "       This may indicate a certificate trust issue"
                echo "       Error: ${curl_ca_output:0:200}"
            fi
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
# 15. Web Proxy Configuration Check
# ============================================
section "Web Proxy Configuration"

# Collect proxy vars from the environment (check both lower and upper case)
DETECTED_HTTP_PROXY="${http_proxy:-${HTTP_PROXY:-}}"
DETECTED_HTTPS_PROXY="${https_proxy:-${HTTPS_PROXY:-}}"
DETECTED_NO_PROXY="${no_proxy:-${NO_PROXY:-}}"

if [ -n "$DETECTED_HTTP_PROXY" ] || [ -n "$DETECTED_HTTPS_PROXY" ]; then
    check_info "Proxy environment detected"
    [ -n "$DETECTED_HTTP_PROXY" ]  && echo "       http_proxy  = $DETECTED_HTTP_PROXY"
    [ -n "$DETECTED_HTTPS_PROXY" ] && echo "       https_proxy = $DETECTED_HTTPS_PROXY"
    [ -n "$DETECTED_NO_PROXY" ]    && echo "       no_proxy    = $DETECTED_NO_PROXY"

    # Warn if localhost / 127.0.0.1 is not excluded from the proxy
    if [ -n "$DETECTED_NO_PROXY" ]; then
        if echo "$DETECTED_NO_PROXY" | grep -qE '(^|,)\s*(localhost|127\.0\.0\.1|\*)\s*(,|$)'; then
            check_pass "no_proxy includes localhost/127.0.0.1"
        else
            check_warn "no_proxy does not appear to include localhost/127.0.0.1"
            echo "       Local Wazuh API and indexer calls may be routed through the proxy"
            echo "       Consider: export no_proxy=\"localhost,127.0.0.1,\$no_proxy\""
        fi
    else
        check_warn "no_proxy is not set — all traffic will go through the proxy"
        echo "       Consider: export no_proxy=\"localhost,127.0.0.1\""
    fi

    echo ""

    # --- Helper: check a systemd unit for proxy env vars ---
    check_systemd_proxy() {
        local unit="$1"
        local label="$2"

        if ! systemctl list-unit-files "$unit" &>/dev/null 2>&1; then
            return
        fi

        # Check if the unit is installed
        if ! systemctl cat "$unit" &>/dev/null 2>&1; then
            check_info "$label ($unit) is not installed — skipping"
            return
        fi

        echo ""
        echo "  $label ($unit):"

        # Gather full unit config (including drop-ins) and look for proxy vars
        unit_env=$(systemctl show "$unit" -p Environment --no-pager 2>/dev/null || true)
        unit_files=$(systemctl cat "$unit" 2>/dev/null || true)

        found_proxy=0

        # Check Environment= and EnvironmentFile= in the unit
        if echo "$unit_files" | grep -qiE '(http_proxy|https_proxy)'; then
            check_pass "$label unit file contains proxy environment variables"
            echo "$unit_files" | grep -iE '(http_proxy|https_proxy|no_proxy)' | sed 's/^/       /'
            found_proxy=1
        fi

        # Check resolved environment from systemd
        if echo "$unit_env" | grep -qiE '(http_proxy|https_proxy)'; then
            if [ $found_proxy -eq 0 ]; then
                check_pass "$label has proxy vars in resolved environment"
                echo "$unit_env" | grep -iE '(http_proxy|https_proxy|no_proxy)' | sed 's/^/       /'
                found_proxy=1
            fi
        fi

        # Check for EnvironmentFile that may supply proxy vars
        env_file=$(echo "$unit_files" | grep -i 'EnvironmentFile' | sed 's/.*=//' | tr -d ' ' || true)
        if [ -n "$env_file" ] && [ -f "$env_file" ]; then
            if grep -qiE '(http_proxy|https_proxy)' "$env_file" 2>/dev/null; then
                check_pass "$label EnvironmentFile ($env_file) contains proxy settings"
                grep -iE '(http_proxy|https_proxy|no_proxy)' "$env_file" | sed 's/^/       /'
                found_proxy=1
            fi
        fi

        # Check for systemd drop-in overrides
        drop_in_dir="/etc/systemd/system/${unit}.d"
        if [ -d "$drop_in_dir" ]; then
            for f in "$drop_in_dir"/*.conf; do
                [ -f "$f" ] || continue
                if grep -qiE '(http_proxy|https_proxy)' "$f" 2>/dev/null; then
                    check_pass "$label drop-in ($f) contains proxy settings"
                    grep -iE '(http_proxy|https_proxy|no_proxy)' "$f" | sed 's/^/       /'
                    found_proxy=1
                fi
            done
        fi

        if [ $found_proxy -eq 0 ]; then
            check_warn "$label has no proxy configuration"
            echo "       To configure, create a drop-in override:"
            echo "         mkdir -p /etc/systemd/system/${unit}.d"
            echo "         cat > /etc/systemd/system/${unit}.d/proxy.conf <<DROPEOF"
            echo "         [Service]"
            echo "         Environment=\"http_proxy=$DETECTED_HTTP_PROXY\""
            echo "         Environment=\"https_proxy=$DETECTED_HTTPS_PROXY\""
            [ -n "$DETECTED_NO_PROXY" ] && echo "         Environment=\"no_proxy=$DETECTED_NO_PROXY\""
            echo "         DROPEOF"
            echo "         systemctl daemon-reload && systemctl restart $unit"
        fi
    }

    # --- Check each Wazuh service ---
    check_systemd_proxy "wazuh-indexer.service"   "Wazuh Indexer"
    check_systemd_proxy "wazuh-manager.service"   "Wazuh Manager"
    check_systemd_proxy "wazuh-dashboard.service" "Wazuh Dashboard"
    check_systemd_proxy "filebeat.service"         "Filebeat"

    # --- Java/JVM proxy settings for wazuh-indexer ---
    echo ""
    echo "  Wazuh Indexer JVM proxy options:"
    JVM_OPTIONS_FILE="/etc/wazuh-indexer/jvm.options"
    JVM_OPTIONS_DIR="/etc/wazuh-indexer/jvm.options.d"
    jvm_proxy_found=0

    if [ -f "$JVM_OPTIONS_FILE" ]; then
        if grep -qE '^\-D(http|https)\.(proxyHost|proxyPort)' "$JVM_OPTIONS_FILE" 2>/dev/null; then
            check_pass "JVM proxy options set in $JVM_OPTIONS_FILE"
            grep -E '^\-D(http|https)\.(proxyHost|proxyPort|nonProxyHosts)' "$JVM_OPTIONS_FILE" | sed 's/^/       /'
            jvm_proxy_found=1
        fi
    fi

    if [ -d "$JVM_OPTIONS_DIR" ]; then
        for f in "$JVM_OPTIONS_DIR"/*.options; do
            [ -f "$f" ] || continue
            if grep -qE '^\-D(http|https)\.(proxyHost|proxyPort)' "$f" 2>/dev/null; then
                check_pass "JVM proxy options set in $f"
                grep -E '^\-D(http|https)\.(proxyHost|proxyPort|nonProxyHosts)' "$f" | sed 's/^/       /'
                jvm_proxy_found=1
            fi
        done
    fi

    if [ $jvm_proxy_found -eq 0 ]; then
        # Parse host and port from the detected proxy URL for the hint
        proxy_url="${DETECTED_HTTPS_PROXY:-$DETECTED_HTTP_PROXY}"
        proxy_host=$(echo "$proxy_url" | sed -E 's|^https?://||;s|:[0-9]+/?$||;s|/$||')
        proxy_port=$(echo "$proxy_url" | grep -oE ':[0-9]+' | tail -1 | tr -d ':')
        proxy_port="${proxy_port:-3128}"

        check_warn "No JVM proxy options found for wazuh-indexer"
        echo "       Java does not inherit shell proxy env vars automatically."
        echo "       To configure, create $JVM_OPTIONS_DIR/proxy.options:"
        echo "         -Dhttp.proxyHost=$proxy_host"
        echo "         -Dhttp.proxyPort=$proxy_port"
        echo "         -Dhttps.proxyHost=$proxy_host"
        echo "         -Dhttps.proxyPort=$proxy_port"
        [ -n "$DETECTED_NO_PROXY" ] && echo "         -Dhttp.nonProxyHosts=$(echo "$DETECTED_NO_PROXY" | sed 's/,/|/g')"
    fi

    # --- Wazuh Manager ossec.conf remote proxy ---
    echo ""
    OSSEC_CONF="/var/ossec/etc/ossec.conf"
    if [ -f "$OSSEC_CONF" ]; then
        echo "  Wazuh Manager ossec.conf proxy settings:"
        if grep -qE '<proxy>' "$OSSEC_CONF" 2>/dev/null; then
            check_pass "Proxy configured in ossec.conf"
            grep -A1 '<proxy>' "$OSSEC_CONF" | sed 's/^/       /'
        else
            check_warn "No <proxy> block in ossec.conf"
            echo "       If the manager needs to reach external update sources through a proxy,"
            echo "       add to the relevant <remote> or <wodle> section:"
            echo "         <proxy>${DETECTED_HTTPS_PROXY:-$DETECTED_HTTP_PROXY}</proxy>"
        fi
    fi

    # --- Filebeat proxy in filebeat.yml ---
    FILEBEAT_YML="/etc/filebeat/filebeat.yml"
    if [ -f "$FILEBEAT_YML" ]; then
        echo ""
        echo "  Filebeat config proxy settings:"
        if grep -qiE '^\s*proxy_url:' "$FILEBEAT_YML" 2>/dev/null; then
            check_pass "proxy_url configured in $FILEBEAT_YML"
            grep -iE '^\s*proxy_url:' "$FILEBEAT_YML" | sed 's/^/       /'
        else
            check_info "No proxy_url in $FILEBEAT_YML (usually not needed for local indexer output)"
        fi
    fi
else
    check_pass "No proxy environment variables detected (http_proxy/https_proxy not set)"
fi

# ============================================
# 16. Agent Event Ingestion Check
# ============================================
section "Agent Event Ingestion"

# Build curl auth/TLS flags for indexer API queries
CURL_BASE_FLAGS="-s --noproxy $INDEXER_HOST --connect-timeout 5 -o /dev/null -w %{http_code}"
CURL_QUERY_FLAGS="-s --noproxy $INDEXER_HOST --connect-timeout 5"
INDEXER_URL="https://${INDEXER_HOST}:${INDEXER_PORT}"

# Try admin credentials from environment, common defaults, or ossec internal_users
INDEXER_USER="${WAZUH_INDEXER_USER:-admin}"
INDEXER_PASS="${WAZUH_INDEXER_PASS:-}"

# If no password supplied, try to read from Wazuh internal users file
if [ -z "$INDEXER_PASS" ]; then
    INTERNAL_USERS="/etc/wazuh-indexer/opensearch-security/internal_users.yml"
    if [ -f "$INTERNAL_USERS" ]; then
        # internal_users.yml stores hashed passwords; we can't extract the plaintext
        # Fall back to the common default
        INDEXER_PASS="admin"
    else
        INDEXER_PASS="admin"
    fi
fi

AUTH_FLAGS="-u ${INDEXER_USER}:${INDEXER_PASS}"
TLS_FLAGS="-k"

# Use client certificate if available (required by some indexer configurations)
CERT_FLAGS=""
if [ -f "$INDEXER_CERTS_DIR/$ADMIN_CERT" ] && [ -f "$INDEXER_CERTS_DIR/$ADMIN_KEY" ]; then
    CERT_FLAGS="--cert $INDEXER_CERTS_DIR/$ADMIN_CERT --key $INDEXER_CERTS_DIR/$ADMIN_KEY"
fi

# --- Verify API is reachable with auth ---
api_status=$(curl $CURL_BASE_FLAGS $TLS_FLAGS $CERT_FLAGS $AUTH_FLAGS "$INDEXER_URL" 2>/dev/null || echo "000")
if [ "$api_status" = "000" ]; then
    check_fail "Cannot reach indexer API at $INDEXER_URL"
    echo "       Skipping ingestion checks (API unreachable)"
elif [ "$api_status" = "401" ] || [ "$api_status" = "403" ]; then
    check_fail "Indexer API authentication failed (HTTP $api_status)"
    echo "       Set WAZUH_INDEXER_USER and WAZUH_INDEXER_PASS env vars if defaults don't work"
    echo "       Skipping ingestion checks"
else
    check_pass "Indexer API reachable (HTTP $api_status)"

    # --- Check wazuh-alerts-* index exists and has documents ---
    echo ""
    echo "  Checking wazuh-alerts-* index..."
    alerts_response=$(curl $CURL_QUERY_FLAGS $TLS_FLAGS $CERT_FLAGS $AUTH_FLAGS "$INDEXER_URL/wazuh-alerts-*/_count" 2>/dev/null || echo "")

    if [ -z "$alerts_response" ]; then
        check_fail "No response when querying wazuh-alerts-* index"
    elif echo "$alerts_response" | grep -q '"count"'; then
        alerts_count=$(echo "$alerts_response" | grep -oP '"count"\s*:\s*\K[0-9]+' || echo "0")
        if [ "$alerts_count" -gt 0 ] 2>/dev/null; then
            check_pass "wazuh-alerts-* contains $alerts_count documents"
        else
            check_warn "wazuh-alerts-* index exists but has 0 documents"
            echo "       Agents may not be sending events, or Filebeat may not be forwarding them"
        fi
    elif echo "$alerts_response" | grep -q "index_not_found"; then
        check_fail "wazuh-alerts-* index does not exist"
        echo "       No alerts have been ingested yet — check Filebeat and manager connectivity"
    else
        check_warn "Unexpected response from wazuh-alerts-* count query"
        echo "       Response: ${alerts_response:0:200}"
    fi

    # --- Check for recent events (last 5 minutes) ---
    echo ""
    echo "  Checking for recent events (last 5 minutes)..."
    recent_query='{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}'
    recent_response=$(curl $CURL_QUERY_FLAGS $TLS_FLAGS $CERT_FLAGS $AUTH_FLAGS \
        -H "Content-Type: application/json" \
        -d "$recent_query" \
        "$INDEXER_URL/wazuh-alerts-*/_count" 2>/dev/null || echo "")

    if echo "$recent_response" | grep -q '"count"'; then
        recent_count=$(echo "$recent_response" | grep -oP '"count"\s*:\s*\K[0-9]+' || echo "0")
        if [ "$recent_count" -gt 0 ] 2>/dev/null; then
            check_pass "$recent_count events ingested in the last 5 minutes"
        else
            check_warn "No events in the last 5 minutes"
            echo "       This may be normal for low-traffic environments"
            echo "       Verify: agents are connected, Filebeat is running, manager is receiving events"
        fi
    fi

    # --- Check which agents have reported in ---
    echo ""
    echo "  Checking for distinct reporting agents..."
    agents_query='{"size":0,"aggs":{"agents":{"terms":{"field":"agent.id","size":50}}}}'
    agents_response=$(curl $CURL_QUERY_FLAGS $TLS_FLAGS $CERT_FLAGS $AUTH_FLAGS \
        -H "Content-Type: application/json" \
        -d "$agents_query" \
        "$INDEXER_URL/wazuh-alerts-*/_search" 2>/dev/null || echo "")

    if echo "$agents_response" | grep -q '"buckets"'; then
        agent_count=$(echo "$agents_response" | grep -oP '"buckets"\s*:\s*\[' | head -1)
        # Count agent entries in the buckets array
        num_agents=$(echo "$agents_response" | grep -oP '"key"\s*:\s*"[^"]*"' | wc -l)
        if [ "$num_agents" -gt 0 ] 2>/dev/null; then
            check_pass "$num_agents distinct agent(s) have events in the index"
            echo "       Agent IDs:"
            echo "$agents_response" | grep -oP '"key"\s*:\s*"\K[^"]+' | head -10 | while read -r aid; do
                agent_docs=$(echo "$agents_response" | grep -oP "\"key\"\\s*:\\s*\"${aid}\"[^}]*\"doc_count\"\\s*:\\s*\\K[0-9]+" || echo "?")
                echo "         - Agent $aid ($agent_docs events)"
            done
        else
            check_warn "No agent data found in aggregation"
        fi
    fi

    # --- Check wazuh-archives-* if present ---
    echo ""
    echo "  Checking wazuh-archives-* index..."
    archives_response=$(curl $CURL_QUERY_FLAGS $TLS_FLAGS $CERT_FLAGS $AUTH_FLAGS "$INDEXER_URL/wazuh-archives-*/_count" 2>/dev/null || echo "")

    if echo "$archives_response" | grep -q '"count"'; then
        archives_count=$(echo "$archives_response" | grep -oP '"count"\s*:\s*\K[0-9]+' || echo "0")
        if [ "$archives_count" -gt 0 ] 2>/dev/null; then
            check_pass "wazuh-archives-* contains $archives_count documents"
        else
            check_info "wazuh-archives-* exists but has 0 documents (archiving may be disabled)"
        fi
    elif echo "$archives_response" | grep -q "index_not_found"; then
        check_info "wazuh-archives-* index does not exist (archiving is likely disabled — this is normal)"
    fi

    # --- Check Filebeat connectivity ---
    echo ""
    echo "  Checking Filebeat status..."
    if systemctl is-active --quiet filebeat 2>/dev/null; then
        check_pass "Filebeat service is running"

        # Check for Filebeat output errors in recent logs
        fb_errors=$(journalctl -u filebeat --no-pager -n 100 --since "5 minutes ago" 2>/dev/null | grep -ciE "(error|failed|connection refused)" 2>/dev/null) || fb_errors=0
        if [ "$fb_errors" -gt 0 ]; then
            check_warn "Filebeat has $fb_errors error(s) in the last 5 minutes"
            echo "       Recent errors:"
            journalctl -u filebeat --no-pager -n 100 --since "5 minutes ago" 2>/dev/null | grep -iE "(error|failed|connection refused)" | tail -5 | sed 's/^/         /'
        else
            check_pass "No Filebeat errors in the last 5 minutes"
        fi
    else
        check_fail "Filebeat service is NOT running"
        echo "       Filebeat forwards Wazuh manager events to the indexer"
        echo "       Try: systemctl start filebeat && systemctl status filebeat"
    fi
fi

# ============================================
# 17. Filebeat Configuration Validation
# ============================================
section "Filebeat Configuration"

FILEBEAT_YML="/etc/filebeat/filebeat.yml"
FILEBEAT_CERTS_DIR="/etc/filebeat/certs"

if [ ! -f "$FILEBEAT_YML" ]; then
    check_fail "Filebeat config not found: $FILEBEAT_YML"
else
    check_pass "Filebeat config exists: $FILEBEAT_YML"

    # --- Output target ---
    echo ""
    echo "  Output configuration:"
    if grep -q 'output.elasticsearch' "$FILEBEAT_YML" 2>/dev/null; then
        check_pass "Output type: output.elasticsearch (expected for Wazuh)"

        # Extract hosts
        fb_hosts=$(grep -A5 'output.elasticsearch' "$FILEBEAT_YML" 2>/dev/null | grep -E '^\s*-\s*"?[0-9a-zA-Z]' | head -5)
        if [ -n "$fb_hosts" ]; then
            echo "  Configured hosts:"
            echo "$fb_hosts" | sed 's/^/       /'
        else
            # Try single-line hosts format
            fb_hosts_inline=$(grep 'hosts:' "$FILEBEAT_YML" 2>/dev/null | head -1)
            if [ -n "$fb_hosts_inline" ]; then
                echo "  Configured hosts:"
                echo "$fb_hosts_inline" | sed 's/^/       /'
            else
                check_warn "Could not parse hosts from filebeat.yml"
            fi
        fi

        # Check protocol
        fb_protocol=$(grep -E '^\s*protocol:' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'")
        if [ "$fb_protocol" = "https" ]; then
            check_pass "Protocol: https"
        elif [ -n "$fb_protocol" ]; then
            check_warn "Protocol: $fb_protocol (expected https for Wazuh indexer)"
        else
            check_warn "No protocol specified (defaults to http — should be https for Wazuh indexer)"
        fi
    else
        check_fail "No output.elasticsearch section found in filebeat.yml"
        echo "       Wazuh Filebeat must output to the indexer via output.elasticsearch"
    fi

    # --- SSL/TLS configuration ---
    echo ""
    echo "  SSL/TLS configuration:"
    if grep -q 'ssl.certificate_authorities' "$FILEBEAT_YML" 2>/dev/null; then
        fb_ca=$(grep 'ssl.certificate_authorities' "$FILEBEAT_YML" 2>/dev/null | head -1)
        echo "  $fb_ca" | sed 's/^/     /'

        # Extract CA path and check it exists
        fb_ca_path=$(grep -A1 'ssl.certificate_authorities' "$FILEBEAT_YML" 2>/dev/null | grep -oE '/[^ "]+\.pem' | head -1)
        if [ -n "$fb_ca_path" ] && [ -f "$fb_ca_path" ]; then
            check_pass "SSL CA file exists: $fb_ca_path"

            # Verify it's the same CA as the indexer
            if [ -f "$INDEXER_CERTS_DIR/$ROOT_CA" ]; then
                fb_ca_hash=$(openssl x509 -in "$fb_ca_path" -noout -hash 2>/dev/null)
                idx_ca_hash=$(openssl x509 -in "$INDEXER_CERTS_DIR/$ROOT_CA" -noout -hash 2>/dev/null)
                if [ "$fb_ca_hash" = "$idx_ca_hash" ]; then
                    check_pass "Filebeat CA matches indexer Root CA"
                else
                    check_fail "Filebeat CA does NOT match indexer Root CA!"
                    echo "       Filebeat CA hash: $fb_ca_hash ($fb_ca_path)"
                    echo "       Indexer CA hash:  $idx_ca_hash ($INDEXER_CERTS_DIR/$ROOT_CA)"
                fi
            fi
        elif [ -n "$fb_ca_path" ]; then
            check_fail "SSL CA file missing: $fb_ca_path"
        fi
    else
        check_warn "No ssl.certificate_authorities configured"
        echo "       Filebeat needs the Root CA to verify the indexer's certificate"
    fi

    # Check client certificate
    fb_cert_path=$(grep -E '^\s*ssl.certificate:' "$FILEBEAT_YML" 2>/dev/null | grep -oE '/[^ "]+' | head -1)
    fb_key_path=$(grep -E '^\s*ssl.key:' "$FILEBEAT_YML" 2>/dev/null | grep -oE '/[^ "]+' | head -1)

    if [ -n "$fb_cert_path" ]; then
        if [ -f "$fb_cert_path" ]; then
            check_pass "SSL client certificate exists: $fb_cert_path"

            # Check certificate validity
            if openssl x509 -in "$fb_cert_path" -noout -checkend 0 2>/dev/null; then
                fb_cert_expiry=$(openssl x509 -in "$fb_cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
                check_pass "Filebeat certificate is valid (expires: $fb_cert_expiry)"
            else
                check_fail "Filebeat certificate is EXPIRED!"
            fi

            # Verify it's signed by the same CA
            if [ -f "$fb_ca_path" ]; then
                if openssl verify -CAfile "$fb_ca_path" "$fb_cert_path" 2>/dev/null | grep -q "OK"; then
                    check_pass "Filebeat certificate is signed by its configured CA"
                else
                    check_fail "Filebeat certificate is NOT signed by its configured CA!"
                fi
            fi
        else
            check_fail "SSL client certificate missing: $fb_cert_path"
        fi
    else
        check_info "No ssl.certificate configured (client cert auth not in use)"
    fi

    if [ -n "$fb_key_path" ]; then
        if [ -f "$fb_key_path" ]; then
            check_pass "SSL client key exists: $fb_key_path"

            # Verify key matches certificate
            if [ -n "$fb_cert_path" ] && [ -f "$fb_cert_path" ]; then
                fb_cert_mod=$(openssl x509 -noout -modulus -in "$fb_cert_path" 2>/dev/null | md5sum | cut -d' ' -f1)
                fb_key_mod=$(openssl rsa -noout -modulus -in "$fb_key_path" 2>/dev/null | md5sum | cut -d' ' -f1)
                if [ "$fb_cert_mod" = "$fb_key_mod" ]; then
                    check_pass "Filebeat certificate and key match"
                else
                    check_fail "Filebeat certificate and key DO NOT match!"
                fi
            fi
        else
            check_fail "SSL client key missing: $fb_key_path"
        fi
    elif [ -n "$fb_cert_path" ]; then
        check_fail "ssl.certificate is set but ssl.key is missing"
    fi

    # --- Credentials ---
    echo ""
    echo "  Credentials configuration:"
    if grep -qE '^\s*username:' "$FILEBEAT_YML" 2>/dev/null; then
        fb_username=$(grep -E '^\s*username:' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'")
        if echo "$fb_username" | grep -q '^\$'; then
            check_pass "Username uses keystore variable: $fb_username"
        else
            check_pass "Username configured: $fb_username"
        fi
    else
        check_warn "No username configured in filebeat.yml"
    fi

    if grep -qE '^\s*password:' "$FILEBEAT_YML" 2>/dev/null; then
        fb_password=$(grep -E '^\s*password:' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'")
        if echo "$fb_password" | grep -q '^\$'; then
            check_pass "Password uses keystore variable: $fb_password"
        else
            check_pass "Password configured (hardcoded in config)"
        fi
    else
        check_warn "No password configured in filebeat.yml"
    fi

    # Check keystore exists if variables reference it
    FILEBEAT_KEYSTORE="/var/lib/filebeat/filebeat.keystore"
    if grep -qE '\$\{' "$FILEBEAT_YML" 2>/dev/null; then
        if [ -f "$FILEBEAT_KEYSTORE" ]; then
            check_pass "Filebeat keystore exists: $FILEBEAT_KEYSTORE"
        else
            check_fail "Filebeat keystore missing: $FILEBEAT_KEYSTORE"
            echo "       Config references keystore variables but keystore does not exist"
            echo "       Create with: filebeat keystore create"
        fi
    fi

    # --- Wazuh module ---
    echo ""
    echo "  Wazuh module configuration:"
    if grep -q 'module: wazuh' "$FILEBEAT_YML" 2>/dev/null; then
        check_pass "Wazuh module is configured in filebeat.yml"

        if grep -qE '^\s+alerts:' "$FILEBEAT_YML" 2>/dev/null; then
            alerts_enabled=$(grep -A2 'alerts:' "$FILEBEAT_YML" 2>/dev/null | grep 'enabled:' | head -1 | awk '{print $2}')
            if [ "$alerts_enabled" = "true" ]; then
                check_pass "Wazuh alerts collection is enabled"
            else
                check_warn "Wazuh alerts collection is not enabled"
            fi
        fi

        if grep -qE '^\s+archives:' "$FILEBEAT_YML" 2>/dev/null; then
            archives_enabled=$(grep -A2 'archives:' "$FILEBEAT_YML" 2>/dev/null | grep 'enabled:' | head -1 | awk '{print $2}')
            if [ "$archives_enabled" = "true" ]; then
                check_info "Wazuh archives collection is enabled"
            else
                check_info "Wazuh archives collection is disabled (normal)"
            fi
        fi
    else
        check_fail "Wazuh module is NOT configured in filebeat.yml"
        echo "       filebeat.yml must include: - module: wazuh"
    fi

    # --- Wazuh module files on disk ---
    echo ""
    echo "  Wazuh module installation:"
    FILEBEAT_MODULE_DIR="/usr/share/filebeat/module"
    WAZUH_MODULE_DIR="$FILEBEAT_MODULE_DIR/wazuh"

    if [ -d "$WAZUH_MODULE_DIR" ]; then
        check_pass "Wazuh module directory exists: $WAZUH_MODULE_DIR"

        # Check for alerts manifest
        if [ -f "$WAZUH_MODULE_DIR/alerts/manifest.yml" ]; then
            check_pass "Wazuh alerts manifest present"
        else
            check_fail "Wazuh alerts manifest missing: $WAZUH_MODULE_DIR/alerts/manifest.yml"
        fi

        # Check for archives manifest
        if [ -f "$WAZUH_MODULE_DIR/archives/manifest.yml" ]; then
            check_pass "Wazuh archives manifest present"
        else
            check_warn "Wazuh archives manifest missing: $WAZUH_MODULE_DIR/archives/manifest.yml"
        fi

        # Check module.yml
        if [ -f "$WAZUH_MODULE_DIR/module.yml" ]; then
            check_pass "Wazuh module.yml present"
        else
            check_fail "Wazuh module.yml missing: $WAZUH_MODULE_DIR/module.yml"
        fi

        # Show module contents
        echo "       Module contents:"
        ls -la "$WAZUH_MODULE_DIR"/ 2>/dev/null | sed 's/^/         /'
    else
        check_fail "Wazuh module directory missing: $WAZUH_MODULE_DIR"
        echo "       The Wazuh Filebeat module is not installed"
        echo "       Install with: curl -so /tmp/wazuh-filebeat-module.tar.gz https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz"
        echo "                     tar -xzf /tmp/wazuh-filebeat-module.tar.gz -C $FILEBEAT_MODULE_DIR"

        # Check if any modules directory exists at all
        if [ -d "$FILEBEAT_MODULE_DIR" ]; then
            check_pass "Filebeat modules directory exists: $FILEBEAT_MODULE_DIR"
            echo "       Installed modules:"
            ls -d "$FILEBEAT_MODULE_DIR"/*/ 2>/dev/null | xargs -I{} basename {} | sed 's/^/         /' || echo "         (none)"
        else
            check_fail "Filebeat modules directory missing: $FILEBEAT_MODULE_DIR"
        fi
    fi

    # Verify filebeat can load the module
    echo ""
    echo "  Module load test:"
    if command -v filebeat &>/dev/null; then
        fb_modules_output=$(filebeat modules list 2>&1 || true)
        if echo "$fb_modules_output" | grep -q "wazuh"; then
            if echo "$fb_modules_output" | grep -B999 "^Disabled:" | grep -q "wazuh"; then
                check_warn "Wazuh module is installed but DISABLED in Filebeat"
                echo "       This may be fine if enabled via filebeat.yml directly"
            else
                check_pass "Wazuh module is listed and enabled in Filebeat"
            fi
        else
            check_fail "Wazuh module not found in 'filebeat modules list'"
            echo "       Output: ${fb_modules_output:0:200}"
        fi
    else
        check_info "filebeat command not in PATH — skipping module load test"
    fi

    # --- Wazuh template ---
    echo ""
    echo "  Wazuh index template:"
    fb_template_path=$(grep 'setup.template.json.path' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'")
    if [ -n "$fb_template_path" ]; then
        if [ -f "$fb_template_path" ]; then
            check_pass "Wazuh template file exists: $fb_template_path"
        else
            check_fail "Wazuh template file missing: $fb_template_path"
            echo "       This template defines the index mappings for Wazuh alerts"
        fi
    else
        check_warn "setup.template.json.path not set in filebeat.yml"
    fi

    fb_template_name=$(grep 'setup.template.json.name' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'")
    if [ "$fb_template_name" = "wazuh" ]; then
        check_pass "Template name: wazuh"
    elif [ -n "$fb_template_name" ]; then
        check_warn "Template name: $fb_template_name (expected: wazuh)"
    fi

    # --- ILM should be disabled ---
    fb_ilm=$(grep 'setup.ilm.enabled' "$FILEBEAT_YML" 2>/dev/null | head -1 | awk '{print $2}')
    if [ "$fb_ilm" = "false" ]; then
        check_pass "ILM is disabled (correct for Wazuh)"
    elif [ -n "$fb_ilm" ]; then
        check_warn "ILM is set to $fb_ilm (should be false for Wazuh)"
    fi
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
