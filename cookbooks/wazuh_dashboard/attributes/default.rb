# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Attributes:: default
# Author:: Wazuh <info@wazuh.com>

# Wazuh version
default['wazuh']['major_version'] = '4.x'
default['wazuh']['minor_version'] = '4.14'
default['wazuh']['patch_version'] = '4.14.2'

# Wazuh Dashboard settings
default['wazuh_dashboard']['version'] = node['wazuh']['patch_version']
default['wazuh_dashboard']['config_path'] = '/etc/wazuh-dashboard'
default['wazuh_dashboard']['certs_path'] = '/etc/wazuh-dashboard/certs'
default['wazuh_dashboard']['package_path'] = '/usr/share/wazuh-dashboard'

# Dashboard configuration
default['wazuh_dashboard']['yml']['server']['host'] = '0.0.0.0'
default['wazuh_dashboard']['yml']['server']['port'] = 443
default['wazuh_dashboard']['yml']['opensearch']['hosts'] = ['https://127.0.0.1:9200']

# SSL settings
default['wazuh_dashboard']['ssl']['enabled'] = true

# Wazuh API connection settings
default['wazuh_dashboard']['wazuh_api']['url'] = 'https://127.0.0.1'
default['wazuh_dashboard']['wazuh_api']['port'] = 55000
default['wazuh_dashboard']['wazuh_api']['username'] = 'wazuh-wui'
default['wazuh_dashboard']['wazuh_api']['password'] = 'wazuh-wui'

# =============================================================================
# Certificate Configuration (Manual Deployment)
# =============================================================================
# Certificates must be generated externally using wazuh-certs-tool.sh
# See: https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/certificates.html
#
# Option 1: Provide certificate content directly (PEM format)
# Option 2: Use a Chef data bag (set data_bag_name and data_bag_item)
# Option 3: Place certificates manually and set paths only
#
# Required certificates:
#   - dashboard.pem (node certificate)
#   - dashboard-key.pem (node private key)
#   - root-ca.pem (CA certificate)
# =============================================================================

# Certificate content (PEM format) - set these in your role/environment/wrapper cookbook
# If nil, cookbook will skip certificate deployment (manual placement expected)
default['wazuh_dashboard']['certificates']['dashboard_pem'] = nil
default['wazuh_dashboard']['certificates']['dashboard_key'] = nil
default['wazuh_dashboard']['certificates']['root_ca_pem'] = nil

# Data bag configuration (alternative to direct attributes)
# Set to use certificates from an encrypted data bag
default['wazuh_dashboard']['certificates']['data_bag_name'] = nil
default['wazuh_dashboard']['certificates']['data_bag_item'] = nil

# =============================================================================
# OpenSearch Connection Credentials
# =============================================================================
# The dashboard uses the 'kibanaserver' user to connect to OpenSearch/Wazuh Indexer.
# After running wazuh_indexer::passwords, update this password and run
# wazuh_dashboard::passwords to apply the changes.
# =============================================================================
default['wazuh_dashboard']['opensearch']['username'] = 'kibanaserver'
default['wazuh_dashboard']['opensearch']['password'] = nil # Set after running wazuh_indexer::passwords
