# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Attributes:: default
# Author:: Wazuh <info@wazuh.com>

# Wazuh version
default['wazuh']['major_version'] = '4.x'
default['wazuh']['minor_version'] = '4.14'
default['wazuh']['patch_version'] = '4.14.2'

# Wazuh Indexer settings
default['wazuh_indexer']['version'] = node['wazuh']['patch_version']
default['wazuh_indexer']['config_path'] = '/etc/wazuh-indexer'
default['wazuh_indexer']['certs_path'] = '/etc/wazuh-indexer/certs'
default['wazuh_indexer']['data_path'] = '/var/lib/wazuh-indexer'
default['wazuh_indexer']['logs_path'] = '/var/log/wazuh-indexer'

# OpenSearch configuration
default['wazuh_indexer']['yml']['network']['host'] = '0.0.0.0'
default['wazuh_indexer']['yml']['http']['port'] = 9200
default['wazuh_indexer']['yml']['transport']['port'] = 9300
default['wazuh_indexer']['yml']['node']['name'] = node['hostname']
default['wazuh_indexer']['yml']['cluster']['name'] = 'wazuh-cluster'
default['wazuh_indexer']['yml']['cluster']['initial_master_nodes'] = [node['hostname']]
default['wazuh_indexer']['yml']['discovery']['seed_hosts'] = ['127.0.0.1']

# JVM settings
default['wazuh_indexer']['jvm']['memory'] = '1g'

# Single node or cluster mode
default['wazuh_indexer']['single_node'] = true

# Security plugin DN configuration
# These must match the DNs in your certificates
default['wazuh_indexer']['security']['admin_dn'] = ['CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US']
default['wazuh_indexer']['security']['nodes_dn'] = ["CN=#{node['hostname']},OU=Wazuh,O=Wazuh,L=California,C=US"]

# =============================================================================
# Certificate Configuration (Manual Deployment)
# =============================================================================
# Certificates must be generated externally using wazuh-certs-tool.sh
# See: https://documentation.wazuh.com/current/user-manual/wazuh-indexer/certificates.html
#
# Option 1: Provide certificate content directly (base64 encoded or plain PEM)
# Option 2: Use a Chef data bag (set data_bag_name and data_bag_item)
# Option 3: Place certificates manually and set paths only
#
# Required certificates:
#   - indexer.pem (node certificate)
#   - indexer-key.pem (node private key)
#   - root-ca.pem (CA certificate)
#   - admin.pem (admin certificate for security initialization)
#   - admin-key.pem (admin private key)
# =============================================================================

# Certificate content (PEM format) - set these in your role/environment/wrapper cookbook
# If nil, cookbook will skip certificate deployment (manual placement expected)
default['wazuh_indexer']['certificates']['indexer_pem'] = nil
default['wazuh_indexer']['certificates']['indexer_key'] = nil
default['wazuh_indexer']['certificates']['root_ca_pem'] = nil
default['wazuh_indexer']['certificates']['admin_pem'] = nil
default['wazuh_indexer']['certificates']['admin_key'] = nil

# Data bag configuration (alternative to direct attributes)
# Set to use certificates from an encrypted data bag
default['wazuh_indexer']['certificates']['data_bag_name'] = nil
default['wazuh_indexer']['certificates']['data_bag_item'] = nil

# Admin credentials for API access
default['wazuh_indexer']['admin_user'] = 'admin'
default['wazuh_indexer']['admin_password'] = 'admin'
