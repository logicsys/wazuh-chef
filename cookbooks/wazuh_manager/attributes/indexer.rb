# Cookbook:: wazuh-manager
# Attributes:: indexer
# Author:: Wazuh <info@wazuh.com>

# =============================================================================
# Wazuh Indexer Integration Configuration
# =============================================================================
# This configures the manager's connection to the Wazuh Indexer (OpenSearch)
# for vulnerability detection and other indexer-dependent features.
#
# For single-node deployments, the default configuration should work.
# For multi-node deployments, update the hosts array with all indexer nodes.
# =============================================================================

# Indexer connection settings
default['ossec']['conf']['indexer'] = {
  'enabled' => 'yes',
  'hosts' => {
    'host' => 'https://127.0.0.1:9200',
  },
  'ssl' => {
    'certificate_authorities' => {
      'ca' => '/var/ossec/etc/certs/root-ca.pem',
    },
    'certificate' => '/var/ossec/etc/certs/filebeat.pem',
    'key' => '/var/ossec/etc/certs/filebeat-key.pem',
  },
}

# Indexer authentication credentials (stored in wazuh-keystore, not in ossec.conf)
# These are used by the recipes/manager.rb to initialize the keystore
default['wazuh_manager']['indexer']['username'] = 'admin'
default['wazuh_manager']['indexer']['password'] = 'admin'

# =============================================================================
# Certificate Configuration for Manager
# =============================================================================
# Certificates for manager-to-indexer communication (uses filebeat certs)
# These should be the same certificates used by Filebeat
#
# Required certificates:
#   - filebeat.pem (node certificate for indexer auth)
#   - filebeat-key.pem (node private key)
#   - root-ca.pem (CA certificate)
# =============================================================================

default['wazuh_manager']['certs_path'] = '/var/ossec/etc/certs'

# Certificate content (PEM format) - set in role/environment/wrapper cookbook
# If nil, cookbook will skip certificate deployment (manual placement expected)
default['wazuh_manager']['certificates']['filebeat_pem'] = nil
default['wazuh_manager']['certificates']['filebeat_key'] = nil
default['wazuh_manager']['certificates']['root_ca_pem'] = nil

# Data bag configuration (alternative to direct attributes)
default['wazuh_manager']['certificates']['data_bag_name'] = nil
default['wazuh_manager']['certificates']['data_bag_item'] = nil
