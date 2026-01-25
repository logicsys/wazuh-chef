# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: certificates
# Author:: Wazuh <info@wazuh.com>

# =============================================================================
# Certificate Deployment for Wazuh Indexer
# =============================================================================
# This recipe deploys TLS certificates for the Wazuh Indexer.
# Certificates must be generated externally using wazuh-certs-tool.sh
#
# Usage options:
#   1. Set certificate content in attributes (node['wazuh_indexer']['certificates'])
#   2. Use an encrypted data bag (set data_bag_name and data_bag_item)
#   3. Skip this recipe and place certificates manually
# =============================================================================

certs_path = node['wazuh_indexer']['certs_path']

# Create certificates directory
directory certs_path do
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0500'
  recursive true
  action :create
end

# Load certificates from data bag if configured
certs = {}
if node['wazuh_indexer']['certificates']['data_bag_name'] &&
   node['wazuh_indexer']['certificates']['data_bag_item']
  begin
    certs = data_bag_item(
      node['wazuh_indexer']['certificates']['data_bag_name'],
      node['wazuh_indexer']['certificates']['data_bag_item']
    )
    Chef::Log.info('Loaded certificates from data bag')
  rescue StandardError => e
    Chef::Log.warn("Could not load certificates from data bag: #{e.message}")
  end
end

# Certificate file mappings
cert_files = {
  'indexer.pem' => certs['indexer_pem'] || node['wazuh_indexer']['certificates']['indexer_pem'],
  'indexer-key.pem' => certs['indexer_key'] || node['wazuh_indexer']['certificates']['indexer_key'],
  'root-ca.pem' => certs['root_ca_pem'] || node['wazuh_indexer']['certificates']['root_ca_pem'],
  'admin.pem' => certs['admin_pem'] || node['wazuh_indexer']['certificates']['admin_pem'],
  'admin-key.pem' => certs['admin_key'] || node['wazuh_indexer']['certificates']['admin_key'],
}

# Track if all certificates are available
certs_available = true

cert_files.each do |filename, content|
  if content.nil? || content.empty?
    Chef::Log.warn("Certificate #{filename} not provided - manual deployment required")
    certs_available = false
    next
  end

  file "#{certs_path}/#{filename}" do
    content content
    owner 'wazuh-indexer'
    group 'wazuh-indexer'
    mode filename.include?('key') ? '0400' : '0440'
    sensitive true
    action :create
    notifies :restart, 'service[wazuh-indexer]', :delayed if defined?(resources('service[wazuh-indexer]'))
  end
end

# Log warning if certificates are missing
unless certs_available
  log 'certificates_warning' do
    message <<~MSG
      ============================================================================
      WARNING: Not all certificates were provided via attributes or data bag.

      Required certificates for #{certs_path}:
        - indexer.pem (node certificate)
        - indexer-key.pem (node private key)
        - root-ca.pem (CA certificate)
        - admin.pem (admin certificate)
        - admin-key.pem (admin private key)

      Generate certificates using wazuh-certs-tool.sh:
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/wazuh-certs-tool.sh
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/config.yml
        bash ./wazuh-certs-tool.sh -A

      Then either:
        1. Set certificate content in node attributes
        2. Use an encrypted data bag
        3. Manually copy certificates to #{certs_path}

      The Wazuh Indexer service will not start until certificates are in place.
      ============================================================================
    MSG
    level :warn
  end
end

# Set permissions on certificates directory
# Note: chmod 440 *.pem first, then chmod 400 *-key.pem to ensure key files get correct permissions
execute 'fix_certs_permissions' do
  command "chown -R wazuh-indexer:wazuh-indexer #{certs_path} && chmod 500 #{certs_path} && chmod 440 #{certs_path}/*.pem 2>/dev/null || true && chmod 400 #{certs_path}/*-key.pem 2>/dev/null || true"
  only_if { ::Dir.exist?(certs_path) }
  action :run
end
