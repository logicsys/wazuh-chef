# frozen_string_literal: true

# Cookbook:: wazuh_manager
# Recipe:: certificates
# Author:: Wazuh <info@wazuh.com>

# =============================================================================
# Certificate Deployment for Wazuh Manager
# =============================================================================
# This recipe deploys TLS certificates for the Wazuh Manager's connection
# to the Wazuh Indexer. These are typically the same certificates used by
# Filebeat (filebeat.pem, filebeat-key.pem, root-ca.pem).
#
# Usage options:
#   1. Set certificate content in attributes (node['wazuh_manager']['certificates'])
#   2. Use an encrypted data bag (set data_bag_name and data_bag_item)
#   3. Skip this recipe and place certificates manually
# =============================================================================

certs_path = node['wazuh_manager']['certs_path']

# Create certificates directory
directory certs_path do
  owner 'root'
  group node['ossec']['group']
  mode '0500'
  recursive true
  action :create
end

# Load certificates from data bag if configured
certs = {}
if node['wazuh_manager']['certificates']['data_bag_name'] &&
   node['wazuh_manager']['certificates']['data_bag_item']
  begin
    certs = data_bag_item(
      node['wazuh_manager']['certificates']['data_bag_name'],
      node['wazuh_manager']['certificates']['data_bag_item']
    )
    Chef::Log.info('Loaded manager certificates from data bag')
  rescue StandardError => e
    Chef::Log.warn("Could not load manager certificates from data bag: #{e.message}")
  end
end

# Certificate file mappings
cert_files = {
  'filebeat.pem' => certs['filebeat_pem'] || node['wazuh_manager']['certificates']['filebeat_pem'],
  'filebeat-key.pem' => certs['filebeat_key'] || node['wazuh_manager']['certificates']['filebeat_key'],
  'root-ca.pem' => certs['root_ca_pem'] || node['wazuh_manager']['certificates']['root_ca_pem'],
}

# Track if all certificates are available
certs_available = true

cert_files.each do |filename, content|
  if content.nil? || content.empty?
    Chef::Log.warn("Manager certificate #{filename} not provided - manual deployment required")
    certs_available = false
    next
  end

  file "#{certs_path}/#{filename}" do
    content content
    owner 'root'
    group node['ossec']['group']
    mode filename.include?('key') ? '0400' : '0440'
    sensitive true
    action :create
    notifies :restart, 'service[wazuh]', :delayed if defined?(resources('service[wazuh]'))
  end
end

# Log warning if certificates are missing
unless certs_available
  log 'manager_certificates_warning' do
    message <<~MSG
      ============================================================================
      WARNING: Not all manager certificates were provided via attributes or data bag.

      Required certificates for #{certs_path}:
        - filebeat.pem (node certificate for indexer authentication)
        - filebeat-key.pem (node private key)
        - root-ca.pem (CA certificate)

      These certificates are used for the manager's connection to the Wazuh Indexer.
      They are typically the same certificates used by Filebeat.

      Generate certificates using wazuh-certs-tool.sh:
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/wazuh-certs-tool.sh
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/config.yml
        bash ./wazuh-certs-tool.sh -A

      Then either:
        1. Set certificate content in node attributes
        2. Use an encrypted data bag
        3. Manually copy certificates to #{certs_path}

      The Wazuh Manager will not be able to connect to the Indexer without these certificates.
      ============================================================================
    MSG
    level :warn
  end
end

# Set permissions on certificates directory
execute 'fix_manager_certs_permissions' do
  command "chown -R root:#{node['ossec']['group']} #{certs_path} && chmod 500 #{certs_path} && chmod 440 #{certs_path}/*.pem 2>/dev/null || true && chmod 400 #{certs_path}/*-key.pem 2>/dev/null || true"
  only_if { ::Dir.exist?(certs_path) }
  action :run
end
