# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Recipe:: certificates
# Author:: Wazuh <info@wazuh.com>

# =============================================================================
# Certificate Deployment for Wazuh Dashboard
# =============================================================================
# This recipe deploys TLS certificates for the Wazuh Dashboard.
# Certificates must be generated externally using wazuh-certs-tool.sh
#
# Usage options:
#   1. Set certificate content in attributes (node['wazuh_dashboard']['certificates'])
#   2. Use an encrypted data bag (set data_bag_name and data_bag_item)
#   3. Skip this recipe and place certificates manually
# =============================================================================

certs_path = node['wazuh_dashboard']['certs_path']

# Create certificates directory
directory certs_path do
  owner 'wazuh-dashboard'
  group 'wazuh-dashboard'
  mode '0500'
  recursive true
  action :create
end

# Load certificates from data bag if configured
certs = {}
if node['wazuh_dashboard']['certificates']['data_bag_name'] &&
   node['wazuh_dashboard']['certificates']['data_bag_item']
  begin
    certs = data_bag_item(
      node['wazuh_dashboard']['certificates']['data_bag_name'],
      node['wazuh_dashboard']['certificates']['data_bag_item']
    )
    Chef::Log.info('Loaded certificates from data bag')
  rescue StandardError => e
    Chef::Log.warn("Could not load certificates from data bag: #{e.message}")
  end
end

# Certificate file mappings
cert_files = {
  'dashboard.pem' => certs['dashboard_pem'] || node['wazuh_dashboard']['certificates']['dashboard_pem'],
  'dashboard-key.pem' => certs['dashboard_key'] || node['wazuh_dashboard']['certificates']['dashboard_key'],
  'root-ca.pem' => certs['root_ca_pem'] || node['wazuh_dashboard']['certificates']['root_ca_pem'],
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
    owner 'wazuh-dashboard'
    group 'wazuh-dashboard'
    mode filename.include?('key') ? '0400' : '0440'
    sensitive true
    action :create
    notifies :restart, 'service[wazuh-dashboard]', :delayed if defined?(resources('service[wazuh-dashboard]'))
  end
end

# Log warning if certificates are missing
unless certs_available
  log 'certificates_warning' do
    message <<~MSG
      ============================================================================
      WARNING: Not all certificates were provided via attributes or data bag.

      Required certificates for #{certs_path}:
        - dashboard.pem (node certificate)
        - dashboard-key.pem (node private key)
        - root-ca.pem (CA certificate)

      Generate certificates using wazuh-certs-tool.sh:
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/wazuh-certs-tool.sh
        curl -sO https://packages.wazuh.com/#{node['wazuh']['patch_version']}/config.yml
        bash ./wazuh-certs-tool.sh -A

      Then either:
        1. Set certificate content in node attributes
        2. Use an encrypted data bag
        3. Manually copy certificates to #{certs_path}

      The Wazuh Dashboard service will not start until certificates are in place.
      ============================================================================
    MSG
    level :warn
  end
end

# Set permissions on certificates directory
# Note: chmod 440 *.pem first, then chmod 400 *-key.pem to ensure key files get correct permissions
execute 'fix_dashboard_certs_permissions' do
  command "chown -R wazuh-dashboard:wazuh-dashboard #{certs_path} && chmod 500 #{certs_path} && chmod 440 #{certs_path}/*.pem 2>/dev/null || true && chmod 400 #{certs_path}/*-key.pem 2>/dev/null || true"
  only_if { ::Dir.exist?(certs_path) }
  action :run
end
