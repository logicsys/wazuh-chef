# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Recipe:: passwords
# Author:: Wazuh <info@wazuh.com>
#
# This recipe updates the Wazuh Dashboard's OpenSearch connection credentials.
# Run this after wazuh_indexer::passwords to update the dashboard with new passwords.
#
# The dashboard uses the 'kibanaserver' user to connect to OpenSearch/Wazuh Indexer.
#
# Usage:
#   1. Run wazuh_indexer::passwords first to change indexer passwords
#   2. Set the new password in node['wazuh_dashboard']['opensearch']['password']
#      or let it be retrieved from run_state
#   3. Include this recipe to update the dashboard configuration

config_path = node['wazuh_dashboard']['config_path']
package_path = node['wazuh_dashboard']['package_path']

# Get kibanaserver password from run_state or attributes
ruby_block 'get_kibanaserver_password' do
  block do
    if node.run_state['wazuh_passwords'] && node.run_state['wazuh_passwords']['kibanaserver']
      node.run_state['dashboard_opensearch_password'] = node.run_state['wazuh_passwords']['kibanaserver']
      Chef::Log.info('Using kibanaserver password from wazuh_indexer::passwords run_state')
    elsif node['wazuh_dashboard']['opensearch']['password']
      node.run_state['dashboard_opensearch_password'] = node['wazuh_dashboard']['opensearch']['password']
      Chef::Log.info('Using kibanaserver password from node attributes')
    else
      Chef::Log.warn('No kibanaserver password found - dashboard may not connect to indexer')
      node.run_state['dashboard_opensearch_password'] = 'kibanaserver' # default
    end
  end
  action :run
end

# Update opensearch_dashboards.yml with new credentials
# The dashboard uses keystore for credentials
execute 'create_dashboard_keystore' do
  command "#{package_path}/bin/opensearch-dashboards-keystore create --allow-root"
  action :run
  not_if { ::File.exist?("#{package_path}/data/opensearch-dashboards.keystore") }
end

ruby_block 'update_dashboard_opensearch_credentials' do
  block do
    password = node.run_state['dashboard_opensearch_password']

    # Remove existing credentials if present
    system("#{package_path}/bin/opensearch-dashboards-keystore remove opensearch.username --allow-root 2>/dev/null || true")
    system("#{package_path}/bin/opensearch-dashboards-keystore remove opensearch.password --allow-root 2>/dev/null || true")

    # Add new credentials
    # Using echo to pipe password to avoid showing it in process list
    system("echo 'kibanaserver' | #{package_path}/bin/opensearch-dashboards-keystore add opensearch.username --stdin --allow-root")
    system("echo '#{password}' | #{package_path}/bin/opensearch-dashboards-keystore add opensearch.password --stdin --allow-root")

    Chef::Log.info('Updated OpenSearch credentials in dashboard keystore')
  end
  action :run
  sensitive true
end

# Set proper ownership on keystore
file "#{package_path}/data/opensearch-dashboards.keystore" do
  owner 'wazuh-dashboard'
  group 'wazuh-dashboard'
  mode '0600'
  action :create
  only_if { ::File.exist?("#{package_path}/data/opensearch-dashboards.keystore") }
end

# Restart dashboard to apply new credentials
service 'wazuh-dashboard' do
  action :restart
  only_if { ::File.exist?('/usr/lib/systemd/system/wazuh-dashboard.service') }
end

log 'dashboard_password_update_complete' do
  message <<~MSG
    ============================================================================
    Wazuh Dashboard OpenSearch credentials updated.
    The wazuh-dashboard service has been restarted to apply the changes.
    ============================================================================
  MSG
  level :info
end
