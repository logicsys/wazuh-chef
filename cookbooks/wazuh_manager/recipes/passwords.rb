# frozen_string_literal: true

# Cookbook:: wazuh_manager
# Recipe:: passwords
# Author:: Wazuh <info@wazuh.com>
#
# This recipe updates the Wazuh Manager's indexer credentials in the keystore.
# Run this after wazuh_indexer::passwords to update the manager with new passwords.
#
# Usage:
#   1. Run wazuh_indexer::passwords first to change indexer passwords
#   2. Set the new password in node['wazuh_manager']['indexer']['password']
#   3. Include this recipe to update the manager's keystore

admin_username = node['wazuh_manager']['indexer']['username']
admin_password = node['wazuh_manager']['indexer']['password']

# Check if password is available from run_state (set by wazuh_indexer::passwords)
ruby_block 'get_indexer_password_from_run_state' do
  block do
    if node.run_state['wazuh_indexer_admin_password']
      node.run_state['manager_indexer_password'] = node.run_state['wazuh_indexer_admin_password']
      Chef::Log.info('Using admin password from wazuh_indexer::passwords run_state')
    else
      node.run_state['manager_indexer_password'] = admin_password
      Chef::Log.info('Using admin password from node attributes')
    end
  end
  action :run
end

# Update the indexer username in wazuh-keystore
execute 'update_indexer_username' do
  command "/var/ossec/bin/wazuh-keystore -f indexer -k username -v #{admin_username}"
  action :run
  sensitive true
end

# Update the indexer password in wazuh-keystore
ruby_block 'update_indexer_password' do
  block do
    password = node.run_state['manager_indexer_password']
    system("/var/ossec/bin/wazuh-keystore -f indexer -k password -v '#{password}'")
    Chef::Log.info('Updated indexer password in wazuh-keystore')
  end
  action :run
  sensitive true
end

# Restart the manager to apply new credentials
service 'wazuh-manager' do
  action :restart
  only_if { ::File.exist?('/var/ossec/bin/wazuh-control') }
end

log 'manager_password_update_complete' do
  message <<~MSG
    ============================================================================
    Wazuh Manager indexer credentials updated in keystore.
    The wazuh-manager service has been restarted to apply the changes.
    ============================================================================
  MSG
  level :info
end
