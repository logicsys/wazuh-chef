# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: passwords
# Author:: Wazuh <info@wazuh.com>
#
# This recipe changes the default passwords for Wazuh Indexer users.
# It should be run AFTER the indexer is fully initialized and security is configured.
#
# Usage:
#   1. Include this recipe after wazuh_indexer::indexer
#   2. Set node['wazuh_indexer']['passwords']['change_defaults'] = true
#   3. Optionally provide custom passwords in attributes or let them be generated
#
# The recipe will:
#   - Generate secure random passwords if not provided
#   - Update internal_users.yml with new password hashes
#   - Run securityadmin to apply changes
#   - Store passwords in a file for reference (can be disabled)

require 'securerandom'

certs_path = node['wazuh_indexer']['certs_path']
config_path = node['wazuh_indexer']['config_path']
passwords_file = node['wazuh_indexer']['passwords']['output_file']

# Only run if password change is enabled and security is initialized
return unless node['wazuh_indexer']['passwords']['change_defaults']

unless ::File.exist?('/var/lib/wazuh-indexer/.security_initialized')
  Chef::Log.warn('Wazuh Indexer security not initialized - skipping password change')
  return
end

if ::File.exist?('/var/lib/wazuh-indexer/.passwords_changed')
  Chef::Log.info('Wazuh Indexer passwords already changed - skipping')
  return
end

# Define users to update
users_to_update = node['wazuh_indexer']['passwords']['users'].to_h

# Generate passwords for users that don't have one specified
ruby_block 'generate_passwords' do
  block do
    users_to_update.each do |user, config|
      if config['password'].nil? || config['password'].empty?
        # Generate a secure random password
        password = SecureRandom.alphanumeric(24)
        node.run_state['wazuh_passwords'] ||= {}
        node.run_state['wazuh_passwords'][user] = password
        Chef::Log.info("Generated password for user: #{user}")
      else
        node.run_state['wazuh_passwords'] ||= {}
        node.run_state['wazuh_passwords'][user] = config['password']
      end
    end
  end
  action :run
end

# Backup current internal_users.yml
execute 'backup_internal_users' do
  command "cp #{config_path}/opensearch-security/internal_users.yml #{config_path}/opensearch-security/internal_users.yml.bak.$(date +%Y%m%d%H%M%S)"
  action :run
  only_if { ::File.exist?("#{config_path}/opensearch-security/internal_users.yml") }
end

# Generate password hashes and update internal_users.yml
ruby_block 'update_password_hashes' do
  block do
    require 'open3'

    internal_users_file = "#{config_path}/opensearch-security/internal_users.yml"
    hash_script = '/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh'

    unless ::File.exist?(internal_users_file)
      Chef::Log.error("internal_users.yml not found at #{internal_users_file}")
      raise "internal_users.yml not found"
    end

    unless ::File.exist?(hash_script)
      Chef::Log.error("hash.sh script not found at #{hash_script}")
      raise "hash.sh script not found"
    end

    # Read current internal_users.yml
    content = ::File.read(internal_users_file)

    node.run_state['wazuh_passwords'].each do |user, password|
      # Generate bcrypt hash using the provided hash.sh script
      env = { 'JAVA_HOME' => '/usr/share/wazuh-indexer/jdk/' }
      stdout, stderr, status = Open3.capture3(env, hash_script, '-p', password)

      unless status.success?
        Chef::Log.error("Failed to generate hash for #{user}: #{stderr}")
        next
      end

      hash = stdout.strip

      # Update the hash in internal_users.yml
      # Match the user block and replace the hash line
      user_pattern = /^#{Regexp.escape(user)}:\s*\n(\s+)hash:\s*"[^"]*"/m
      if content.match?(user_pattern)
        content.gsub!(user_pattern, "#{user}:\n\\1hash: \"#{hash}\"")
        Chef::Log.info("Updated password hash for user: #{user}")
      else
        Chef::Log.warn("User #{user} not found in internal_users.yml - skipping")
      end
    end

    # Write updated content
    ::File.write(internal_users_file, content)
    Chef::Log.info("Updated internal_users.yml with new password hashes")
  end
  action :run
end

# Run securityadmin to apply changes
bash 'apply_password_changes' do
  code <<-EOH
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk/
    export OPENSEARCH_CONF_DIR=#{config_path}

    # Determine host to connect to
    network_host="#{node['wazuh_indexer']['yml']['network']['host']}"
    if [ "$network_host" = "0.0.0.0" ]; then
      connect_host="127.0.0.1"
    else
      connect_host="$network_host"
    fi

    # Run securityadmin to apply the new configuration
    sudo -u wazuh-indexer \
      JAVA_HOME=/usr/share/wazuh-indexer/jdk/ \
      OPENSEARCH_CONF_DIR=#{config_path} \
      /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f #{config_path}/opensearch-security/internal_users.yml \
      -t internalusers \
      -p #{node['wazuh_indexer']['yml']['http']['port']} \
      -nhnv \
      -cacert #{certs_path}/root-ca.pem \
      -cert #{certs_path}/admin.pem \
      -key #{certs_path}/admin-key.pem \
      -icl \
      -h $connect_host

    if [ $? -eq 0 ]; then
      echo "Security configuration applied successfully"
    else
      echo "Failed to apply security configuration"
      exit 1
    fi
  EOH
  action :run
  only_if do
    ::File.exist?("#{certs_path}/admin.pem") &&
      ::File.exist?("#{certs_path}/admin-key.pem")
  end
end

# Save passwords to file for reference (if enabled)
ruby_block 'save_passwords_file' do
  block do
    if node['wazuh_indexer']['passwords']['save_to_file']
      passwords_content = "# Wazuh Indexer Passwords\n"
      passwords_content += "# Generated: #{Time.now}\n"
      passwords_content += "# WARNING: Store this file securely and delete after noting passwords\n\n"

      node.run_state['wazuh_passwords'].each do |user, password|
        passwords_content += "#{user}: #{password}\n"
      end

      ::File.write(passwords_file, passwords_content)
      ::File.chmod(0600, passwords_file)
      Chef::Log.info("Passwords saved to #{passwords_file}")
    end
  end
  action :run
end

# Mark passwords as changed
file '/var/lib/wazuh-indexer/.passwords_changed' do
  content "Passwords changed at #{Time.now}\n"
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0644'
  action :create
end

# Update the admin credentials in node attributes for other recipes to use
ruby_block 'update_admin_credentials' do
  block do
    if node.run_state['wazuh_passwords'] && node.run_state['wazuh_passwords']['admin']
      # Store new admin password in run_state for other recipes
      node.run_state['wazuh_indexer_admin_password'] = node.run_state['wazuh_passwords']['admin']
      Chef::Log.info("Admin password updated in run_state for use by other recipes")
    end
  end
  action :run
end

log 'password_change_complete' do
  message <<~MSG
    ============================================================================
    Wazuh Indexer passwords have been changed!

    #{"Passwords saved to: #{passwords_file}" if node['wazuh_indexer']['passwords']['save_to_file']}

    IMPORTANT: Update the following components with the new passwords:
      - Wazuh Dashboard (opensearch connection)
      - Wazuh Manager (indexer keystore)
      - Filebeat (keystore)

    You can use the wazuh_dashboard::passwords and wazuh_manager::passwords
    recipes to update these components automatically.
    ============================================================================
  MSG
  level :info
end
