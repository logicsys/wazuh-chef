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
#   3. Optionally:
#      - Provide custom passwords in attributes, or
#      - Configure a data bag to read passwords from, or
#      - Let them be auto-generated
#
# Data bag usage:
#   Set node['wazuh_indexer']['passwords']['data_bag_name'] and
#   node['wazuh_indexer']['passwords']['data_bag_item'] to read passwords
#   from a data bag. Expected structure:
#     {
#       "id": "indexer",
#       "admin": "your-admin-password",
#       "kibanaserver": "your-kibanaserver-password"
#     }
#   Set data_bag_encrypted = true for encrypted data bags.
#
# The recipe will:
#   - Read passwords from data bag if configured
#   - Otherwise generate secure random passwords if not provided in attributes
#   - Update internal_users.yml with new password hashes
#   - Run securityadmin to apply changes
#   - Store passwords in a file for reference (can be disabled)

require 'securerandom'

certs_path = node['wazuh_indexer']['certs_path']
config_path = node['wazuh_indexer']['config_path']
passwords_file = node['wazuh_indexer']['passwords']['output_file']

# Define users to update (evaluated at compile time, used in converge-time blocks)
users_to_update = node['wazuh_indexer']['passwords']['users'].to_h

# Common guard: only run if password change is enabled, security is initialized,
# and passwords haven't already been successfully changed. This is evaluated at CONVERGE time.
#
# We check for BOTH .passwords_changed AND the output file existing.
# If .passwords_changed exists but the output file doesn't, that's an inconsistent
# state (possibly from a failed previous run) and we should regenerate.
passwords_should_run = lambda {
  return false unless node['wazuh_indexer']['passwords']['change_defaults']
  return false unless ::File.exist?('/var/lib/wazuh-indexer/.security_initialized')

  passwords_changed_marker = '/var/lib/wazuh-indexer/.passwords_changed'
  output_file = node['wazuh_indexer']['passwords']['output_file']

  # If marker doesn't exist, we should run
  return true unless ::File.exist?(passwords_changed_marker)

  # If marker exists but output file doesn't, that's inconsistent - regenerate
  # (This handles failed previous runs or manual deletion of password file)
  return true unless ::File.exist?(output_file)

  # Both marker and output file exist - passwords already changed successfully
  false
}

# Load or generate passwords for users
ruby_block 'load_or_generate_passwords' do
  block do

    node.run_state['wazuh_passwords'] ||= {}
    data_bag_name = node['wazuh_indexer']['passwords']['data_bag_name']
    data_bag_item = node['wazuh_indexer']['passwords']['data_bag_item']
    data_bag_encrypted = node['wazuh_indexer']['passwords']['data_bag_encrypted']

    passwords_from_databag = false

    # Priority 1: Try to load from data bag if configured
    if data_bag_name && data_bag_item
      begin
        Chef::Log.info("Attempting to load passwords from data bag '#{data_bag_name}/#{data_bag_item}'")

        bag_item = if data_bag_encrypted
                     Chef::EncryptedDataBagItem.load(data_bag_name, data_bag_item)
                   else
                     data_bag_item(data_bag_name, data_bag_item)
                   end

        users_to_update.each_key do |user|
          if bag_item[user] && !bag_item[user].empty?
            node.run_state['wazuh_passwords'][user] = bag_item[user]
            Chef::Log.info("Loaded password for user '#{user}' from data bag")
            passwords_from_databag = true
          end
        end

        if passwords_from_databag
          Chef::Log.info("Successfully loaded passwords from data bag")
        else
          Chef::Log.warn("Data bag found but no matching user passwords - will generate")
        end
      rescue Net::HTTPClientException, Chef::Exceptions::InvalidDataBagPath => e
        Chef::Log.warn("Could not load data bag '#{data_bag_name}/#{data_bag_item}': #{e.message}")
        Chef::Log.warn("Falling back to attribute/generated passwords")
      end
    end

    # Priority 2: Use attributes or generate for any users not loaded from data bag
    users_to_update.each do |user, config|
      next if node.run_state['wazuh_passwords'][user] # Already loaded from data bag

      if config['password'] && !config['password'].empty?
        # Use password from attributes
        node.run_state['wazuh_passwords'][user] = config['password']
        Chef::Log.info("Using password from attributes for user: #{user}")
      else
        # Generate a secure random password
        password = SecureRandom.alphanumeric(24)
        node.run_state['wazuh_passwords'][user] = password
        Chef::Log.info("Generated random password for user: #{user}")
      end
    end

    Chef::Log.info("Passwords configured for users: #{node.run_state['wazuh_passwords'].keys.join(', ')}")
  end
  action :run
  only_if { passwords_should_run.call }
end

# Backup current internal_users.yml
execute 'backup_internal_users' do
  command "cp #{config_path}/opensearch-security/internal_users.yml #{config_path}/opensearch-security/internal_users.yml.bak.$(date +%Y%m%d%H%M%S)"
  action :run
  only_if do
    passwords_should_run.call &&
      ::File.exist?("#{config_path}/opensearch-security/internal_users.yml")
  end
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
  only_if { passwords_should_run.call }
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
    passwords_should_run.call &&
      ::File.exist?("#{certs_path}/admin.pem") &&
      ::File.exist?("#{certs_path}/admin-key.pem")
  end
end

# Save passwords to JSON file for other recipes to read
ruby_block 'save_passwords_file' do
  block do
    require 'json'

    data_bag_name = node['wazuh_indexer']['passwords']['data_bag_name']
    data_bag_item = node['wazuh_indexer']['passwords']['data_bag_item']
    source = data_bag_name && data_bag_item ? "data_bag:#{data_bag_name}/#{data_bag_item}" : 'generated'

    passwords_data = {
      'generated_at' => Time.now.to_s,
      'source' => source,
      'passwords' => node.run_state['wazuh_passwords']
    }

    ::File.write(passwords_file, JSON.pretty_generate(passwords_data))
    ::File.chmod(0600, passwords_file)
    Chef::Log.info("Passwords saved to #{passwords_file} (source: #{source})")
  end
  action :run
  only_if { passwords_should_run.call }
end

# Mark passwords as changed
file '/var/lib/wazuh-indexer/.passwords_changed' do
  content "Passwords changed at #{Time.now}\n"
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0644'
  action :create
  only_if { passwords_should_run.call }
end

# Update the admin credentials in node attributes for other recipes to use
ruby_block 'update_admin_credentials' do
  block do
    if node.run_state['wazuh_passwords'] && node.run_state['wazuh_passwords']['admin']
      # Store new admin password in run_state for other recipes
      node.run_state['wazuh_indexer_admin_password'] = node.run_state['wazuh_passwords']['admin']
      Chef::Log.info('Admin password stored in run_state for use by other recipes')
    end
  end
  action :run
  only_if { passwords_should_run.call }
end

log 'password_change_complete' do
  message lazy {
    data_bag_configured = node['wazuh_indexer']['passwords']['data_bag_name'] &&
                          node['wazuh_indexer']['passwords']['data_bag_item']
    source_msg = data_bag_configured ? "Passwords loaded from data bag." : "Passwords were auto-generated."

    <<~MSG
      ============================================================================
      Wazuh Indexer passwords have been changed!

      #{source_msg}
      #{"Passwords saved to: #{passwords_file}" if node['wazuh_indexer']['passwords']['save_to_file']}

      IMPORTANT: Update the following components with the new passwords:
        - Wazuh Dashboard (opensearch connection)
        - Wazuh Manager (indexer keystore)
        - Filebeat (keystore)

      You can use the wazuh_dashboard::passwords and wazuh_manager::passwords
      recipes to update these components automatically.
      ============================================================================
    MSG
  }
  level :info
  only_if { passwords_should_run.call }
end

# =============================================================================
# Wazuh Template Injection
# =============================================================================
# This is done here (after password handling) to ensure we have valid credentials.
# The template is required for Wazuh alerts to be indexed correctly.

wazuh_template_url = "https://raw.githubusercontent.com/wazuh/wazuh/v#{node['wazuh']['patch_version']}/extensions/elasticsearch/7.x/wazuh-template.json"
wazuh_template_path = '/tmp/wazuh-template.json'

# Clean up stale template marker if passwords were changed but file is missing
# This indicates an inconsistent state from a failed/interrupted run
ruby_block 'cleanup_stale_template_marker' do
  block do
    Chef::Log.warn('Detected stale state: template_injected marker exists but passwords file missing')
    Chef::Log.warn('Removing stale template marker to allow re-injection with correct credentials')
    ::File.delete('/var/lib/wazuh-indexer/.template_injected')
  end
  action :run
  only_if do
    ::File.exist?('/var/lib/wazuh-indexer/.template_injected') &&
      ::File.exist?('/var/lib/wazuh-indexer/.passwords_changed') &&
      !::File.exist?(node['wazuh_indexer']['passwords']['output_file'])
  end
end

remote_file wazuh_template_path do
  source wazuh_template_url
  owner 'root'
  group 'root'
  mode '0644'
  action :create
  only_if do
    ::File.exist?('/var/lib/wazuh-indexer/.security_initialized') &&
      !::File.exist?('/var/lib/wazuh-indexer/.template_injected')
  end
end

bash 'inject_wazuh_template' do
  code lazy {
    admin_user = node['wazuh_indexer']['admin_user']
    port = node['wazuh_indexer']['yml']['http']['port']

    # Get valid admin password: run_state > passwords file > default
    admin_pass = node.run_state['wazuh_indexer_admin_password']
    admin_pass ||= node.run_state['wazuh_passwords']['admin'] if node.run_state['wazuh_passwords']

    if admin_pass.nil?
      pf = node['wazuh_indexer']['passwords']['output_file']
      if ::File.exist?(pf)
        require 'json'
        begin
          data = JSON.parse(::File.read(pf))
          admin_pass = data['passwords']['admin'] if data['passwords']
        rescue JSON::ParserError
          # Fall through
        end
      end
    end

    admin_pass ||= node['wazuh_indexer']['admin_password']

    <<-EOH
    # Wait for indexer to be ready with new credentials
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
      http_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u #{admin_user}:#{admin_pass} https://127.0.0.1:#{port}/)
      if [ "$http_code" = "200" ]; then
        break
      fi
      sleep 5
      attempt=$((attempt + 1))
    done

    if [ "$http_code" != "200" ]; then
      echo "Indexer not ready after $max_attempts attempts (last response: $http_code)"
      exit 1
    fi

    # Check if template already exists
    template_exists=$(curl -s -k -u #{admin_user}:#{admin_pass} https://127.0.0.1:#{port}/_cat/templates/wazuh 2>/dev/null | grep -c wazuh || true)

    if [ "$template_exists" = "0" ]; then
      # Inject the template
      response=$(curl -s -k -u #{admin_user}:#{admin_pass} \
        -X PUT "https://127.0.0.1:#{port}/_template/wazuh" \
        -H 'Content-Type: application/json' \
        -d @#{wazuh_template_path} 2>&1)

      if echo "$response" | grep -q '"acknowledged":true'; then
        touch /var/lib/wazuh-indexer/.template_injected
        echo "Wazuh template injected successfully"
      else
        echo "Failed to inject Wazuh template: $response"
        exit 1
      fi
    else
      touch /var/lib/wazuh-indexer/.template_injected
      echo "Wazuh template already exists"
    fi
    EOH
  }
  action :run
  sensitive true
  only_if do
    ::File.exist?('/var/lib/wazuh-indexer/.security_initialized') &&
      !::File.exist?('/var/lib/wazuh-indexer/.template_injected')
  end
end
