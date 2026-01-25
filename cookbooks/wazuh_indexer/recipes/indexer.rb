# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: indexer
# Author:: Wazuh <info@wazuh.com>

certs_path = node['wazuh_indexer']['certs_path']

# Install wazuh-indexer package
case node['platform']
when 'debian', 'ubuntu'
  apt_package 'wazuh-indexer' do
    version node['wazuh_indexer']['version'] if node['wazuh_indexer']['version']
    action :install
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'].to_i >= 8
    dnf_package 'wazuh-indexer' do
      version node['wazuh_indexer']['version'] if node['wazuh_indexer']['version']
      action :install
    end
  else
    yum_package 'wazuh-indexer' do
      version node['wazuh_indexer']['version'] if node['wazuh_indexer']['version']
      action :install
    end
  end
when 'opensuseleap', 'suse'
  zypper_package 'wazuh-indexer' do
    version node['wazuh_indexer']['version'] if node['wazuh_indexer']['version']
    action :install
  end
else
  raise "Platform #{node['platform']} not supported. Please open an issue at https://github.com/wazuh/wazuh-chef"
end

# Configure opensearch.yml
template "#{node['wazuh_indexer']['config_path']}/opensearch.yml" do
  source 'opensearch.yml.erb'
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0660'
  variables(
    network_host: node['wazuh_indexer']['yml']['network']['host'],
    http_port: node['wazuh_indexer']['yml']['http']['port'],
    transport_port: node['wazuh_indexer']['yml']['transport']['port'],
    node_name: node['wazuh_indexer']['yml']['node']['name'],
    cluster_name: node['wazuh_indexer']['yml']['cluster']['name'],
    initial_master_nodes: node['wazuh_indexer']['yml']['cluster']['initial_master_nodes'],
    seed_hosts: node['wazuh_indexer']['yml']['discovery']['seed_hosts'],
    single_node: node['wazuh_indexer']['single_node'],
    admin_dn: node['wazuh_indexer']['security']['admin_dn'],
    nodes_dn: node['wazuh_indexer']['security']['nodes_dn']
  )
  notifies :restart, 'service[wazuh-indexer]', :delayed
end

# Configure JVM options
template "#{node['wazuh_indexer']['config_path']}/jvm.options" do
  source 'jvm.options.erb'
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0660'
  variables(memory: node['wazuh_indexer']['jvm']['memory'])
  notifies :restart, 'service[wazuh-indexer]', :delayed
end

# Set system limits for wazuh-indexer
bash 'configure_limits' do
  code <<-EOH
    grep -q 'wazuh-indexer' /etc/security/limits.conf || {
      echo "wazuh-indexer - nofile 65535" >> /etc/security/limits.conf
      echo "wazuh-indexer - memlock unlimited" >> /etc/security/limits.conf
    }
  EOH
  not_if 'grep -q wazuh-indexer /etc/security/limits.conf'
end

# Ensure proper ownership of directories
%w(/etc/wazuh-indexer /var/lib/wazuh-indexer /var/log/wazuh-indexer).each do |dir|
  directory dir do
    owner 'wazuh-indexer'
    group 'wazuh-indexer'
    recursive true
    action :create
  end
end

# Enable and start service (only if certificates are present)
service 'wazuh-indexer' do
  supports status: true, restart: true, reload: true
  action [:enable, :start]
  only_if { ::File.exist?("#{certs_path}/indexer.pem") }
end

# Log if service not started due to missing certificates
log 'service_not_started' do
  message "Wazuh Indexer service not started - certificates not found in #{certs_path}"
  level :warn
  not_if { ::File.exist?("#{certs_path}/indexer.pem") }
end

# Wait for indexer to be ready (only if certificates are present)
ruby_block 'wait_for_indexer' do
  block do
    require 'socket'
    max_attempts = 30
    attempts = 0
    loop do
      begin
        TCPSocket.open(
          node['wazuh_indexer']['yml']['network']['host'] == '0.0.0.0' ? '127.0.0.1' : node['wazuh_indexer']['yml']['network']['host'],
          node['wazuh_indexer']['yml']['http']['port']
        )
        break
      rescue StandardError
        attempts += 1
        raise 'Wazuh Indexer failed to start' if attempts >= max_attempts

        Chef::Log.info('Waiting for Wazuh Indexer to start...')
        sleep 5
      end
    end
  end
  action :run
  only_if { ::File.exist?("#{certs_path}/indexer.pem") }
end

# Convert any PKCS#1 keys to PKCS#8 format before security init
# This handles cases where certificates were manually deployed (not via certificates recipe)
# OpenSearch security plugin requires keys in PKCS#8 format (-----BEGIN PRIVATE KEY-----)
%w[indexer-key.pem admin-key.pem].each do |key_file|
  key_path = "#{certs_path}/#{key_file}"

  ruby_block "ensure_#{key_file}_pkcs8_format" do
    block do
      if ::File.exist?(key_path)
        key_content = ::File.read(key_path)

        # Check if key is in PKCS#1 (RSA) or EC format (not PKCS#8)
        if key_content.include?('-----BEGIN RSA PRIVATE KEY-----') ||
           key_content.include?('-----BEGIN EC PRIVATE KEY-----') ||
           key_content.include?('-----BEGIN DSA PRIVATE KEY-----')

          Chef::Log.info("Converting #{key_file} from PKCS#1/EC format to PKCS#8 format")

          # Backup original key with restrictive permissions
          backup_path = "#{key_path}.pkcs1.bak"
          unless ::File.exist?(backup_path)
            ::File.write(backup_path, key_content)
            ::FileUtils.chown('wazuh-indexer', 'wazuh-indexer', backup_path)
            ::File.chmod(0o400, backup_path)
          end

          # Convert to PKCS#8 using openssl
          require 'mixlib/shellout'
          convert_cmd = Mixlib::ShellOut.new(
            "openssl pkcs8 -topk8 -inform PEM -outform PEM -in #{key_path} -out #{key_path}.tmp -nocrypt"
          )
          convert_cmd.run_command

          if convert_cmd.exitstatus == 0
            ::File.rename("#{key_path}.tmp", key_path)
            ::FileUtils.chown('wazuh-indexer', 'wazuh-indexer', key_path)
            ::File.chmod(0o400, key_path)
            Chef::Log.info("Successfully converted #{key_file} to PKCS#8 format")
          else
            Chef::Log.warn("Failed to convert #{key_file}: #{convert_cmd.stderr}")
            ::File.delete("#{key_path}.tmp") if ::File.exist?("#{key_path}.tmp")
          end
        end
      end
    end
    action :run
    only_if {
      ::File.exist?(key_path) &&
        !::File.exist?('/var/lib/wazuh-indexer/.security_initialized')
    }
  end
end

# Initialize security (only on first run with certificates)
execute 'indexer_security_init' do
  command '/usr/share/wazuh-indexer/bin/indexer-security-init.sh'
  action :run
  only_if {
    ::File.exist?("#{certs_path}/indexer.pem") &&
      ::File.exist?("#{certs_path}/admin.pem") &&
      !::File.exist?('/var/lib/wazuh-indexer/.security_initialized')
  }
  notifies :create, 'file[/var/lib/wazuh-indexer/.security_initialized]', :immediately
end

file '/var/lib/wazuh-indexer/.security_initialized' do
  action :nothing
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0644'
end
