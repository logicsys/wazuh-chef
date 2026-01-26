# Cookbook:: filebeat-oss
# Recipe:: filebeat-oss
# Author:: Wazuh <info@wazuh.com>

# Install filebeat-oss package

case node['platform']
when 'debian', 'ubuntu'
  apt_package 'filebeat' do
    version "#{node['elk']['patch_version']}"
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'] >= '8'
    dnf_package 'filebeat' do
      version "#{node['elk']['patch_version']}"
    end
  else
    yum_package 'filebeat' do
      version "#{node['elk']['patch_version']}"
    end
  end
when 'opensuseleap', 'suse'
  zypper_package 'filebeat' do
    version "#{node['elk']['patch_version']}"
  end
else
  raise 'Currently platform not supported yet. Feel free to open an issue on https://www.github.com/wazuh/wazuh-chef if you consider that support for a specific OS should be added'
end

# Create Filebeat keystore and store credentials
execute 'create_filebeat_keystore' do
  command 'filebeat keystore create --force'
  action :run
  not_if { ::File.exist?('/var/lib/filebeat/filebeat.keystore') }
end

execute 'store_filebeat_username' do
  command "echo #{node['filebeat']['indexer_username']} | filebeat keystore add username --force --stdin"
  action :run
  sensitive true
end

execute 'store_filebeat_password' do
  command "echo #{node['filebeat']['indexer_password']} | filebeat keystore add password --force --stdin"
  action :run
  sensitive true
end

# Edit the file /etc/filebeat/filebeat.yml
template "#{node['filebeat']['config_path']}/filebeat.yml" do
  source 'filebeat.yml.erb'
  owner 'root'
  group 'root'
  mode '0640'
  variables({
    hosts: node['filebeat']['yml']['output']['elasticsearch']['hosts'],
  })
end

# Download the alerts template for Elasticsearch
# Use the full version tag (v4.14.2) for the GitHub raw URL
remote_file "#{node['filebeat']['config_path']}/#{node['filebeat']['alerts_template']}" do
  source "https://raw.githubusercontent.com/wazuh/wazuh/v#{node['wazuh']['patch_version']}/extensions/elasticsearch/#{node['elk']['major_version']}/#{node['filebeat']['alerts_template']}"
  owner 'root'
  group 'root'
  mode '0644'
end

# Download the Wazuh module for Filebeat
execute 'Extract Wazuh module' do
  command "curl -s https://packages.wazuh.com/#{node['wazuh']['major_version']}/filebeat/#{node['filebeat']['wazuh_module']} | tar -xvz -C #{node['filebeat']['wazuh_module_path']}"
  action :run
  not_if { ::Dir.exist?("#{node['filebeat']['wazuh_module_path']}/wazuh") }
end

# Configure Filebeat certificates directory
directory node['filebeat']['certs_path'] do
  owner 'root'
  group 'root'
  mode '0500'
  action :create
end

ruby_block 'Copy certificate files' do
  block do
    dest_path = node['filebeat']['certs_path']
    certs_copied = false

    # Define possible certificate source paths in order of preference
    # 1. Wazuh Manager certs (for single-node where manager and filebeat are on same host)
    # 2. Wazuh Indexer certs
    # 3. Legacy Elasticsearch path
    source_paths = [
      '/var/ossec/etc/certs',                    # Wazuh Manager certs path
      node['wazuh_indexer']['certs_path'],       # Wazuh Indexer certs path
      node['elastic']['certs_path'],             # Legacy Elasticsearch path
    ]

    # Define possible certificate name patterns
    # The install script may name certs after the server node (e.g., wazuh-server.pem)
    # or use standard names (filebeat.pem)
    hostname = node['hostname']
    cert_patterns = [
      { cert: 'filebeat.pem', key: 'filebeat-key.pem' },
      { cert: "#{hostname}.pem", key: "#{hostname}-key.pem" },
      { cert: 'wazuh-server.pem', key: 'wazuh-server-key.pem' },
      { cert: 'server.pem', key: 'server-key.pem' },
    ]

    source_paths.each do |source_path|
      next unless ::Dir.exist?(source_path)

      Chef::Log.info("Checking certificate source: #{source_path}")

      # Try each certificate naming pattern
      cert_patterns.each do |pattern|
        cert_file = "#{source_path}/#{pattern[:cert]}"
        key_file = "#{source_path}/#{pattern[:key]}"
        root_ca = "#{source_path}/root-ca.pem"

        if ::File.exist?(cert_file) && ::File.exist?(key_file) && ::File.exist?(root_ca)
          Chef::Log.info("Found certificates with pattern: #{pattern[:cert]}")

          # Copy certificates to filebeat certs directory with standard names
          IO.copy_stream(cert_file, "#{dest_path}/filebeat.pem")
          IO.copy_stream(key_file, "#{dest_path}/filebeat-key.pem")
          IO.copy_stream(root_ca, "#{dest_path}/root-ca.pem")

          certs_copied = true
          Chef::Log.info("Certificates copied from #{source_path} to #{dest_path}")
          break
        end
      end

      break if certs_copied

      # Also check for old .key naming convention
      if ::File.exist?("#{source_path}/filebeat.pem") &&
         ::File.exist?("#{source_path}/filebeat.key") &&
         ::File.exist?("#{source_path}/root-ca.pem")
        IO.copy_stream("#{source_path}/filebeat.pem", "#{dest_path}/filebeat.pem")
        IO.copy_stream("#{source_path}/filebeat.key", "#{dest_path}/filebeat-key.pem")
        IO.copy_stream("#{source_path}/root-ca.pem", "#{dest_path}/root-ca.pem")
        certs_copied = true
        Chef::Log.info("Certificates copied from #{source_path} (legacy .key format)")
        break
      end
    end

    unless certs_copied
      Chef::Log.warn("Certificate files not found in any source path. Please copy certificates to #{dest_path}:
        - filebeat.pem (node certificate)
        - filebeat-key.pem (node private key)
        - root-ca.pem (CA certificate)
      Then run: systemctl restart filebeat")
    end
  end
  action :run
end

# Set proper permissions on certificate files
execute 'set_filebeat_cert_permissions' do
  command "chmod 400 #{node['filebeat']['certs_path']}/*.pem 2>/dev/null || true"
  only_if { ::Dir.exist?(node['filebeat']['certs_path']) }
end

# Enable and start service
service 'filebeat' do
  supports start: true, stop: true, restart: true, reload: true
  action [:enable, :start]
  only_if do
    ::File.exist?("#{node['filebeat']['certs_path']}/filebeat.pem") &&
      ::File.exist?("#{node['filebeat']['certs_path']}/filebeat-key.pem") &&
      ::File.exist?("#{node['filebeat']['certs_path']}/root-ca.pem")
  end
end

# Log warning if service not started due to missing certificates
log 'filebeat_cert_warning' do
  message "Filebeat service not started - certificates not found in #{node['filebeat']['certs_path']}"
  level :warn
  not_if do
    ::File.exist?("#{node['filebeat']['certs_path']}/filebeat.pem") &&
      ::File.exist?("#{node['filebeat']['certs_path']}/filebeat-key.pem") &&
      ::File.exist?("#{node['filebeat']['certs_path']}/root-ca.pem")
  end
end
