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
remote_file "#{node['filebeat']['config_path']}/#{node['filebeat']['alerts_template']}" do
  source "https://raw.githubusercontent.com/wazuh/wazuh/#{node['wazuh']['minor_version']}/extensions/elasticsearch/#{node['elk']['major_version']}/#{node['filebeat']['alerts_template']}"
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
    source_path = nil
    # Check for Wazuh Indexer certs first
    if ::Dir.exist?(node['wazuh_indexer']['certs_path'])
      source_path = node['wazuh_indexer']['certs_path']
    # Fallback to legacy Elasticsearch path
    elsif ::Dir.exist?(node['elastic']['certs_path'])
      source_path = node['elastic']['certs_path']
    end

    if source_path
      # Copy certificates with correct naming convention
      if ::File.exist?("#{source_path}/filebeat.pem")
        IO.copy_stream("#{source_path}/filebeat.pem", "#{node['filebeat']['certs_path']}/filebeat.pem")
      end
      # Handle both old (.key) and new (-key.pem) naming conventions
      if ::File.exist?("#{source_path}/filebeat-key.pem")
        IO.copy_stream("#{source_path}/filebeat-key.pem", "#{node['filebeat']['certs_path']}/filebeat-key.pem")
      elsif ::File.exist?("#{source_path}/filebeat.key")
        IO.copy_stream("#{source_path}/filebeat.key", "#{node['filebeat']['certs_path']}/filebeat-key.pem")
      end
      if ::File.exist?("#{source_path}/root-ca.pem")
        IO.copy_stream("#{source_path}/root-ca.pem", "#{node['filebeat']['certs_path']}/root-ca.pem")
      end
    else
      Chef::Log.warn("Certificate source directory not found. Please copy certificates to #{node['filebeat']['certs_path']}:
        - filebeat.pem
        - filebeat-key.pem
        - root-ca.pem
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
