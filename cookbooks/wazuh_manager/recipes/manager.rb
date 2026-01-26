# Cookbook:: wazuh-manager
# Recipe:: manager
# Author:: Wazuh <info@wazuh.com>

case node['platform']
when 'ubuntu', 'debian'
  apt_package 'wazuh-manager' do
    version "#{node['wazuh']['patch_version']}-1"
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'] >= '8'
    dnf_package 'wazuh-manager' do
      version "#{node['wazuh']['patch_version']}-1"
    end
  else
    yum_package 'wazuh-manager' do
      version "#{node['wazuh']['patch_version']}-1"
    end
  end
when 'opensuseleap', 'suse'
  zypper_package 'wazuh-manager' do
    version "#{node['wazuh']['patch_version']}-1"
  end
else
  raise 'Currently platforn not supported yet. Feel free to open an issue on https://www.github.com/wazuh/wazuh-chef if you consider that support for a specific OS should be added'
end

# The dependences should be installed only when the cluster is enabled
# Handle both boolean (true/false) and string ('yes'/'no') values
cluster_enabled = node['ossec']['conf']['cluster']['disabled'] == false ||
                  node['ossec']['conf']['cluster']['disabled'] == 'no'
if cluster_enabled
  case node['platform']
  when 'ubuntu', 'debian'
    log 'Wazuh_Cluster_not_compatible' do
      message "Wazuh cluster is not compatible with this version with #{node['platform']}"
      level :warn
    end
  when 'redhat', 'oracle', 'centos', 'amazon', 'fedora', 'rocky'
    if node['platform_version'].to_i == 7
      package ['python-setuptools', 'python-cryptography']
    end
  else
    raise 'Currently platforn not supported yet. Feel free to open an issue on https://www.github.com/wazuh/wazuh-chef if you consider that support for a specific OS should be added'
  end
end

# Enable Authd for agent registration
# Required for: master nodes in cluster mode, OR single-node deployments (cluster disabled)
# Handle both boolean (true/false) and string ('yes'/'no') values for disabled setting
cluster_disabled_val = node['ossec']['conf']['cluster']['disabled']
cluster_disabled = cluster_disabled_val == true || cluster_disabled_val == 'yes'
is_master = node['ossec']['conf']['cluster']['node_type'] == 'master'

if is_master || cluster_disabled
  execute 'Enable Authd' do
    command '/var/ossec/bin/wazuh-control enable auth'
    not_if 'ps axu | grep wazuh-authd | grep -v grep'
  end
end

# Initialize indexer credentials in wazuh-keystore
# This allows the manager to authenticate to the Wazuh Indexer
execute 'set_indexer_username' do
  command "/var/ossec/bin/wazuh-keystore -f indexer -k username -v #{node['wazuh_manager']['indexer']['username']}"
  action :run
  sensitive true
  not_if '/var/ossec/bin/wazuh-keystore -f indexer -l 2>/dev/null | grep -q username'
end

execute 'set_indexer_password' do
  command "/var/ossec/bin/wazuh-keystore -f indexer -k password -v #{node['wazuh_manager']['indexer']['password']}"
  action :run
  sensitive true
  not_if '/var/ossec/bin/wazuh-keystore -f indexer -l 2>/dev/null | grep -q password'
end

include_recipe 'wazuh_manager::common'

template "#{node['ossec']['dir']}/etc/local_internal_options.conf" do
  source 'var/ossec/etc/manager_local_internal_options.conf'
  owner 'root'
  group node['ossec']['group']
  mode '0640'
end

template "#{node['ossec']['dir']}/etc/rules/local_rules.xml" do
  source 'ossec_local_rules.xml.erb'
  owner 'root'
  group node['ossec']['group']
  mode '0640'
end

template "#{node['ossec']['dir']}/etc/decoders/local_decoder.xml" do
  source 'ossec_local_decoder.xml.erb'
  owner 'root'
  group node['ossec']['group']
  mode '0640'
end

template "#{node['ossec']['dir']}/api/configuration/api.yaml" do
  source 'api.yaml.erb'
  owner 'root'
  group node['ossec']['group']
  mode '0660'
  variables(
    host: "#{node['api']['ip']}",
    port: "#{node['api']['port']}"
  )
end

service 'wazuh' do
  service_name 'wazuh-manager'
  supports :status => true, :restart => true, :reload => true
  action [:enable, :restart]
end
