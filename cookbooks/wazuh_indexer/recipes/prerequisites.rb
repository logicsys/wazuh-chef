# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: prerequisites
# Author:: Wazuh <info@wazuh.com>

# Create wazuh-indexer group and user if they don't exist
# (Package installation will also create them, but we need them earlier for certificates)
group 'wazuh-indexer' do
  system true
  action :create
  not_if 'getent group wazuh-indexer'
end

user 'wazuh-indexer' do
  system true
  gid 'wazuh-indexer'
  home '/var/lib/wazuh-indexer'
  shell '/sbin/nologin'
  action :create
  not_if 'getent passwd wazuh-indexer'
end

case node['platform']
when 'debian', 'ubuntu'
  apt_package %w(gnupg apt-transport-https curl) do
    action :install
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'].to_i >= 8
    dnf_package %w(curl libcap) do
      action :install
    end
  else
    yum_package %w(curl libcap) do
      action :install
    end
  end
when 'opensuseleap', 'suse'
  zypper_package %w(curl libcap2) do
    action :install
  end
else
  raise "Platform #{node['platform']} not supported. Please open an issue at https://github.com/wazuh/wazuh-chef"
end
