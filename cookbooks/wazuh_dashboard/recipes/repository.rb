# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Recipe:: repository
# Author:: Wazuh <info@wazuh.com>

case node['platform']
when 'debian', 'ubuntu'
  execute 'import_wazuh_gpg_key' do
    command 'curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg'
    not_if { ::File.exist?('/usr/share/keyrings/wazuh.gpg') }
  end

  file '/etc/apt/sources.list.d/wazuh.list' do
    content "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/#{node['wazuh']['major_version']}/apt/ stable main\n"
    mode '0644'
    notifies :update, 'apt_update[wazuh]', :immediately
  end

  apt_update 'wazuh' do
    action :nothing
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  yum_repository 'wazuh' do
    description 'Wazuh repository'
    baseurl "https://packages.wazuh.com/#{node['wazuh']['major_version']}/yum/"
    gpgkey 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
    gpgcheck true
    enabled true
    make_cache true
    if node['platform_version'].to_i >= 9
      options({ 'priority' => '1' })
    else
      options({ 'protect' => '1' })
    end
    action :create
  end
when 'opensuseleap', 'suse'
  zypper_repository 'wazuh' do
    description 'Wazuh repository'
    baseurl "https://packages.wazuh.com/#{node['wazuh']['major_version']}/yum/"
    gpgkey 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
    gpgcheck true
    enabled true
    action :create
  end
else
  raise "Platform #{node['platform']} not supported. Please open an issue at https://github.com/wazuh/wazuh-chef"
end
