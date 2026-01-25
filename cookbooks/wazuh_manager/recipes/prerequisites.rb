# Cookbook:: wazuh-manager
# Recipe:: prerequisites
# Author:: Wazuh <info@wazuh.com>

# Install all the required utilities

case node['platform']
when 'debian', 'ubuntu'
  package 'lsb-release'

  ohai 'reload lsb' do
    plugin 'lsb'
    subscribes :reload, 'package[lsb-release]', :immediately
  end

  apt_package %w(curl apt-transport-https lsb-release gnupg2)
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'] >= '8'
    dnf_package 'curl'
  else
    yum_package 'curl'
  end
when 'opensuseleap', 'suse'
  zypper_package 'curl'
else
  raise 'Currently platforn not supported yet. Feel free to open an issue on https://www.github.com/wazuh/wazuh-chef if you consider that support for a specific OS should be added'
end

# Configure firewall for Wazuh Manager ports
wazuh_ports = %w(1514/tcp 1515/tcp 1516/tcp 55000/tcp)

case node['platform']
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  # Use firewalld on RHEL-based systems
  wazuh_ports.each do |port|
    execute "firewall_open_#{port.gsub('/', '_')}" do
      command "firewall-cmd --add-port=#{port} --permanent"
      not_if "firewall-cmd --list-ports | grep -q '#{port}'"
      only_if 'systemctl is-active firewalld'
      notifies :run, 'execute[firewall_reload]', :delayed
    end
  end

  execute 'firewall_reload' do
    command 'firewall-cmd --reload'
    action :nothing
  end
when 'debian', 'ubuntu'
  # Use ufw on Debian-based systems if active
  wazuh_ports.each do |port|
    execute "ufw_open_#{port.gsub('/', '_')}" do
      command "ufw allow #{port}"
      not_if "ufw status | grep -q '#{port.split('/')[0]}.*ALLOW'"
      only_if 'ufw status | grep -q "Status: active"'
    end
  end
end
