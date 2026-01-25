# frozen_string_literal: true

# Cookbook:: opendistro
# Recipe:: prerequisites
# Author:: Wazuh <info@wazuh.com>

package %w(curl unzip wget) do
  action :install
end

case node['platform']
when 'debian', 'ubuntu'
  package 'lsb-release'

  ohai 'reload lsb' do
    plugin 'lsb'
    subscribes :reload, 'package[lsb-release]', :immediately
  end

  # Install apt prerequisites
  apt_package %w[apt-transport-https software-properties-common libcap2-bin]

  # Add the repository for Java Development Kit (JDK)
  # Note: Debian 11+ and Ubuntu 20.04+ have openjdk-11 in main repos
  case node['platform']
  when 'debian'
    # Only add backports for older Debian versions (< 11)
    if node['platform_version'].to_i < 11
      bash 'add backports.list' do
        code <<-EOH
            echo 'deb http://deb.debian.org/debian #{node['lsb']['codename']}-backports main' > /etc/apt/sources.list.d/backports.list
        EOH
      end
    end
  when 'ubuntu'
    execute 'add apt repository' do
      command 'add-apt-repository ppa:openjdk-r/ppa'
      not_if { node['platform_version'].to_f >= 20.04 }
    end
  end

  # Update repository data
  apt_update

  # Install all the required utilities
  execute 'export JAVA_HOME' do
    command  'export JAVA_HOME=/usr/'
  end

  apt_package 'openjdk-11-jdk'
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  # Install all the necessary packages for the installation
  execute 'export JAVA_HOME' do
    command  'export JAVA_HOME=/usr/'
  end

  if node['platform_version'] >= '8'
    dnf_package 'Install prerequisites packages' do
      package_name %w[java-11-openjdk libcap]
      action :install
    end
  else
    yum_package 'Install prerequisites packages' do
      package_name %w[java-11-openjdk libcap]
      action :install
    end
  end
when 'opensuseleap', 'suse'
  # Install zypper prerequisites
  zypper_package 'Install prerequisites packages' do
    package_name %w[libcap2 java-11-openjdk]
  end
else
  raise 'Currently platforn not supported yet. Feel free to open an issue on https://www.github.com/wazuh/wazuh-chef if you consider that support for a specific OS should be added'
end
