# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Recipe:: dashboard
# Author:: Wazuh <info@wazuh.com>

certs_path = node['wazuh_dashboard']['certs_path']

# Install wazuh-dashboard package
case node['platform']
when 'debian', 'ubuntu'
  apt_package 'wazuh-dashboard' do
    version node['wazuh_dashboard']['version'] if node['wazuh_dashboard']['version']
    action :install
  end
when 'redhat', 'centos', 'amazon', 'fedora', 'oracle', 'rocky'
  if node['platform_version'].to_i >= 8
    dnf_package 'wazuh-dashboard' do
      version node['wazuh_dashboard']['version'] if node['wazuh_dashboard']['version']
      action :install
    end
  else
    yum_package 'wazuh-dashboard' do
      version node['wazuh_dashboard']['version'] if node['wazuh_dashboard']['version']
      action :install
    end
  end
when 'opensuseleap', 'suse'
  zypper_package 'wazuh-dashboard' do
    version node['wazuh_dashboard']['version'] if node['wazuh_dashboard']['version']
    action :install
  end
else
  raise "Platform #{node['platform']} not supported. Please open an issue at https://github.com/wazuh/wazuh-chef"
end

# Configure opensearch_dashboards.yml
template "#{node['wazuh_dashboard']['config_path']}/opensearch_dashboards.yml" do
  source 'opensearch_dashboards.yml.erb'
  owner 'wazuh-dashboard'
  group 'wazuh-dashboard'
  mode '0640'
  variables(
    server_host: node['wazuh_dashboard']['yml']['server']['host'],
    server_port: node['wazuh_dashboard']['yml']['server']['port'],
    opensearch_hosts: node['wazuh_dashboard']['yml']['opensearch']['hosts'],
    ssl_enabled: node['wazuh_dashboard']['ssl']['enabled'],
    ssl_certificate: "#{certs_path}/dashboard.pem",
    ssl_key: "#{certs_path}/dashboard-key.pem"
  )
  notifies :restart, 'service[wazuh-dashboard]', :delayed
end

# Create required data directories for Wazuh Dashboard
%w(config downloads logs).each do |subdir|
  directory "#{node['wazuh_dashboard']['package_path']}/data/wazuh/#{subdir}" do
    owner 'wazuh-dashboard'
    group 'wazuh-dashboard'
    mode '0750'
    recursive true
    action :create
  end
end

template "#{node['wazuh_dashboard']['package_path']}/data/wazuh/config/wazuh.yml" do
  source 'wazuh.yml.erb'
  owner 'wazuh-dashboard'
  group 'wazuh-dashboard'
  mode '0640'
  variables(
    api_url: node['wazuh_dashboard']['wazuh_api']['url'],
    api_port: node['wazuh_dashboard']['wazuh_api']['port'],
    api_username: node['wazuh_dashboard']['wazuh_api']['username'],
    api_password: node['wazuh_dashboard']['wazuh_api']['password']
  )
  notifies :restart, 'service[wazuh-dashboard]', :delayed
end

# Allow dashboard to bind to privileged ports (443)
execute 'setcap_dashboard' do
  command "setcap 'cap_net_bind_service=+ep' #{node['wazuh_dashboard']['package_path']}/node/bin/node"
  action :run
  not_if "getcap #{node['wazuh_dashboard']['package_path']}/node/bin/node | grep -q cap_net_bind_service"
end

# Ensure proper ownership of directories
directory node['wazuh_dashboard']['package_path'] do
  owner 'wazuh-dashboard'
  group 'wazuh-dashboard'
  recursive true
  action :create
end

# Set up OpenSearch credentials in keystore before starting dashboard
# This ensures the dashboard can connect to the indexer on first start
ruby_block 'setup_dashboard_credentials_before_start' do
  block do
    require 'json'

    package_path = node['wazuh_dashboard']['package_path']
    keystore_path = "#{package_path}/data/opensearch-dashboards.keystore"

    # Get kibanaserver password from run_state or passwords file
    kibana_password = nil

    if node.run_state['wazuh_passwords'] && node.run_state['wazuh_passwords']['kibanaserver']
      kibana_password = node.run_state['wazuh_passwords']['kibanaserver']
      Chef::Log.info('Using kibanaserver password from run_state')
    else
      passwords_file = node['wazuh_dashboard']['indexer_passwords_file'] || '/root/wazuh-passwords.txt'
      if ::File.exist?(passwords_file)
        begin
          data = JSON.parse(::File.read(passwords_file))
          kibana_password = data['passwords']['kibanaserver'] if data['passwords']
          Chef::Log.info("Using kibanaserver password from #{passwords_file}")
        rescue JSON::ParserError
          Chef::Log.warn('Could not parse passwords file')
        end
      end
    end

    if kibana_password
      # Create keystore if it doesn't exist (use yes to auto-confirm any prompts)
      unless ::File.exist?(keystore_path)
        system("yes | #{package_path}/bin/opensearch-dashboards-keystore create --allow-root")
      end

      # Remove and re-add credentials
      system("#{package_path}/bin/opensearch-dashboards-keystore remove opensearch.username --allow-root 2>/dev/null")
      system("#{package_path}/bin/opensearch-dashboards-keystore remove opensearch.password --allow-root 2>/dev/null")
      system("echo 'kibanaserver' | #{package_path}/bin/opensearch-dashboards-keystore add opensearch.username --stdin --allow-root")
      system("echo '#{kibana_password}' | #{package_path}/bin/opensearch-dashboards-keystore add opensearch.password --stdin --allow-root")

      # Set permissions
      if ::File.exist?(keystore_path)
        ::File.chown(
          Etc.getpwnam('wazuh-dashboard').uid,
          Etc.getgrnam('wazuh-dashboard').gid,
          keystore_path
        )
        ::File.chmod(0600, keystore_path)
      end
      Chef::Log.info('Dashboard keystore configured with kibanaserver credentials')
    else
      Chef::Log.info('No kibanaserver password available - dashboard will use defaults')
    end
  end
  action :run
  only_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end

# Enable and start service (only if certificates are present)
service 'wazuh-dashboard' do
  supports status: true, restart: true, reload: true
  action [:enable, :start]
  only_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end

# Log if service not started due to missing certificates
log 'dashboard_service_not_started' do
  message "Wazuh Dashboard service not started - certificates not found in #{certs_path}"
  level :warn
  not_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end

# Wait for dashboard to be ready using HTTP health check (only if certificates are present)
bash 'wait_for_dashboard_health' do
  code <<-EOH
    max_attempts=30
    attempt=0
    dashboard_host="#{node['wazuh_dashboard']['yml']['server']['host']}"
    dashboard_port="#{node['wazuh_dashboard']['yml']['server']['port']}"

    # Use localhost if bound to 0.0.0.0
    if [ "$dashboard_host" = "0.0.0.0" ]; then
      dashboard_host="127.0.0.1"
    fi

    echo "Waiting for Wazuh Dashboard to be ready at https://$dashboard_host:$dashboard_port/status"

    while [ $attempt -lt $max_attempts ]; do
      http_code=$(curl -s -o /dev/null -w "%{http_code}" -k "https://$dashboard_host:$dashboard_port/status" 2>/dev/null || echo "000")

      if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
        echo "Wazuh Dashboard is ready (HTTP $http_code)"
        exit 0
      fi

      echo "Waiting for dashboard... (attempt $((attempt+1))/$max_attempts, HTTP $http_code)"
      sleep 10
      attempt=$((attempt + 1))
    done

    echo "Wazuh Dashboard failed to become ready after $max_attempts attempts"
    exit 1
  EOH
  action :run
  timeout 600
  only_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end

# Update wazuh.yml with actual API server address after dashboard is ready
# This ensures the dashboard can connect to the Wazuh API
ruby_block 'update_wazuh_yml_api_url' do
  block do
    wazuh_yml_path = "#{node['wazuh_dashboard']['package_path']}/data/wazuh/config/wazuh.yml"

    if ::File.exist?(wazuh_yml_path)
      content = ::File.read(wazuh_yml_path)
      api_url = node['wazuh_dashboard']['wazuh_api']['url']

      # If API URL is localhost/127.0.0.1, try to determine actual server IP
      if api_url.include?('localhost') || api_url.include?('127.0.0.1')
        # For single-node deployments, use the node's IP if available
        actual_ip = node['ipaddress'] || '127.0.0.1'
        new_url = "https://#{actual_ip}"

        content.gsub!(%r{url:\s*https?://(?:localhost|127\.0\.0\.1)}, "url: #{new_url}")
        ::File.write(wazuh_yml_path, content)
        Chef::Log.info("Updated wazuh.yml API URL to #{new_url}")
      end
    end
  end
  action :run
  only_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end

log 'dashboard_access_info' do
  message "Wazuh Dashboard available at https://#{node['wazuh_dashboard']['yml']['server']['host']}:#{node['wazuh_dashboard']['yml']['server']['port']} (default credentials: admin/admin)"
  level :info
  only_if { ::File.exist?("#{certs_path}/dashboard.pem") }
end
