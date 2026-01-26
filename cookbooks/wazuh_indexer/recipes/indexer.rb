# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: indexer
# Author:: Wazuh <info@wazuh.com>

certs_path = node['wazuh_indexer']['certs_path']

# Calculate JVM heap size dynamically if set to 'auto'
jvm_memory = node['wazuh_indexer']['jvm']['memory']
if jvm_memory == 'auto'
  # Get total system memory in MB
  total_mem_kb = node['memory']['total'].to_i
  total_mem_mb = total_mem_kb / 1024

  # Calculate heap as half of system RAM
  heap_mb = total_mem_mb / 2

  # Apply limits: minimum 1GB, maximum 32GB
  heap_mb = [heap_mb, 1024].max  # At least 1GB
  heap_mb = [heap_mb, 32768].min # At most 32GB

  jvm_memory = "#{heap_mb}m"
  Chef::Log.info("Wazuh Indexer: Auto-calculated JVM heap size: #{jvm_memory} (system RAM: #{total_mem_mb}MB)")
end

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
  variables(memory: jvm_memory)
  notifies :restart, 'service[wazuh-indexer]', :delayed
end

# Set system limits for wazuh-indexer
bash 'configure_limits' do
  code <<-EOH
    grep -q 'wazuh-indexer.*nofile' /etc/security/limits.conf || {
      echo "wazuh-indexer - nofile 65535" >> /etc/security/limits.conf
      echo "wazuh-indexer - memlock unlimited" >> /etc/security/limits.conf
      echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
      echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
    }
  EOH
  not_if 'grep -q "wazuh-indexer.*nofile" /etc/security/limits.conf'
end

# Set vm.max_map_count for OpenSearch (required for proper operation)
sysctl 'vm.max_map_count' do
  value 262144
  action :apply
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

# Initialize security (only on first run with certificates)
execute 'indexer_security_init' do
  command '/usr/share/wazuh-indexer/bin/indexer-security-init.sh'
  action :run
  only_if do
    ::File.exist?("#{certs_path}/indexer.pem") &&
      ::File.exist?("#{certs_path}/admin.pem") &&
      !::File.exist?('/var/lib/wazuh-indexer/.security_initialized')
  end
  notifies :create, 'file[/var/lib/wazuh-indexer/.security_initialized]', :immediately
end

file '/var/lib/wazuh-indexer/.security_initialized' do
  action :nothing
  owner 'wazuh-indexer'
  group 'wazuh-indexer'
  mode '0644'
end

# Download and inject Wazuh template into indexer (required for alerts to be indexed correctly)
wazuh_template_url = "https://raw.githubusercontent.com/wazuh/wazuh/v#{node['wazuh']['patch_version']}/extensions/elasticsearch/7.x/wazuh-template.json"
wazuh_template_path = '/tmp/wazuh-template.json'

remote_file wazuh_template_path do
  source wazuh_template_url
  owner 'root'
  group 'root'
  mode '0644'
  action :create
  not_if { ::File.exist?('/var/lib/wazuh-indexer/.template_injected') }
end

# Inject Wazuh template into indexer after security is initialized
bash 'inject_wazuh_template' do
  code <<-EOH
    # Wait for indexer to be fully ready
    max_attempts=30
    attempt=0
    while [ $attempt -lt $max_attempts ]; do
      http_code=$(curl -s -o /dev/null -w "%{http_code}" -k -u #{node['wazuh_indexer']['admin_user']}:#{node['wazuh_indexer']['admin_password']} https://127.0.0.1:#{node['wazuh_indexer']['yml']['http']['port']}/)
      if [ "$http_code" = "200" ]; then
        break
      fi
      sleep 5
      attempt=$((attempt + 1))
    done

    if [ "$http_code" != "200" ]; then
      echo "Indexer not ready after $max_attempts attempts"
      exit 1
    fi

    # Check if template already exists
    template_exists=$(curl -s -k -u #{node['wazuh_indexer']['admin_user']}:#{node['wazuh_indexer']['admin_password']} https://127.0.0.1:#{node['wazuh_indexer']['yml']['http']['port']}/_cat/templates/wazuh 2>/dev/null | grep -c wazuh || true)

    if [ "$template_exists" = "0" ]; then
      # Inject the template
      curl -s -k -u #{node['wazuh_indexer']['admin_user']}:#{node['wazuh_indexer']['admin_password']} \
        -X PUT "https://127.0.0.1:#{node['wazuh_indexer']['yml']['http']['port']}/_template/wazuh" \
        -H 'Content-Type: application/json' \
        -d @#{wazuh_template_path}

      if [ $? -eq 0 ]; then
        touch /var/lib/wazuh-indexer/.template_injected
        echo "Wazuh template injected successfully"
      else
        echo "Failed to inject Wazuh template"
        exit 1
      fi
    else
      touch /var/lib/wazuh-indexer/.template_injected
      echo "Wazuh template already exists"
    fi
  EOH
  action :run
  sensitive true
  only_if do
    ::File.exist?("#{certs_path}/indexer.pem") &&
      ::File.exist?('/var/lib/wazuh-indexer/.security_initialized') &&
      !::File.exist?('/var/lib/wazuh-indexer/.template_injected')
  end
end
