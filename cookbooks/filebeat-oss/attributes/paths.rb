# Cookbook:: filebeat-oss
# Attribute:: paths
# Author:: Wazuh <info@wazuh.com>

default['filebeat']['config_path'] = '/etc/filebeat'
default['filebeat']['wazuh_module_path'] = '/usr/share/filebeat/module'
default['filebeat']['certs_path'] = "#{node['filebeat']['config_path']}/certs"
# Source path for certificates (from Wazuh Indexer)
default['wazuh_indexer']['config_path'] = '/etc/wazuh-indexer'
default['wazuh_indexer']['certs_path'] = "#{node['wazuh_indexer']['config_path']}/certs"

# Legacy elastic paths (kept for backwards compatibility)
default['elastic']['config_path'] = '/etc/elasticsearch'
default['elastic']['certs_path'] = "#{node['elastic']['config_path']}/certs"
