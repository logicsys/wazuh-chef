source 'https://supermarket.chef.io'

metadata

group 'cookbooks' do
  # Test fixtures
  cookbook 'test_certs', path: 'test/fixtures/cookbooks/test_certs'
  cookbook 'test_firewall', path: 'test/fixtures/cookbooks/test_firewall'

  # Current/Active cookbooks
  cookbook 'wazuh_indexer', path: 'cookbooks/wazuh_indexer'
  cookbook 'wazuh_dashboard', path: 'cookbooks/wazuh_dashboard'
  cookbook 'wazuh_agent', path: 'cookbooks/wazuh_agent'
  cookbook 'wazuh_manager', path: 'cookbooks/wazuh_manager'

  # Deprecated cookbooks (kept for backwards compatibility)
  # These are deprecated as of Wazuh 4.6.0 - use wazuh_indexer and wazuh_dashboard instead
  cookbook 'elastic-stack', path: 'cookbooks/elastic-stack'
  cookbook 'opendistro', path: 'cookbooks/opendistro'
  cookbook 'filebeat', path: 'cookbooks/filebeat'
  cookbook 'filebeat-oss', path: 'cookbooks/filebeat-oss'
end
