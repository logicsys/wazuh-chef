# frozen_string_literal: true

# DEPRECATED: This cookbook is deprecated as of Wazuh 4.6.0
# OpenDistro for Elasticsearch has been sunset by Amazon.
# Wazuh now uses its own Wazuh Indexer and Wazuh Dashboard. Please use:
#   - wazuh_indexer cookbook (for Wazuh Indexer)
#   - wazuh_dashboard cookbook (for Wazuh Dashboard)
# See: https://documentation.wazuh.com/current/release-notes/release-4-6-0.html

name 'opendistro'
maintainer 'Wazuh'
maintainer_email 'info@wazuh.com'
license 'All rights reserved'
description 'DEPRECATED - Install/Configures opendistro (use wazuh_indexer and wazuh_dashboard instead)'
deprecated true
version '0.1.0'
chef_version '>= 15.0'

%w[redhat centos oracle].each do |el|
  supports el, '>= 6.0'
end
supports 'rocky', '>= 8.0'
supports 'amazon', '>= 1.0'
supports 'fedora', '>= 22.0'
supports 'debian', '>= 7.0'
supports 'ubuntu', '>= 12.04'
supports 'suse', '>= 12.0'
supports 'opensuse', '>= 42.0'

issues_url 'https://github.com/wazuh/wazuh-chef/issues'
source_url 'https://github.com/wazuh/wazuh-chef'
