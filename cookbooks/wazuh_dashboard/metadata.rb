# frozen_string_literal: true

name 'wazuh_dashboard'
maintainer 'Wazuh'
maintainer_email 'info@wazuh.com'
license 'Apache-2.0'
description 'Installs/Configures Wazuh Dashboard (OpenSearch Dashboards-based)'
version '0.1.0'
chef_version '>= 15.0'

%w(redhat centos oracle).each do |el|
  supports el, '>= 7.0'
end
supports 'rocky', '>= 8.0'
supports 'amazon', '>= 2.0'
supports 'fedora', '>= 31.0'
supports 'debian', '>= 10.0'
supports 'ubuntu', '>= 18.04'

issues_url 'https://github.com/wazuh/wazuh-chef/issues'
source_url 'https://github.com/wazuh/wazuh-chef'
