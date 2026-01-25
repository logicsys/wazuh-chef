# frozen_string_literal: true

# Cookbook:: wazuh_indexer
# Recipe:: default
# Author:: Wazuh <info@wazuh.com>

include_recipe 'wazuh_indexer::prerequisites'
include_recipe 'wazuh_indexer::repository'
include_recipe 'wazuh_indexer::certificates'
include_recipe 'wazuh_indexer::indexer'
