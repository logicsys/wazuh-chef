# frozen_string_literal: true

# Cookbook:: elastic-stack
# Recipe:: default
# Author:: Wazuh <info@wazuh.com>

include_recipe 'elastic-stack::prerequisites'
include_recipe 'elastic-stack::repository'
include_recipe 'elastic-stack::elasticsearch'
include_recipe 'elastic-stack::kibana'
