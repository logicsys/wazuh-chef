# frozen_string_literal: true

# Cookbook:: wazuh_dashboard
# Recipe:: default
# Author:: Wazuh <info@wazuh.com>

include_recipe 'wazuh_dashboard::prerequisites'
include_recipe 'wazuh_dashboard::repository'
include_recipe 'wazuh_dashboard::certificates'
include_recipe 'wazuh_dashboard::dashboard'
