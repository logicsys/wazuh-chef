# frozen_string_literal: true

# InSpec test for wazuh_dashboard cookbook

# =============================================================================
# Package Installation Tests
# =============================================================================
describe package('wazuh-dashboard') do
  it { should be_installed }
end

describe user('wazuh-dashboard') do
  it { should exist }
end

describe group('wazuh-dashboard') do
  it { should exist }
end

# =============================================================================
# Configuration Files Tests
# =============================================================================
describe file('/etc/wazuh-dashboard/opensearch_dashboards.yml') do
  it { should exist }
  its('mode') { should cmp '0640' }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

describe file('/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml') do
  it { should exist }
  its('mode') { should cmp '0640' }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

# =============================================================================
# Directory Tests
# =============================================================================
describe directory('/etc/wazuh-dashboard/certs') do
  it { should exist }
  its('mode') { should cmp '0500' }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

describe directory('/usr/share/wazuh-dashboard') do
  it { should exist }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

describe directory('/usr/share/wazuh-dashboard/data/wazuh/config') do
  it { should exist }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

# =============================================================================
# Capability Tests
# =============================================================================
# Check that node binary has cap_net_bind_service capability for port 443
describe command('getcap /usr/share/wazuh-dashboard/node/bin/node') do
  its('stdout') { should match(/cap_net_bind_service/) }
end

# =============================================================================
# Service Tests (certificate-dependent)
# =============================================================================
# NOTE: Service will only be running if certificates are deployed.
# These tests check the service state based on certificate presence.

certs_present = file('/etc/wazuh-dashboard/certs/dashboard.pem').exist?

describe service('wazuh-dashboard') do
  it { should be_installed }
  # Service is enabled regardless of certificates
  it { should be_enabled } if certs_present
end

if certs_present
  describe service('wazuh-dashboard') do
    it { should be_running }
  end

  describe port(443) do
    it { should be_listening }
  end

  # Certificate files should exist with proper permissions
  describe file('/etc/wazuh-dashboard/certs/dashboard.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-dashboard' }
  end

  describe file('/etc/wazuh-dashboard/certs/dashboard-key.pem') do
    it { should exist }
    its('mode') { should cmp '0400' }
    its('owner') { should eq 'wazuh-dashboard' }
  end

  describe file('/etc/wazuh-dashboard/certs/root-ca.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-dashboard' }
  end
else
  # When certificates are not present, service should not be running
  describe 'Wazuh Dashboard without certificates' do
    it 'service is not running (certificates not deployed)' do
      expect(service('wazuh-dashboard').running?).to eq(false)
    end
  end
end
