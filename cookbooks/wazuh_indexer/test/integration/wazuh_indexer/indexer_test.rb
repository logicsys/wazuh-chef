# frozen_string_literal: true

# InSpec test for wazuh_indexer cookbook

# =============================================================================
# Package Installation Tests
# =============================================================================
describe package('wazuh-indexer') do
  it { should be_installed }
end

describe user('wazuh-indexer') do
  it { should exist }
end

describe group('wazuh-indexer') do
  it { should exist }
end

# =============================================================================
# Configuration Files Tests
# =============================================================================
describe file('/etc/wazuh-indexer/opensearch.yml') do
  it { should exist }
  its('mode') { should cmp '0660' }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
  # Verify required configuration settings
  its('content') { should match(/path\.data: \/var\/lib\/wazuh-indexer/) }
  its('content') { should match(/path\.logs: \/var\/log\/wazuh-indexer/) }
  its('content') { should match(/node\.max_local_storage_nodes: 3/) }
  its('content') { should match(/cluster\.routing\.allocation\.disk\.threshold_enabled: false/) }
  its('content') { should match(/compatibility\.override_main_response_version: true/) }
end

describe file('/etc/wazuh-indexer/jvm.options') do
  it { should exist }
  its('mode') { should cmp '0660' }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
end

# =============================================================================
# Directory Tests
# =============================================================================
describe directory('/etc/wazuh-indexer/certs') do
  it { should exist }
  its('mode') { should cmp '0500' }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
end

describe directory('/var/lib/wazuh-indexer') do
  it { should exist }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
end

describe directory('/var/log/wazuh-indexer') do
  it { should exist }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
end

# =============================================================================
# Service Tests (certificate-dependent)
# =============================================================================
# NOTE: Service will only be running if certificates are deployed.
# These tests check the service state based on certificate presence.

certs_present = file('/etc/wazuh-indexer/certs/indexer.pem').exist?

describe service('wazuh-indexer') do
  it { should be_installed }
  # Service is enabled regardless of certificates
  it { should be_enabled } if certs_present
end

if certs_present
  describe service('wazuh-indexer') do
    it { should be_running }
  end

  describe port(9200) do
    it { should be_listening }
  end

  describe port(9300) do
    it { should be_listening }
  end

  # Certificate files should exist with proper permissions
  describe file('/etc/wazuh-indexer/certs/indexer.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-indexer' }
  end

  describe file('/etc/wazuh-indexer/certs/indexer-key.pem') do
    it { should exist }
    its('mode') { should cmp '0400' }
    its('owner') { should eq 'wazuh-indexer' }
  end

  describe file('/etc/wazuh-indexer/certs/root-ca.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-indexer' }
  end

  # Security initialization marker
  describe file('/var/lib/wazuh-indexer/.security_initialized') do
    it { should exist }
  end

  # Wazuh template injection marker
  describe file('/var/lib/wazuh-indexer/.template_injected') do
    it { should exist }
  end

  # Test that indexer is responding to API calls
  describe command('curl -s -k -u admin:TestAdminPassword123! https://127.0.0.1:9200/ -o /dev/null -w "%{http_code}"') do
    its('stdout') { should match(/200|401/) }
  end

  # Test that wazuh template exists in indexer
  describe command('curl -s -k -u admin:TestAdminPassword123! https://127.0.0.1:9200/_cat/templates/wazuh') do
    its('stdout') { should match(/wazuh/) }
  end
else
  # When certificates are not present, service should not be running
  describe 'Wazuh Indexer without certificates' do
    it 'service is not running (certificates not deployed)' do
      expect(service('wazuh-indexer').running?).to eq(false)
    end
  end
end
