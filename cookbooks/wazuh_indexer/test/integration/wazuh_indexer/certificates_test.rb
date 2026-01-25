# frozen_string_literal: true

# InSpec test for wazuh_indexer certificates recipe

# =============================================================================
# Certificate Directory Tests
# =============================================================================
describe directory('/etc/wazuh-indexer/certs') do
  it { should exist }
  its('mode') { should cmp '0500' }
  its('owner') { should eq 'wazuh-indexer' }
  its('group') { should eq 'wazuh-indexer' }
end

# =============================================================================
# Certificate Files Tests (conditional)
# =============================================================================
# These tests only run if certificates have been deployed

indexer_cert = file('/etc/wazuh-indexer/certs/indexer.pem')

if indexer_cert.exist?
  describe file('/etc/wazuh-indexer/certs/indexer.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-indexer' }
    its('group') { should eq 'wazuh-indexer' }
    its('content') { should match(/-----BEGIN CERTIFICATE-----/) }
  end

  describe file('/etc/wazuh-indexer/certs/indexer-key.pem') do
    it { should exist }
    its('mode') { should cmp '0400' }
    its('owner') { should eq 'wazuh-indexer' }
    its('group') { should eq 'wazuh-indexer' }
    its('content') { should match(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/) }
  end

  describe file('/etc/wazuh-indexer/certs/root-ca.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-indexer' }
    its('group') { should eq 'wazuh-indexer' }
    its('content') { should match(/-----BEGIN CERTIFICATE-----/) }
  end

  describe file('/etc/wazuh-indexer/certs/admin.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-indexer' }
    its('group') { should eq 'wazuh-indexer' }
    its('content') { should match(/-----BEGIN CERTIFICATE-----/) }
  end

  describe file('/etc/wazuh-indexer/certs/admin-key.pem') do
    it { should exist }
    its('mode') { should cmp '0400' }
    its('owner') { should eq 'wazuh-indexer' }
    its('group') { should eq 'wazuh-indexer' }
    its('content') { should match(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/) }
  end
else
  describe 'Certificate deployment status' do
    it 'certificates not deployed - manual deployment required' do
      skip 'Certificates not deployed via cookbook - this is expected if using manual deployment'
    end
  end
end
