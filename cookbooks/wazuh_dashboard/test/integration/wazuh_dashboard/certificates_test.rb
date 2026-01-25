# frozen_string_literal: true

# InSpec test for wazuh_dashboard certificates recipe

# =============================================================================
# Certificate Directory Tests
# =============================================================================
describe directory('/etc/wazuh-dashboard/certs') do
  it { should exist }
  its('mode') { should cmp '0500' }
  its('owner') { should eq 'wazuh-dashboard' }
  its('group') { should eq 'wazuh-dashboard' }
end

# =============================================================================
# Certificate Files Tests (conditional)
# =============================================================================
# These tests only run if certificates have been deployed

dashboard_cert = file('/etc/wazuh-dashboard/certs/dashboard.pem')

if dashboard_cert.exist?
  describe file('/etc/wazuh-dashboard/certs/dashboard.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-dashboard' }
    its('group') { should eq 'wazuh-dashboard' }
    its('content') { should match(/-----BEGIN CERTIFICATE-----/) }
  end

  describe file('/etc/wazuh-dashboard/certs/dashboard-key.pem') do
    it { should exist }
    its('mode') { should cmp '0400' }
    its('owner') { should eq 'wazuh-dashboard' }
    its('group') { should eq 'wazuh-dashboard' }
    its('content') { should match(/-----BEGIN (RSA |EC )?PRIVATE KEY-----/) }
  end

  describe file('/etc/wazuh-dashboard/certs/root-ca.pem') do
    it { should exist }
    its('mode') { should cmp '0440' }
    its('owner') { should eq 'wazuh-dashboard' }
    its('group') { should eq 'wazuh-dashboard' }
    its('content') { should match(/-----BEGIN CERTIFICATE-----/) }
  end
else
  describe 'Certificate deployment status' do
    it 'certificates not deployed - manual deployment required' do
      skip 'Certificates not deployed via cookbook - this is expected if using manual deployment'
    end
  end
end
