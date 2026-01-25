describe package('wazuh-manager') do
  it { should be_installed }
end

describe service('wazuh-manager') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end

describe port(55000) do
  it { should be_listening }
  its('processes') { should include 'python3' }
end

describe port(1515) do
  it { should be_listening }
  its('processes') { should include 'wazuh-authd' }
end

describe port(1514) do
  it { should be_listening }
  its('processes') { should include 'wazuh-remoted' }
end

# Security test: Verify default admin/admin credentials do not work against Wazuh API
describe command("curl -s -k -u admin:admin -X GET https://127.0.0.1:55000/security/user/authenticate") do
  its('stdout') { should_not match(/"token"/) }
  its('stdout') { should match(/Invalid credentials|Unauthorized|401/) }
end
