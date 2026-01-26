describe package('filebeat') do
  it { should be_installed }
end

describe file('/etc/filebeat/filebeat.yml') do
  its('owner') { should cmp 'root' }
  its('group') { should cmp 'root' }
  its('mode') { should cmp '0640' }
  its('content') { should match(/output\.elasticsearch/) }
  its('content') { should match(/protocol: https/) }
  # Verify seccomp configuration is present (required for newer kernels)
  its('content') { should match(/seccomp:/) }
  its('content') { should match(/- rseq/) }
end

describe file('/etc/filebeat/wazuh-template.json') do
  its('owner') { should cmp 'root' }
  its('group') { should cmp 'root' }
  its('mode') { should cmp '0644' }
end

describe directory('/usr/share/filebeat/module/wazuh') do
  it { should exist }
end

describe directory('/etc/filebeat/certs') do
  it { should exist }
  its('mode') { should cmp '0500' }
end

# Certificate files
describe file('/etc/filebeat/certs/filebeat.pem') do
  it { should exist }
end

describe file('/etc/filebeat/certs/filebeat-key.pem') do
  it { should exist }
end

describe file('/etc/filebeat/certs/root-ca.pem') do
  it { should exist }
end

# Filebeat keystore should exist
describe file('/var/lib/filebeat/filebeat.keystore') do
  it { should exist }
end

describe service('filebeat') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end
