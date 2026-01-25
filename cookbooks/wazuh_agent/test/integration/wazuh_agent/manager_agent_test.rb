# Check agent service is running
describe service('wazuh-agent') do
  it { should be_installed }
  it { should be_enabled }
  it { should be_running }
end

# Check agent successfully connected to manager (log message 4102)
describe command("grep '(4102): Connected to the server (\\[#{input('manager_ip')}\\]:#{input('manager_port')}/#{input('protocol')})' /var/ossec/logs/ossec.log") do
  its('exit_status') { should eq 0 }
end

