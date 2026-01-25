# frozen_string_literal: true

# InSpec test for wazuh_dashboard repository recipe

case os.family
when 'debian'
  describe file('/etc/apt/sources.list.d/wazuh.list') do
    it { should exist }
    its('content') { should match(/packages\.wazuh\.com/) }
  end

  describe file('/usr/share/keyrings/wazuh.gpg') do
    it { should exist }
  end
when 'redhat', 'fedora'
  describe yum.repo('wazuh') do
    it { should exist }
    it { should be_enabled }
  end

  describe file('/etc/yum.repos.d/wazuh.repo') do
    it { should exist }
    its('content') { should match(/packages\.wazuh\.com/) }
  end
when 'suse'
  describe file('/etc/zypp/repos.d/wazuh.repo') do
    it { should exist }
  end
end
