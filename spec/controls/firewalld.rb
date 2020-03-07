# Task file for tests
ref_file = 'roles/hardening/tasks/firewalld.yaml'

control 'firewalld-01' do
  title 'Ensure FirewallD is installed'
  impact 'critical'
  ref ref_file
  pkgs = %w[firewalld python3-firewall]
  pkgs.each do |pkg|
    describe package(pkg) do
      it { should be_installed }
    end
  end
end

control 'firewalld-02' do
  title 'Ensure FirewallD is running'
  impact 'critical'
  ref ref_file
  describe systemd_service('firewalld') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'firewalld-05' do
  title 'Ensure services directory exists'
  impact 'medium'
  ref ref_file
  describe file('/etc/firewalld/services') do
    it { should exist }
    its('type') { should eq :directory }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0750' }
    its('selinux_label') { should eq 'system_u:object_r:firewalld_etc_rw_t:s0' }
  end
end

control 'firewalld-04' do
  title 'Map RFC1918 addresses to the internal zone'
  impact 'medium'
  ref ref_file
  describe firewalld.where { zone == 'internal' } do
    its('sources') { should include ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] }
  end
end

control 'firewalld-05' do
  title 'Ensure SSH is available for the public zone'
  impact 'medium'
  ref ref_file
  describe firewalld do
    it { should have_service_enabled_in_zone('ssh', 'public') }
  end
end

control 'firewalld-06' do
  title 'Ensure mDNS is not available for the public zone'
  impact 'medium'
  ref ref_file
  describe firewalld do
    it { should_not have_service_enabled_in_zone('mdns', 'public') }
  end
end
