# Task file for tests
ref_file = 'tasks/fail2ban.yml'

control 'fail2ban-01' do
  title 'Ensure Fail2Ban is installed'
  impact 'high'
  ref ref_file
  pkgs = %w[fail2ban fail2ban-systemd fail2ban-firewalld]
  pkgs.each do |pkg|
    describe package(pkg) do
      it { should be_installed }
    end
  end
end

control 'fail2ban-02' do
  title 'Configure default jails'
  impact 'high'
  ref ref_file
  describe file('/etc/fail2ban/jail.d/10-shl.conf') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
    its('selinux_label') { should eq 'system_u:object_r:etc_t:s0' }
  end
  describe command('fail2ban-client status') do
    its('stdout') { should match(/sshd/) }
  end
end

control 'fail2ban-03' do
  title 'Ensure Fail2Ban is running'
  impact 'high'
  ref ref_file
  describe systemd_service('fail2ban') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
  describe file('/var/run/fail2ban/fail2ban.sock') do
    it { should exist }
    its('type') { should eq :socket }
  end
  describe command('fail2ban-client status') do
    its('exit_status') { should eq 0 }
  end
end
