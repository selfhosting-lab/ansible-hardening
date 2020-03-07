# Task file for tests
ref_file = 'roles/hardening/tasks/tweaks.yaml'

control 'tweaks-01' do
  title 'Ensure SHA512 is used to hash passwords'
  impact 'low'
  ref ref_file
  describe login_defs do
    its('ENCRYPT_METHOD') { should eq 'SHA512' }
  end
end

control 'tweaks-02' do
  title 'Ensure timeout is set for logins'
  impact 'low'
  ref ref_file
  describe login_defs do
    its('LOGIN_TIMEOUT') { should eq '60' }
  end
end

control 'tweaks-03' do
  title 'Disable setuid on ssh-keysign'
  impact 'low'
  ref ref_file
  describe file('/usr/libexec/openssh/ssh-keysign') do
    its('owner') { should eq 'root' }
    its('group') { should eq 'ssh_keys' }
    its('mode') { should cmp '00555' }
    it { should_not be_setuid }
    it { should_not be_setgid }
  end
end
