# Task file for tests
ref_file = 'roles/hardening/tasks/selinux.yaml'

control 'selinux-01' do
  title 'Ensure SELinux python library is installed'
  impact 'medium'
  ref ref_file
  describe package('python3-libselinux') do
    it { should be_installed }
  end
end

control 'selinux-02' do
  title 'Ensure SELinux is enforcing'
  impact 'critical'
  ref ref_file
  describe command('getenforce') do
    its('stdout') { should match 'Enforcing' }
  end
end
