# Task file for tests
ref_file = 'roles/hardening/tasks/umasks.yaml'

control 'umasks-01' do
  title 'Ensure insecure umasks are not used in profiles'
  impact 'low'
  ref ref_file
  profiles = %w[/etc/profile /etc/bashrc /etc/csh.cshrc /etc/init.d/functions]
  profiles.each do |profile|
    describe file(profile) do
      its('content') { should_not match(/^ *umask +(?!027).*$/) }
    end
  end
end

control 'umasks-02' do
  title 'Ensure default umask for logins is set appropriately'
  impact 'low'
  ref ref_file
  describe login_defs do
    its('UMASK') { should eq '027' }
  end
end
