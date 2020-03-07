# Task file for tests
ref_file = 'roles/hardening/tasks/audit.yaml'

control 'audit-01' do
  title 'Ensure audit logs are written in raw format'
  impact 'low'
  ref ref_file
  describe auditd_conf do
    its('log_format') { should cmp 'raw' }
  end
end

control 'audit-02' do
  title 'Ensure audit logs are not automatically deleted'
  impact 'low'
  ref ref_file
  describe auditd_conf do
    its('max_log_file_action') { should cmp 'keep_logs' }
  end
end
