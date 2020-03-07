# Task file for tests
ref_file = 'roles/hardening/tasks/ssh.yaml'

ssh_ciphers = [
  'chacha20-poly1305@openssh.com',
  'aes256-gcm@openssh.com',
  'aes128-gcm@openssh.com',
  'aes256-ctr,aes192-ctr,aes128-ctr'
]

ssh_macs = [
  'hmac-sha2-512-etm@openssh.com',
  'hmac-sha2-256-etm@openssh.com',
  'umac-128-etm@openssh.com',
  'hmac-sha2-512',
  'hmac-sha2-256'
]

ssh_kex = [
  'curve25519-sha256@libssh.org',
  'diffie-hellman-group-exchange-sha256'
]

ssh_host_keys = [
  '/etc/ssh/ssh_host_rsa_key',
  '/etc/ssh/ssh_host_ecdsa_key',
  '/etc/ssh/ssh_host_ed25519_key'
]

control 'ssh-01' do
  title 'Ensure SSHD configuration is set appropriately'
  impact 'high'
  ref ref_file
  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0600' }
    its('selinux_label') { should eq 'system_u:object_r:etc_t:s0' }
  end
  describe sshd_config do
    its('Port') { should eq '22' }
    its('ListenAddress') { should eq '0.0.0.0' }
    its('AddressFamily') { should eq 'inet' }
    its('TCPKeepAlive') { should eq 'no' }
    its('ClientAliveInterval') { should eq '300' }
    its('ClientAliveCountMax') { should eq '3' }
    its('MaxStartups') { should eq '10:30:100' }
    its('PermitTunnel') { should eq 'no' }
    its('AllowTcpForwarding') { should eq 'no' }
    its('GatewayPorts') { should eq 'no' }
    its('Compression') { should eq 'no' }
    its('Protocol') { should eq '2' }
    its('StrictModes') { should eq 'yes' }
    its('SyslogFacility') { should eq 'AUTH' }
    its('LogLevel') { should eq 'VERBOSE' }
    its('Ciphers') { should eq ssh_ciphers.join(',') }
    its('MACs') { should eq ssh_macs.join(',') }
    its('KexAlgorithms') { should eq ssh_kex.join(',') }
    its('HostKey') { should cmp ssh_host_keys }
    its('KerberosAuthentication') { should eq 'no' }
    its('KerberosOrLocalPasswd') { should eq 'no' }
    its('KerberosTicketCleanup') { should eq 'yes' }
    its('KerberosGetAFSToken') { should eq 'no' }
    its('KerberosUseKuserok') { should eq 'yes' }
    its('GSSAPIAuthentication') { should eq 'no' }
    its('GSSAPICleanupCredentials') { should eq 'yes' }
    its('GSSAPIStrictAcceptorCheck') { should eq 'yes' }
    its('GSSAPIKeyExchange') { should eq 'no' }
    its('GSSAPIEnablek5users') { should eq 'no' }
    its('IgnoreRhosts') { should eq 'yes' }
    its('IgnoreUserKnownHosts') { should eq 'yes' }
    its('HostbasedAuthentication') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('PermitEmptyPasswords') { should eq 'no' }
    its('ChallengeResponseAuthentication') { should eq 'no' }
    its('PubkeyAuthentication') { should eq 'yes' }
    its('MaxAuthTries') { should eq '2' }
    its('MaxSessions') { should eq '10' }
    its('LoginGraceTime') { should eq '30s' }
    its('PermitRootLogin') { should match(/no|without-password|prohibit-password/) }
    its('UsePAM') { should eq 'yes' }
    its('Banner') { should eq 'none' }
    its('PrintMotd') { should eq 'no' }
    its('PrintLastLog') { should eq 'yes' }
    its('AllowAgentForwarding') { should eq 'no' }
    its('UseDNS') { should eq 'no' }
    its('X11UseLocalhost') { should eq 'yes' }
    its('X11Forwarding') { should eq 'no' }
    its('PermitUserEnvironment') { should eq 'no' }
  end
end

control 'ssh-02' do
  title 'Ensure SSH client configuration is set appropriately'
  impact 'low'
  ref ref_file
  describe file('/etc/ssh/ssh_config') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
    its('selinux_label') { should eq 'system_u:object_r:etc_t:s0' }
  end
  describe ssh_config do
    its('ForwardAgent') { should eq 'no' }
    its('ForwardX11') { should eq 'no' }
    its('PasswordAuthentication') { should eq 'no' }
    its('HostbasedAuthentication') { should eq 'no' }
    its('GSSAPIAuthentication') { should eq 'no' }
    its('GSSAPIDelegateCredentials') { should eq 'no' }
    its('GSSAPIKeyExchange') { should eq 'no' }
    its('GSSAPITrustDNS') { should eq 'no' }
    its('BatchMode') { should eq 'no' }
    its('CheckHostIP') { should eq 'yes' }
    its('ConnectTimeout') { should eq '0' }
    its('StrictHostKeyChecking') { should eq 'ask' }
    its('Port') { should eq '22' }
    its('AddressFamily') { should eq 'any' }
    its('Protocol') { should eq '2' }
    its('Tunnel') { should eq 'no' }
    its('PermitLocalCommand') { should eq 'no' }
    its('Ciphers') { should eq ssh_ciphers.join(',') }
    its('MACs') { should eq ssh_macs.join(',') }
    its('KexAlgorithms') { should eq ssh_kex.join(',') }
  end
end
