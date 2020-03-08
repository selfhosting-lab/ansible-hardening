# Task file for tests
ref_file = 'tasks/kernel.yml'

control 'kernel-01' do
  title 'Prevent unprivileged users from seeing dmesg output'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.dmesg_restrict') do
    its('value') { should eq 1 }
  end
end

control 'kernel-02' do
  title 'Prevent users from reading kernel pointers'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.kptr_restrict') do
    its('value') { should eq 2 }
  end
end

control 'kernel-03' do
  title 'Disable kernel magic key'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.sysrq') do
    its('value') { should eq 0 }
  end
end

control 'kernel-04' do
  title 'Prevent unprivileged users from using ptrace'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.yama.ptrace_scope') do
    its('value') { should eq 2 }
  end
end

control 'kernel-05' do
  title 'Append PID to core name in kernel dumps'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.core_uses_pid') do
    its('value') { should eq 1 }
  end
end

control 'kernel-06' do
  title 'Randomise process address space'
  impact 'low'
  ref ref_file
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

control 'kernel-07' do
  title 'Protect cross-volume links'
  impact 'low'
  ref ref_file
  links = %w[fs.protected_hardlinks fs.protected_symlinks]
  links.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-08' do
  title 'Prevent coredumps from setuid'
  impact 'low'
  ref ref_file
  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should eq 0 }
  end
end

control 'kernel-09' do
  title 'Disable TCP timestamps'
  impact 'low'
  ref ref_file
  describe kernel_parameter('net.ipv4.tcp_timestamps') do
    its('value') { should eq 0 }
  end
end

control 'kernel-09' do
  title 'Rate limit ICMP packets'
  impact 'low'
  ref ref_file
  describe kernel_parameter('net.ipv4.icmp_ratelimit') do
    its('value') { should eq 100 }
  end
  describe kernel_parameter('net.ipv4.icmp_ratemask') do
    its('value') { should eq 88_089 }
  end
end

control 'kernel-10' do
  title 'Ignore suspicious ICMP packets'
  impact 'medium'
  ref ref_file
  suspicious_icmp_packets = %w[icmp_ignore_bogus_error_responses icmp_echo_ignore_broadcasts]
  suspicious_icmp_packets.each do |param|
    describe kernel_parameter("net.ipv4.#{param}") do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-11' do
  title 'Protect from TCP attacks'
  impact 'medium'
  ref ref_file
  tcp_attacks = %w[tcp_syncookies tcp_rfc1337]
  tcp_attacks.each do |param|
    describe kernel_parameter("net.ipv4.#{param}")
  end
end

control 'kernel-12' do
  title 'Disable IPv6'
  impact 'high'
  ref ref_file
  params = %w[
    net.ipv6.conf.all.disable_ipv6
    net.ipv6.conf.default.disable_ipv6
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-13' do
  title 'Enable source address verification'
  impact 'high'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.rp_filter
    net.ipv4.conf.all.log_martians
    net.ipv4.conf.default.rp_filter
    net.ipv4.conf.default.log_martians
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-14' do
  title 'Ignore ARP messages from IP and interface mismatch'
  impact 'medium'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.arp_ignore
    net.ipv4.conf.default.arp_ignore
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-14' do
  title 'Ignore ARP messages from IP and interface mismatch'
  impact 'medium'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.arp_ignore
    net.ipv4.conf.default.arp_ignore
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-15' do
  title 'Only respond to ARP messages on the appropriate interface'
  impact 'medium'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.arp_announce
    net.ipv4.conf.default.arp_announce
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 2 }
    end
  end
end

control 'kernel-16' do
  title 'Disable IPv6 autoconfiguration'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv6.conf.all.autoconf
    net.ipv6.conf.default.autoconf
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-17' do
  title 'Disable IPv6 neighbour solicitations'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv6.conf.all.dad_transmits
    net.ipv6.conf.default.dad_transmits
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-18' do
  title 'Assign one global unicast IPv6 address'
  impact 'medium'
  ref ref_file
  params = %w[
    net.ipv6.conf.all.max_addresses
    net.ipv6.conf.default.max_addresses
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 1 }
    end
  end
end

control 'kernel-19' do
  title 'Do not send ICMP redirects'
  impact 'medium'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.default.send_redirects
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-20' do
  title 'Refuse IPv6 router advertisements'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv6.conf.all.accept_ra
    net.ipv6.conf.all.accept_ra_defrtr
    net.ipv6.conf.all.accept_ra_pinfo
    net.ipv6.conf.all.accept_ra_rtr_pref
    net.ipv6.conf.all.router_solicitations
    net.ipv6.conf.default.accept_ra
    net.ipv6.conf.default.accept_ra_defrtr
    net.ipv6.conf.default.accept_ra_pinfo
    net.ipv6.conf.default.accept_ra_rtr_pref
    net.ipv6.conf.default.router_solicitations
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-21' do
  title 'Refuse secure ICMP redirects'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.secure_redirects
    net.ipv4.conf.default.secure_redirects
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-22' do
  title 'kernel : Do not accept IP source routing'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.default.accept_source_route
    net.ipv6.conf.all.accept_source_route
    net.ipv6.conf.default.accept_source_route
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end

control 'kernel-23' do
  title 'kernel : Do not accept ICMP redirects'
  impact 'low'
  ref ref_file
  params = %w[
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.default.accept_redirects
  ]
  params.each do |param|
    describe kernel_parameter(param) do
      its('value') { should eq 0 }
    end
  end
end
