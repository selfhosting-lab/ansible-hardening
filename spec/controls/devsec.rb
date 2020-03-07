# DevSec compliance

# https://dev-sec.io/baselines/linux/
include_controls 'dev-sec-linux' do
  skip_control 'os-05' # Check login.defs - some of the options here are opinionated
  skip_control 'os-08' # Entropy is not always full when you start a new system
  skip_control 'os-10' # Disable unused filesystems - we don't know the user's system
  skip_control 'sysctl-01' # Kubernetes requires forwarding
  skip_control 'sysctl-19' # Kubernetes requires forwarding
end

# https://dev-sec.io/baselines/ssh/
include_controls 'dev-sec-ssh' do
  skip_control 'sshd-45' # Printing last log in can be really useful for admins
end
