# roles/hardening

## Description

[![Drone build status](https://img.shields.io/drone/build/selfhosting-lab/ansible-host/master?label=BUILD&logo=drone&style=for-the-badge)](https://cloud.drone.io/selfhosting-lab/ansible-host/)

## Description

Provide a variety of security settings to help protect your system, via Ansible.

This is used as a base image for selfhosting-labs.

## Dependencies

- [Fedora 30](https://getfedora.org/) x86_64 target machine.
- [Ansible](https://ansible.com).
- [Ruby](https://ruby-lang.org) >= `2.6` if you wish to run the test suite.
- [Bundler](https://bundler.io)

---

## Quick start

If you want to spin a quick environment up in Vagrant, it is enough to run the
following:

```shell
bundle install
bundle exec kitchen converge vagrant
bundle exec kitchen verify vagrant
bundle exec kitchen login vagrant
```

---

## Features

- [Kernel hardening](#kernel-hardening)
- [FirewallD](#firewalld)
- [Fail2Ban](#fail2ban)
- [SELinux](#selinux)
- [Umask configuration](#umask-configuration)
- [SSH hardening](#ssh-hardening)
- [DevSec compliance](#devsec-compliance)

---

## Kernel hardening

A multitude of Kernel settings are set in order to provide better protection against a variety of well-known attacks.

## FirewallD

FirewallD is enabled by default, rather than more traditional firewall systems such as iptables, as it better supports Kubernetes due to the ability to dynamically create firewall rules.

RFC1918 addresses are added to the 'Internal' zone as they are exclusively used inside private LANs and are generally safer to permit access from than the public Internet.

SSH is exposed in the public zone as generally remote access is required to administer hosts. To actually expose it to the public Internet you may need to do further steps in your cloud provider or on your network appliances.

## Fail2Ban

[Fail2Ban](https://www.fail2ban.org/) is enabled to reduce unauthorised logins by detecting when more than a threshold of failed logins occurs from a certain source IP address and then temporarily banning the address from connecting via FirewallD.

This role, as well as installing Fail2Ban itself, sets up a jail for SSH with three failed attempts in an hour triggering a one hour IP ban for SSH connections.

RFC1918 addresses are whitelisted so traffic on your LAN will not be affected.

## SELinux

[SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) is enabled and set into enforcing mode.

## Umask configuration

A more secure umask of `027` is set as default providing the equivalent of `640` for files and `750` for directories.

This is applied to `/etc/profile`, `/etc/bashrc`, and `/etc/csh.cshrc` and therefore affects Bash and C shell. If you install additional shells which do not use, or override, the default umask in `/etc/profile` this configuration will not apply to those shells.

## SSH hardening

[SSH](https://www.openssh.com/) is configured to industry best-practice. Remote access is restricted exclusively to key-based authentication, with tunneling disabled.

## DevSec compliance

As well as including bespoke tests for ensuring this role is performing correctly, the role should be compliant with the DevSec [Linux baseline](https://dev-sec.io/baselines/linux/) and [SSH baseline](https://dev-sec.io/baselines/ssh/). This provides confirmation of alignment with industry best practices.

A few minor checks are disabled due to being too agressively opinionated. You can review which specific checks are disabled in `spec/controls/dev-sec.rb`.

On a basic OS install, all enabled checks from the DevSec InSpec profiles should pass. If you find that certain checks are failing, please raise a bug report as the scope of this role can be modified to enforce additional rules.
