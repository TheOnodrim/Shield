#!/bin/bash

kernel_configuration() 
{
  # Configures the kernel
  echo "net.ipv4.tcp_syncookies: 1
net.ipv4.conf.default.accept_source_route: 0
kernel.core_uses_pid: 1
net.ipv4.conf.default.rp_filter: 1
net.ipv4.conf.all.log_martians: 1
kernel.kptr_restrict: 2
net.ipv4.conf.default.secure_redirects: 1
net.ipv4.conf.default.accept_redirects: 0
kernel.sysrq: 0
net.ipv4.icmp_echo_ignore_all: 0
net.ipv4.ip_forward: 0
fs.protected_symlinks: 1
net.ipv4.tcp_rfc1337: 1
net.ipv4.icmp_echo_ignore_broadcasts: 1
net.ipv4.conf.all.rp_filter: 1
net.ipv4.conf.all.send_redirects: 0
net.ipv6.conf.all.forwarding: 0
net.ipv4.conf.all.accept_source_route: 0
net.ipv6.conf.default.accept_source_route: 0
net.ipv4.conf.default.log_martians: 1
net.ipv6.conf.all.accept_source_route: 0
net.ipv4.conf.all.secure_redirects: 1
fs.protected_hardlinks: 1
net.ipv4.conf.all.accept_redirects: 0
kernel.perf_event_paranoid: 2
net.ipv4.conf.default.send_redirects: 0
kernel.randomize_va_space: 2
net.ipv6.conf.all.accept_redirects: 0
net.ipv6.conf.default.accept_redirects: 0
net.ipv4.icmp_ignore_bogus_error_responses: 1
kernel.yama.ptrace_scope: 1" > /etc/sysctl.d/80-lockdown.conf
  sysctl --system  
}
kernel_configuration
