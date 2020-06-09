#!/bin/bash  

secure_ssh() {
  # Secures ssh
  echo "
 ClientAliveCountMax 2
Compression no
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
AllowTcpForwarding no
Port 652
PasswordAuthentication no
" >> /etc/ssh/sshd_config
  sed -i s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config
  sed -i s/^UsePAM.*/UsePAM\ no/ /etc/ssh/sshd_config
}
secure_ssh
