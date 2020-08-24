#!/bin/bash
auditd_configuration() {
  # Installs auditd
  apt install auditd
  # Configures auditd
  echo "
# Removes any existing auditd rules
-D

# Sets the buffer size, which may need to be increased, depending on the load of your system.
-b 8192

# Sets the failure mode to Failure Mode 1, which prints a failure message.
-f 2

# Audits the audit logs.
-w /var/log/audit/ -k auditlog

# Modifies the audit configuration,that occurs during the audit.
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audit/ -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Audits, user, group, and password databases
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd

# Tools to change group identifiers
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/groupmod -p x -k group_modification

# Monitors usage of passwd command
-w /usr/bin/passwd -p x -k passwd_modification

# Schedules cronjobs
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.allow -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron

# Login configuration and information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

# Network Environment
-w /etc/network/ -p wa -k network
-w /etc/hosts -p wa -k hosts
# Library search paths
-w /etc/ld.so.conf -p wa -k libpath

# Kernel parameters and module loading and unloading
-w /etc/sysctl.conf -p wa -k sysctl
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/insmod -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/modprobe -k modules
-a always,exit -F perm=x -F auid!=-1 -F path=/sbin/rmmod -k modules
-a always,exit -F arch=b64 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules
-a always,exit -F arch=b32 -S finit_module -S init_module -S delete_module -F auid!=-1 -k modules

# System startup scripts
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/inittab -p wa -k init

# SSH configuration
-w /etc/ssh/sshd_config -k sshd

# Changes to hostname
-a exit,always -F arch=b32 -S sethostname -k hostname
-a exit,always -F arch=b64 -S sethostname -k hostname
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications

# Captures all failures to access on critical elements
-a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess

# Logs all commands executed by root
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

# Su and Sudo
-w /etc/sudoers -p rw -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /bin/su -p x -k priv_esc

# Poweroffs and reboots tools
-w /sbin/shutdown -p x -k power
-w /sbin/halt -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power

# Monitors for use of audit management tools
-w /sbin/auditd -p x -k audittools
-w /sbin/auditctl -p x -k audittools

# Prevents chrony from overwhelming the logs
-a never,exit -F arch=b64 -S adjtimex -F auid=unset -F uid=chrony -F subj_type=chronyd_t

# Ignore End of Event records 
-a always,exclude -F msgtype=EOE

# Ignore current working directory records
-a always,exclude -F msgtype=CWD

# VMWare tools
-a exit,never -F arch=b32 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2
-a exit,never -F arch=b64 -S fork -F success=0 -F path=/usr/lib/vmware-tools -F subj_type=initrc_t -F exit=-2

# High Volume Event Filter 
-a exit,never -F arch=b32 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b64 -F dir=/dev/shm -k sharedmemaccess
-a exit,never -F arch=b32 -F dir=/var/lock/lvm -k locklvm
-a exit,never -F arch=b64 -F dir=/var/lock/lvm -k locklvm

# Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe

# KExec usage 
-a always,exit -F arch=b32 -S sys_kexec_load -k KEXEC
-a always,exit -F arch=b64 -S kexec_load -k KEXEC

# Special files
-a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles

# Mount operations
-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid!=-1 -k mount

# Local time zone
-w /etc/localtime -p wa -k localtime

# Stunnel
-w /usr/sbin/stunnel -p x -k stunnel

# Sudoers file changes
-w /etc/sudoers -p wa -k actions

# Changes to other files
-a always,exit -F dir=/etc/NetworkManager/ -F perm=wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/sysconfig/network -p wa -k network_modifications
-w /etc/network/ -p wa -k network

# Time
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time

# Changes to /etc/issue
-w /etc/issue -p wa -k etcissue
-w /etc/issue.net -p wa -k etcissu

# Change swap 
-a always,exit -F arch=b64 -S swapon -S swapoff -F auid!=-1 -k swap
-a always,exit -F arch=b32 -S swapon -S swapoff -F auid!=-1 -k swap

# Pam configuration
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam
-w /etc/security/limits.conf -p wa  -k pam
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam

# Systemd
-w /bin/systemctl -p x -k systemd 
-w /etc/systemd/ -p wa -k systemd

# Process ID change applications
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc

# Session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# Discretionary Access Control (DAC) modifications
-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod  -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -k perm_mod

# Suspicious activities
-w /usr/bin/wireshark -p x -k susp_activity
-w /usr/bin/ssh -p x -k susp_activity
-w /usr/bin/curl -p x -k susp_activity
-w /usr/bin/ncat -p x -k susp_activity
-w /usr/bin/base64 -p x -k susp_activity
-w /usr/bin/wget -p x -k susp_activity
-w /usr/bin/rawshark -p x -k susp_activity
-w /bin/nc -p x -k susp_activity
-w /usr/bin/rdesktop -p x -k sbin_susp
-w /bin/netcat -p x -k susp_activity
-w /usr/bin/socat -p x -k susp_activity

# Sbin suspicious activity
-w /usr/sbin/traceroute -p x -k sbin_susp
-w /sbin/ifconfig -p x -k sbin_susp
-w /usr/sbin/tcpdump -p x -k sbin_susp
-w /sbin/iptables -p x -k sbin_susp

# Reconnaissance and information gathering
-w /usr/bin/whoami -p x -k recon
-w /etc/hostname -p r -k recon
-w /etc/issue -p r -k recon

# Injection, these rules watch for code injection by the ptrace facility
# This could indicate someone trying to do something malicious or just debugging
-a always,exit -F arch=b32 -S ptrace -k tracing
-a always,exit -F arch=b64 -S ptrace -k tracing
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k register_injection
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection

# Privilege Abuse, the purpose of this rule is to detect when an admin may be abusing power by looking in user's home directory.
-a always,exit -F dir=/home -F uid=0 -F auid>=1000 -F auid!=4294967295 -C auid!=obj_uid -k power_abuse

# Apt-get and dpkg
-w /usr/bin/apt-get -p x -k software_mgmt
-w /usr/bin/apt-add-repository -p x -k software_mgmt
-w /usr/bin/aptitude -p x -k software_mgmt
-w /usr/bin/dpkg -p x -k software_mgmt

# CHEF
-w /etc/chef -p wa -k soft_chef

# GDS specific secrets
-w /etc/puppet/ssl -p wa -k puppet_ssl

#IBM Bigfix BESClient 
-a exit,always -F arch=b64 -S open -F dir=/opt/BESClient -F success=0 -k soft_besclient
-w /var/opt/BESClient/ -p wa -k soft_besclient

# Root command executions 
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

# Unauthorized file Access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k file_access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k file_access

# File Deletion Events by User
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

# Unsuccessful Creation
-a always,exit -F arch=b32 -S creat,link,mknod,mkdir,symlink,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
-a always,exit -F arch=b64 -S mkdir,creat,link,symlink,mknod,mknodat,linkat,symlinkat -F exit=-EACCES -k file_creation
-a always,exit -F arch=b32 -S link,mkdir,symlink,mkdirat -F exit=-EPERM -k file_creation
-a always,exit -F arch=b64 -S mkdir,link,symlink,mkdirat -F exit=-EPERM -k file_creation

# Unsuccessful Modification
-a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
-a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EACCES -k file_modification
-a always,exit -F arch=b32 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification
-a always,exit -F arch=b64 -S rename -S renameat -S truncate -S chmod -S setxattr -S lsetxattr -S removexattr -S lremovexattr -F exit=-EPERM -k file_modification

# Makes the configuration immutable
-e 2
" > /etc/audit/rules.d/audit.rules
  systemctl enable auditd.service
  service auditd restart
}

automatic_updates() {
  # Enables automatic updates
  apt-get install unattended-upgrades 
  dpkg-reconfigure -plow unattended-upgrades
}

disable_core_dumps() {
  # Disables core dumps
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "ulimit -c 0" >> /etc/profile
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf  
}

disable_firewire() {
  # Disables firewire
  echo "install udf /bin/true
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
}

disable_usb() {
  # Disables usb
  echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}

disable_uncommon_filesystems() {
  # Disables uncommon filesystems
  echo "install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true" >> /etc/modprobe.d/filesystems.conf
}

disable_uncommon_network_protocols() {
  # Disables uncommon network protocols
  echo "install dccp /bin/true
install sctp /bin/true
install tipc /bin/true
install rds /bin/true" >> /etc/modprobe.d/protocols.conf
  apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server 
}

setup_fail2ban() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs fail2ban
  apt install fail2ban
  
  # Enable fail2ban
  systemctl start fail2ban && systemctl enable fail2ban
  
  # Sets up fail2ban
  echo -n "Would you like to change the ssh port on your system [y/N]?"
  read -r qw
  if [ "$qw" == "y" ]
  then
  echo -n "Please enter the port you like to change the ssh port to: "
  read -r ty
  echo"
bantime  = 86400
findtime = 300
maxretry = 3
backend = systemd
banaction = iptables-multiport
banaction_allports = iptables-allports
[sshd]
enabled = true
[ssh]
enabled  = true
port     = $ty
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
" >> nano /etc/fail2ban/jail.local
  fi
  if [ "$qw" == "N" ]
  then
  echo "
bantime  = 86400
findtime = 300
maxretry = 3
backend = systemd
banaction = iptables-multiport
banaction_allports = iptables-allports
[sshd]
enabled = true
[ssh]
enabled  = true
port     = 22
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
" >> nano /etc/fail2ban/jail.local
  fi
  
  # Restarts fail2ban
  service fail2ban restart
}

iptable_configuration() {
  # Installs Iptables
  apt install iptables-persistent
  
   # Flushes existing iptable rules
  iptables -F
  
  # Logs and drops packets
  iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j LOG --log-prefix "IP_SPOOF A: "
  iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP
  
  # Maintains a list of recent connections to match against
  iptables -A FORWARD -m recent --name portscan --rcheck --seconds 100 -j DROP
  iptables -A FORWARD -p tcp -i eth0 --dport 443 -m recent --name portscan --set -j DROP
  
  # Matching against a string in a packet's data payload
  iptables -A FORWARD -m string --string '.com' -j DROP
  iptables -A FORWARD -m string --string '.exe' -j DROP
  
  # Time-based rules
  iptables -A FORWARD -p tcp -m multiport --dport http,https -o eth0 -i eth1 -m time --timestart 21:30 --timestop 22:30 --days Mon,Tue,Wed,Thu,Fri -j ACCEPT
  
  # Packet matching based on TTL values
  iptables -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -j REJECT
 
  # Configures Iptable Defaults
  iptables -P INPUT DROP
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD DROP
  
  # Drops Spoofing attacks
  iptables -A INPUT -s 10.0.0.0/8 -j DROP
  iptables -A INPUT -s 169.254.0.0/16 -j DROP
  iptables -A INPUT -s 172.16.0.0/12 -j DROP
  iptables -A INPUT -s 127.0.0.0/8 -j DROP
  iptables -A INPUT -s 192.168.0.0/24 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -d 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 240.0.0.0/5 -j DROP
  iptables -A INPUT -d 240.0.0.0/5 -j DROP
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 239.255.255.0/24 -j DROP
  iptables -A INPUT -d 255.255.255.255 -j DROP
  
  # Accepts loopback input
  iptables -A INPUT -i lo -p all -j ACCEPT
  
  # Allows a three-way Handshake
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  
  # Drops packets with excessive RST to avoid Masked attacks
  iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
  
  # Stops Masked Attacks
  iptables -A INPUT -p icmp --icmp-type 13 -j DROP
  iptables -A INPUT -p icmp --icmp-type 14 -j DROP
  iptables -A INPUT -p icmp --icmp-type 17 -j DROP
  iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
  
  # Discards Invalid Packets
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A FORWARD -m state --state INVALID -j DROP
  iptables -A OUTPUT -m state --state INVALID -j DROP
  
  # Allows ssh
  iptables -A INPUT -p tcp -m tcp --dport 652 -j ACCEPT
   
   # Allow one ssh connection at a time
  iptables -A INPUT -p tcp --syn --dport 652 -m connlimit --connlimit-above 2 -j REJECT
  
  # Allows Ping
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
  
  # Protection against port scanning
  iptables -N port-scanning
  iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
  iptables -A port-scanning -j DROP
 
  # SSH brute-force protection
  iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
  iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
  
  # Syn-flood protection
  iptables -N syn_flood
  iptables -A INPUT -p tcp --syn -j syn_flood
  iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
  iptables -A syn_flood -j DROP
  iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
  iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
  iptables -A INPUT -p icmp -j DROP
  iptables -A OUTPUT -p icmp -j ACCEPT
  
  # Mitigating SYN floods with SYNPROXY
  iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
  iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  
  # Block new packets that aren't SYN packets
  iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
  
  # Force fragments packets check
  iptables -A INPUT -f -j DROP
  
  # XMAS packets
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  
  # Drop all null packets
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

  # Block uncommon MSS values
  iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

  # Block packets with bogus TCP flags
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
  
  # Drops connections if the ip address makes more than 5 connection attempts to port 80 within 50 seconds
  $IPT -I INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --set
  $IPT -I INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 50 --hitcount 5 -j DROP
  
  # Saves iptables rules
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
  
  # Starts iptables
  sudo ufw enable
}

kernel_configuration() {
  # Configures the kernel
  echo "net.ipv4.tcp_syncookies: 1
net.ipv4.tcp_synack_retries = 5
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
net.ipv4.conf.all.promote_secondaries : 1
fs.file-max : 65535
net.ipv4.ip_local_port_range : 2000 65000
net.core.rmem : 8388608
net.core.wmem_max : 8388608
net.core.netdev_max_backlog : 5000
net.ipv4.tcp_window_scaling : 1
kernel.exec-shield : 2
kernel.randomize_va_space : 2
net.ipv4.tcp_rmem : 4096 87380 8388608
net.ipv4.tcp_wmem : 4096 87380 8388608
net.ipv4.tcp_rfc1337 : 1
net.ipv6.conf.default.max_addresses : 1
net.ipv6.conf.default.dad_transmits : 0
net.ipv6.conf.default.autoconf : 0
net.ipv6.conf.default.accept_ra_defrtr : 0
net.ipv6.conf.default.accept_ra_pinfo : 0
net.ipv6.conf.default.router_solicitations : 0
kernel.panic : 10
kernel.randomize_va_space : 2
fs.protected_hardlinks : 1
fs.protected_symlinks : 1
kernel.yama.ptrace_scope: 1" > /etc/sysctl.d/80-lockdown.conf
  sysctl --system  
}

legal_banner() {
  # Adds a legal banner to /etc/motd, /etc/issue and /etc/issue.net
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/motd  
  
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/issue
  
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/issue.net
}

install_lynis_recommended_packages() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs lynis recommended packages
  apt install apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard acct 
}

move_/tmp_to_/tmpfs() {
  # Moves /tmp to /tmpfs
  echo "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab
}

purge_old_removed_packages() {
  # Purges old and removed packages
  apt autoremove 
  apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')" 
}

remount_directories_with_restrictions() {
  # Mounts /proc with hidepid=2
  mount -o remount,rw,hidepid=2 /proc
  
  # Mounts /tmp with noexec
  mount -o remount,noexec /tmp

  # Mount /dev with noexec
  mount -o remount,noexec /dev

  # Mounts /run as nodev
  mount -o remount,nodev /run
  
  # Keeps /boot as read only
  echo "LABEL=/boot     /boot     ext2     defaults,ro     1 2" >> /etc/fstab
}

restrict_access_to_compilers() {
  # Restricts access to compilers
  v=$(which clang)
  d=$(which gcc)
  f=$(which c++)
  h=$(which clang++)
  r=$(which g++)
  
  length=${#v}
  lengt=${#d}
  leng=${#f}
  len=${#h}
  le=${#r}
  
  if [ "$length" -gt 0 ]
  then
  chmod o-x "$v"
  chmod o-r "$v"
  chmod o-w "$v"
  fi
  
  if [ "$lengt" -gt 0 ]
  then
  chmod o-x "$d"
  chmod o-r "$d"
  chmod o-w "$d"
  fi
  
  if [ "$leng" -gt 0 ]
  then
  chmod o-x "$f"
  chmod o-r "$f"
  chmod o-w "$f"
  fi
  
  if [ "$len" -gt 0 ]
  then
  chmod o-x "$h"
  chmod o-r "$h"
  chmod o-w "$h"
  fi
  
  if [ "$le" -gt 0 ]
  then
  chmod o-x "$r"
  chmod o-r "$r"
  chmod o-w "$r"
  fi
  
  if [ -d "/usr/bin/as" ]
  then
  chmod o-x /usr/bin/as 
  chmod o-r /usr/bin/as 
  chmod o-w /usr/bin/as
  fi
}

restrict_logins() {
  # Restricts logins by configuring login.defs
  sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
  sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 30/ /etc/login.defs
  echo "SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000" >> /etc/login.defs

 # Locks all empty password accounts
 v=$(awk -F: '($2 == "") {print}' /etc/shadow)
 d=length=${#v} 
 if [ "$d" -gt 0 ]
 then
  for i in $v
  do
    passwd -l "$i"
  done
 fi
}

secure_ssh() {
  # Secures ssh
  if [ "$qw" == "y" ]
  then
  echo "
ClientAliveCountMax 2
ClientAliveInterval 300
Compression no
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
AllowTcpForwarding no
Port $ty
PasswordAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
Protocol 2
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
X11Forwarding no
" >> /etc/ssh/sshd_config
  sed -i s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config
  sed -i s/^UsePAM.*/UsePAM\ yes/ /etc/ssh/sshd_config
  echo -n "Please enter the adminsters username:"
  read -r e
  echo "
AllowUsers $e
PermitRootLogin no
" >> /etc/ssh/sshd_config
  fi

  if [ "$qw" == "N" ]
  then
  echo "
ClientAliveCountMax 2
ClientAliveInterval 300
Compression no
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
AllowTcpForwarding no
Port 22
PasswordAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes
ChallengeResponseAuthentication no
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
Protocol 2
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
" >> /etc/ssh/sshd_config
  sed -i s/^X11Forwarding.*/X11Forwarding\ no/ /etc/ssh/sshd_config
  sed -i s/^UsePAM.*/UsePAM\ yes/ /etc/ssh/sshd_config
  echo -n "Please enter the adminstrators username: "
  read -r e
  echo "
AllowUsers $e
PermitRootLogin no
" >> /etc/ssh/sshd_config
fi
}

setup_aide() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs and sets up aide
  apt install aide
  aideinit
  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  update-aide.conf
  cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf
}

update_upgrade() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Updates the package list
  apt update
  
  # Upgrades packages
  apt upgrade
  
  # Does a dist upgrade, which "intelligently" handles changing dependencies
  apt dist-upgrade
}

setup_rkhunter_and_chkrootkit() {
  
  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs chkrootkit
  apt install chkrootkit
  
  # Installs rkhunter
  apt install rkhunter
  
  # You need to specify where both softwares should look for the commands they require to run scans to detect rootkits
  chkrootkit -p /mnt/safe
  rkhunter --check --bindir /mnt/safe
}

disable_thunderbolt() {
  # Disables Thunderbolt
  echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf
}

setup_psad() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs psad
  apt install psad
  
  # Sets up psad
  echo -e "kern.info\t|/var/lib/psad/psadfifo" >> /etc/syslog.conf
  /etc/init.d/sysklogd restart
  /etc/init.d/klogd
  echo -n "Please enter your email address to receive port scan detection messages:"
  read -r la
  echo -e "EMAIL_ADDRESSES          $la;
  ENABLE_AUTO_IDS             Y;
  IPTABLES_BLOCK_METHOD       Y;
  HOME_NET                NOT_USED;
  "  >> /etc/psad/psad.conf
  
  # Automatically removes all blocked ip addresses
  psad -F
  
  # Restarts psad to save configuaration information 
  /etc/init.d/psad restart
}

protect_physical_console_access() {
  # Create a grub boot loader password
  openssl passwd -1
  echo "Please copy down this password"
  echo -n "Please enter the hashed password that you were just given:"
  read -r lye
  echo "password --md5 $lye" >> /boot/grub/menu.lst
  
  
  # Enables authentication for single-user mode
  echo "~~:S:wait:/sbin/sulogin" >> /etc/inittab

  # Disables interactive hotkey startup at boot
  echo "PROMPT=no" >> /etc/sysconfig/init 

  # Automatically logsout Bash users
  echo "
  TMOUT=300
  readonly TMOUT
  export TMOUT" >> /etc/profile.d/autologout.sh
  chmod +x /etc/profile.d/autologout.sh

  # Disable Ctrl-Alt-Delete
  sed -e '/ca::ctrlaltdel:/sbin/shutdown -t3 -r now/ s/^#*/#/' -i /etc/inittab
  init q
  sed -e '/exec /sbin/shutdown -r now "Control-Alt-Delete pressed"/ s/^#*/#/' -i /etc/event.d/control-alt-delete
  
  # Configures root user timeout
  echo "[ $UID -eq 0 ] && TMOUT=300" >> /etc/profiles
}

setup_lighttpd() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs lighttpd
  apt install lighttpd
  
  # Sets up lighttpd
  echo "server.kbytes-per-second=1024" >> lighttpd.conf
  service lighttpd reload
  echo "connection.kbytes-per-second=64" >> lighttpd.conf
  service lighttpd reload
}

setup_shorewall() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs shorewall
  apt install shorewall shorewall-common shorewall-shell
  
  # Sets up shorewall
  echo "startup=1" >> /etc/default/shorewall
  echo "#ZONE   TYPE    OPTIONS         IN                      OUT
#                                       OPTIONS                 OPTIONS
fw      firewall
net     ipv4" >> /etc/shorewall/zones
  echo "#ZONE   INTERFACE       BROADCAST       OPTIONS
net     eth0            detect          tcpflags,logmartians,nosmurfs
net     eth1            detect          dhcp
net     ppp+            detect          dhcp" >> /etc/shorewall/interfaces
  echo "#SOURCE         DEST            POLICY          LOG LEVEL       LIMIT:
        BURST
        fw              all             ACCEPT
        net             all             DROP            info
        
        all             all             REJECT          info" >> /etc/shorewall/policy
}

install_logwatch() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs logcheck
  apt install logwatch
}

setup_ufw() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs ufw
  apt install ufw
  
  # Sets up ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw logging on
  ufw deny 20/tcp
  ufw deny 21/tcp
  ufw deny 23/tcp
  ufw deny 69/udp
  ufw deny 110/tcp
  ufw deny 143/tcp
  ufw deny 161/udp
  ufw deny 162/udp
  ufw deny 25/tcp
}

core_file_permissions() {
  v=("anacrontab" "crontab" "cron.hourly" "cron.daily" "cron.weekly" "cron.monthly" "cron.d" "passed" "group" "shadow" "gshadow")
  for i in "${v[@]}"
  do
   chown root:root "$i"
   chmod og-rwx "$i"
  done
}

disk_quotas() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs disk quota tools
  apt install quota quotatool
  
  # Installs require quota modules
  apt install linux-image-extra-virtual
  
  # Updates file mount options
  sed -i "s///LABEL=cloudimg-rootfs   /        ext4   usrquota,grpquota        0 0/g" /etc/fstab
  mount -o remount /
  
  # Enables disk quotas
  quotacheck -ugm /
  
  # Start disk quotas
  quotaon -v /
  
  echo -n "How many users would you like to enforce disk quotas on?"
  read -r ef
  length=${#ef}
  for i in $length
  do
    echo -n "Please enter the username of the user you like to enforce disk quotas on?"
    read -r t
    echo -n "Please enter the quota limit you would like to set and enter M for megabytes, K for kilobytes and G for gigabytes write after the limit:"
    read -r y
    setquota -u "$t" "$y" 0 0 0 /
  done
}

enable_process_accounting() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs process accounting software
  apt install acct
  
  # Creates log file
  touch /var/log/pacct
  
  # Turns process accounting on
  accton /var/log/pacct
}

install_ClamAV() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs ClamAV
  apt-get install clamav clamav-daemon
}

daily_cronjob() {
  
  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean

  # Installs cron just in case it isn't already installed
  apt install cron
  
  # This cronjob is created to run a set of programms that will do various security related reasons, such as checking for rootkits.
  crontab -l > security_cronjob
  
  # Opens the auditd log file
  echo "@daily echo "Opening the auditd log file"" >> security_cronjob
  echo "@daily vim /var/log/audit/audit.log" >> security_cronjob
  
  # Opens the fail2ban log file
  echo "@daily echo "Opening the fail2ban log file"" >> security_cronjob
  echo "@daily vim /var/log/fail2ban.log" >> security_cronjob
  
  # Opens the ssh log file
  echo "@daily echo "Opening the ssh log file"" >> security_cronjob
  echo "@daily vim /var/log/auth.log" >> security_cronjob
  
  # Opens the aide log file
  echo "@daily echo "Opening the aide log file"" >> security_cronjob
  echo "@daily vim /var/log/aide/aide.log" >> security_cronjob
  
  # Opens the ufw log file
  echo "@daily echo "Opening the ufw log file"" >> security_cronjob
  echo "@daily vim /var/log/ufw.log" >> security_cronjob
  
  # Opens the ufw log file
  echo "@daily echo "Opening the ufw log file"" >> security_cronjob
  echo "@daily vim /var/log/account/pacct" >> security_cronjob
  
  
  # Checks for potential rootkits
  echo "@daily echo "Checking for rootkits"" >> security_cronjob
  echo "@daily chkrootkit" >> security_cronjob
  echo "@daily rkhunter --check" >> security_cronjob
  
  # Runs logcheck to scan your log files
  echo "@daily echo "Scanning logs with logcheck"" >> security_cronjob
  @daily logcheck >> security_cronjob
  
  # Runs logwatch to scan your log files
  echo "@daily echo "Scanning logs with logwatch"" >> security_cronjob
  echo "@daily logwatch" >> security_cronjob
  
  # Displays a list of open ports and their associated programs 
  echo "@daily echo "Displaying open ports, please go through this list and make sure that all ports that are open should be open"" >> security_cronjob
  echo "@daily netstat -tupn" >> security_cronjob
  
  # Updates your computer daily
  echo "@daily echo "Updating your computer"" >> security_cronjob
  echo "@daily apt dist-upgrade" >> security_cronjob
  
  # Installs the cronjob
  crontab security_cronjob
  rm security_cronjob
}

setup_SElinux() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs SElinux
  apt install selinux-basics selinux-policy-default auditd
  curl -o ~/_load_selinux_policy 'https://wiki.debian.org/SELinux/Setup?action=AttachFile&do=get&target=_load_selinux_policy'
  
  # Sets up SElinux
  mv ~/_load_selinux_policy /usr/share/initramfs-tools/scripts/init-bottom
  update-initramfs -u
  selinux-activate
}

Two-Factor_Authentication () {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean
  
  # Installs the google authenticator
  apt install libpam-google-authenticator
  
  # Sets up Two-Factor Authentication
  echo "To setup Two-Factor Authentication please answer the following prompts"
  google-authenticator
  sed -i s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication\ yes/ /etc/ssh/sshd_config
  systemctl restart ssh
  echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
}

sudo_notifications() {
  # This portion of the script should send you notifications via email regarding when sudo comannds were run, who ran them, etc.
  
  echo -n "Please enter your email address so that you may receive notfication regarding when sudo commands are run and much more: "
  read -r em
  sed "/Defaults         mail_badpass/r Defaults mailto $em"/etc/sudoers
  sed "/Defaults         mailto/r Defaults mail_always on" /etc/sudoers
  sed "/Defaults         mail_always on/r Defaults mail_no_host" /etc/sudoers
  sed "/Defaults         mail_always on/r Defaults mail_no_host" /etc/sudoers
  sed "/Defaults         mail_no_host/r mail_no_perms" /etc/sudoers
  sed "/Defaults         mail_no_perms/r mail_no_user" /etc/sudoers
}

setup_Open_VPN() {

  # Cleans out the local repository of retrieved package files that are left in /var/cache
  apt clean

  # Installs dig just in case it isn't already installed
  apt install dnsutils
  
  # Installs Open VPN and sets it up
  wget https://git.io/vpn -O openvpn-install.sh
  curl https://ipinfo.io/ip  
  echo "To install Open VPN please answer the prompts below to setup Open VPN, but first read the messages to guide you through the installation"
  echo "For the Ip address prompt enter your public ip address which should be displayed above"
  echo "For the port prompt enter 1194"
  echo "For the DNS prompt enter either Google or OpenDNS"
  echo "Finally for the client name prompt enter an all lowercase, one-word, and no special characters name"
  bash openvpn-install.sh 
  
  # Restarts the Open VPN service and then starts it up
  systemctl restart openvpn@server
  systemctl start openvpn@server
}


reboot() {
  # Reboots the system
  sudo reboot
}

# Green color
GREEN='\033[0;32m'
NC='\033[0m'

initiate_function() {
  # Asks for user input as to which hardening programs they would like to run
  typeset -f "$1" | tail -n +2
  echo -e "$2"
  echo -ne "${GREEN}Would you like to run the commands above? [y/N]${NC}"
  read -r answer
  if [ "$answer" != "${answer#[Yy]}" ] 
  then
    $1
  fi
}

# Checks to see if you are root, otherwise it exits the program
while [ $EUID -ne 0 ]
do
echo "Please run this script as root"
exit 1
done
clear

# UI
RED='\033[0;31m'
NC='\033[0m'
info="${GREEN}
Shield was created on May 27 2020, by Jan Heymann
with the purpose of creating a Debian hardener.
Shield does many things to harden your system, 
for example Shield purges old and removed packages to remove
the vulnerability they pose.${NC}"

echo -e "${RED}             Shield:            ${NC}"
echo -e "${GREEN} ============================${NC}" 
echo -e "${RED}    Created by: Jan Heymann${NC}"
echo -e "${GREEN}   GNU GPL v3.0 Public Liscence${NC}\n"
echo -e "${RED}Usage: Shield [Command]${NC}\n"
echo -e "${GREEN}\tCommands:${NC}\n"
echo -e "${RED}===============================${NC}"
echo -e "\t${GREEN}-sysharden Run the system hardener and auditor${NC}"
echo -e "\t${RED}-info Display project information${NC}"
echo -e "\t${GREEN}-exit Exit the program${NC}"
echo -e "\t${RED}===============================${NC}"
while true
do
echo -n "Please enter a command, according to the usage stated above:" 
read -r a
case $a in
  "Shield -sysharden")
    initiate_function update_upgrade "Would you like to upgrade your system packages and upgrade your system package list on your system?"
    initiate_function legal_banner "Would you like to add a legal banner to /etc/issue, /etc/issue.net and /etc/motd? on your system"
    initiate_function auditd_configuration "Would you like to install and configure auditd with reasonable rules on your system?"
    initiate_function automatic_updates "Would you like to enable automatic update on your system?"
    initiate_function disable_core_dumps "Would you like to disable core dumps on your system?"
    initiate_function disable_firewire "Would you like to disable firewire on your system?"
    initiate_function disable_uncommon_filesystems "Would you like to disable uncommon filesystems on your system?"
    initiate_function disable_uncommon_network_protocols "Would you like to disable uncommon network protocol on your systems?"
    initiate_function disable_usb "Would you like to disable usb on your system?"
    initiate_function setup_fail2ban "Would you like to install and setup fail2ban on your system?"
    initiate_function install_lynis_recommended_packages "Would you like to install lynis reccomended packages on your system?"
    initiate_function iptable_configuration "Would you like to install and configure iptables on your system?"
    initiate_function kernel_configuration "Would you like your kernel to be configured on your system?"
    initiate_function move_/tmp_to_/tmpfs "Would you like to move /tmp to /tmpfs on your system?"
    initiate_function purge_old_removed_packages "Would you like to purge old and removed packages on your system?"
    initiate_function remount_directories_with_restrictions "Would you like have certain directories remounted with restrictions on your system?"
    initiate_function restrict_access_to_compilers "Would you like restrict access to compilers on  your system?"
    initiate_function restrict_logins "Would you like to restrict logins on your system?"
    initiate_function revert_/root_permissions "Would you like to revert /root permissions on your system?"
    initiate_function secure_ssh "Would you like to secure ssh and allow ssh only for the admin user on port 652 on your system?"
    initiate_function setup_rkhunter_and_chkrootkit "Would you like to setup and install rkhunter and chkrootkit on your system?"
    initiate_function disable_thunderbolt "Would you like to disable thunderbolt on your system?"
    initiate_function setup_psad "Would you like to install and setup psad on your system?"
    initiate_function protect_physical_console_access "Would you like to protect physical console access on your system?"
    initiate_function setup_lighttpd "Would you like to install and setup lighttpd on your system?"
    initiate_function setup_shorewall "Would you like to install and setup shorewall on your system?"
    initiate_function install_logwatch "Would you like to install logwatch on your system?"
    initiate_function setup_ufw "Would you like to install and setup ufw on your system?"
    initiate_function core_file_permissions "Would you like to set core file permissions on your system?"
    initiate_function disk_quotas "Would you like to enforce disk quotas on your system?"
    initiate_function enable_process_accounting "Would you like to enable process accounting on your system?"
    echo -e "{GREEN} If you are setting up aide then please be patient it may take a while.{NC}"
    initiate_function setup_aide "Would you like to install and setup aide on your system?"
    initate_function install_ClamAV "Would you like to install ClamAV on your system?" 
    initiate_function daily_cronjob "Would you like to install a daily cronjob that runs security related programs and open security related logs?"
    initiate_function setup_SElinux "Would you like to install and setup SElinux on your system?"
    initiate_function Two-Factor_Authentication "Would you like to setup Two-Factor Authentication on your system?"
    initiate_function sudo_notfications "Would you like to setup sudo notifications that notifiy you when sudo is run, who ran it, etc. on your system?"
    initiate_function setup_Open_VPN "Would you like to install and setup Open VPN on your system?"
    initiate_function reboot "Would you like to reboot your system to save all changes made?"
    ;;
  "Shield -info")
    echo -e "${info}"
    ;;
  "Shield -exit")
    exit
    exit
    ;;
  *)
    echo -e "Please enter a valid command"
    ;;
esac
done
