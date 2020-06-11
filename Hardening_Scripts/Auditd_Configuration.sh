 #!/bin/bash
 auditd_configuration() {
  # Installs auditd
  apt-get install auditd
  # Configures auditd
  echo "
# Removes any existing auditd rules
-D

# Sets the buffer size, which may need to be increased, depending on the load of your system.
-b 8192

# Failure Mode 1, prints a failure message.
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

# Postfix configuration
-w /etc/postfix/ -p wa -k mail
-w /etc/aliases -p wa -k mail

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
# This could indicate someone trying to do something bad or just debugging
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
auditd_configuration
