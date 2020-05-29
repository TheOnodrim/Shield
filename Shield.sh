#!/bin/bash
upgrade_update() 
{
  # Updates system packages in a secure way
  apt-get upgrade
  # Updates system package information
  apt-get update

}

iptable_configuration() 
{
  # Installs Iptables
  apt install iptables-persistent 

  # Flushes existing iptable rules
  iptables -F
  
  # Configures Iptable Defaults
  iptables -P INPUT DROP
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD DROP

  
  # Accepts loopback input
  iptables -A INPUT -i lo -p all -j ACCEPT
  
  # Allows a three-way Handshake
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  
  # Stops Masked Attacks
  iptables -A INPUT -p icmp --icmp-type 13 -j DROP
  iptables -A INPUT -p icmp --icmp-type 17 -j DROP
  iptables -A INPUT -p icmp --icmp-type 14 -j DROP
  iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
  
  # Discards Invalid Packets
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A FORWARD -m state --state INVALID -j DROP
  iptables -A OUTPUT -m state --state INVALID -j DROP
  
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
  
  # Drops packets with excessive RST to avoid Masked attacks
  iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
  
  # Blocks Ip adresses from doing portscans
  iptables -A INPUT   -m recent --name portscan --rcheck  -j DROP
  iptables -A FORWARD -m recent --name portscan --rcheck  -j DROP
  
  # Allows ssh
  iptables -A INPUT -p tcp -m tcp --dport 652 -j ACCEPT
  
  # Allows Ping
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
  
  # Allow one ssh connection at a time
  iptables -A INPUT -p tcp --syn --dport 652 -m connlimit --connlimit-above 2 -j REJECT
  
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
}

fail2ban_installation() 
{
  # Installs fail2ban
  apt install fail2ban 
}

kernel_configuration() 
{
  # Configures Kernel
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

automatic_updates() 
{
  # Enables automatic updates
  apt install unattended-upgrades 
  dpkg-reconfigure -plow unattended-upgrades
}

auditd_configuration() 
{
  # Installs auditd
  apt install auditd 

  # Adds auditd configuration
  echo "
# Removes any existing auditd rules
-D
# Buffer Size
# May need to be increased, depending on the load of your system.
-b 8192
# Failure Mode 1, prints a failure message.
-f 1
# Audits the audit logs.
-w /var/log/audit/ -k auditlog
# Modifies the audit configuration,that occurs during the audit.
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
# Schedules cronjobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron
# Audits and logs User, Group, and Password databases
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd
# Monitors usage of passwd command
-w /usr/bin/passwd -p x -k passwd_modification
# Monitor user and group tools
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
# Login configuration and stored info
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
# Network configuration
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
# System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
# Library search paths
-w /etc/ld.so.conf -p wa -k libpath
# Kernel parameters and modules
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/modprobe.conf -p wa -k modprobe
# SSH configuration
-w /etc/ssh/sshd_config -k sshd
# Hostname
-a exit,always -F arch=b32 -S sethostname -k hostname
-a exit,always -F arch=b64 -S sethostname -k hostname
# Logs all commands executed by root
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd
# Captures all failures to access on critical elements
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/local/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess
## Su and Sudo
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc
# Poweroffs and reboots tools
-w /sbin/halt -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/shutdown -p x -k power
# Makes the configuration immutable
-e 2
" > /etc/audit/rules.d/audit.rules
  systemctl enable auditd.service
  service auditd restart
}

disables_core_dumps() 
{
  # Disables core dumps
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo "ulimit -c 0" >> /etc/profile
}

restricts_logins() 
{
  # Configures login.defs
  sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
  sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
  echo "SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000" >> /etc/login.defs
}

secures_ssh() 
{

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
echo -n "Enter the adminstrators username:"
read username
while true
do
if [ groups $username != "$username : $username sudo" ] 
then
echo "Please enter a valid admin username"
fi
done
if [ groups $username == "$username : $username sudo" ]
then
echo "
AllowUsers $username
PermitRootLogin no
" >> /etc/ssh/sshd_config
fi
}


adds_legal_banner() 
{
  # Adds a legal banner
  echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue.net
  echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue
}

installs_lynis_recommended_packages() 
{
  # Installs lynis recommended packages
  apt install apt-listbugs apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard acct 
}

setsup_aide() 
{
  # Setwup aide
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

enables_process_accounting() 
{
  # Enables process accounting
  systemctl enable acct.service
  systemctl start acct.service
}

disables_uncommon_filesystems() 
{
  # Disables uncommon filesystems
  echo "install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install squashfs /bin/true" >> /etc/modprobe.d/filesystems.conf
}

disables_firewire() 
{
  echo "install udf /bin/true
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
}

disables_usb() 
{
  echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}

disables_uncommon_network_protocols() ##
{
  echo "install dccp /bin/true
install sctp /bin/true
install tipc /bin/true
install rds /bin/true" >> /etc/modprobe.d/protocols.conf
}

reverts_/root_permissions() 
{
 # Reverts /root permissions
  chmod 750 /home/debian
  chmod 700 /root

}

restricts_access_to_compilers() 
{
  # Restricts access to compilers
  chmod o-rx /usr/bin/as
}

moves_/tmp_to_/tmpfs() 
{
  # Moves /tmp to /tmpfs
  echo "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab
}

remounts_directories_with_restrictions() 
{
  # Mounts /proc with hidepid=2
  mount -o remount,rw,hidepid=2 /proc
  
  # Mounts /dev with noexec
  mount -o remount,noexec /dev
  
  # Mounts /tmp with noexec
  mount -o remount,noexec /tmp

  # Mount /dev with noexec
  mount -o remount,noexec /dev

  # Mounts /run as nodev
  mount -o remount,nodev /run
}

purges_old_removed_packages() 
{
  # Purges old and removed packages
  apt autoremove 
  apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')" 
}
while [[ $EUID -ne 0 ]]
do
echo "Please run this script as root"
exit 
done
v="   ######   ##       ##  ################# #############  ##                  ##########               
      ##       ##       ##         ##         ##             ##                  ##       ###                  
      ##       ##       ##         ##         ##             ##                  ##         ##       
      ##       ###########         ##         #############  ##                  ##         ##         
      ##       ##       ##         ##         ##             ##                  ##         ##
      ##       ##       ##         ##         ##             ##                  ##       ###      
 #######       ##       ##  ################# #############  #################   ###########"
echo $v
echo "Usage: Shield [command]"
echo "Commands:"
echo "========="
echo "--sysharden Run the system hardener and auditor"
echo "--info Display project information"
while true
do
read -p "Please enter a command, according to the usage stated above:" a
info="Shield is a bash scripts created to audit and harden Debian and Debian based OS's.
\n It does a number of things to secure and harden your system, for example Shield rewrites your iptable configuration
to make your Linux kernel firewall more secure.\n Shield also purges old and removed packages to remove the vulnerability they
pose"
if [ $a != "Shield --info" ]
then 
echo "Please enter a valid command"
fi
if [ $a != "Shield --sysharden]
then
echo "Please enter a valid command
fi
if [ $a = "Shield --info ]
then
echo $info
fi
if [ $a = "Shield --sysharden ]
then
initiate_function() 
{
  typeset -f "$1" | tail -n +2
  echo "$2"
  echo "Run the above commands? [Y/n]"
  read -r answer
  if [ "$answer" != "${answer#[Yy]}" ] 
  then
    $1
  fi
}
fi

done




