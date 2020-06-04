#!/bin/bash

add_legal_banner() {
  # Adds a legal banner
  echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue
  echo "
Unauthorized access to this server is prohibited.
Legal action will be taken. Disconnect now.
" > /etc/issue.net
}
auditd_configuration() {
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
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audit/ -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
# Audits and logs User, Group, and Password databases
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd
 Monitor user and group tools
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
# Configures login and stored information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
# Network configuration
-w /etc/network/ -p wa -k network
-w /etc/hosts -p wa -k hosts
# Library search paths
-w /etc/ld.so.conf -p wa -k libpath
# Kernel parameters and modules
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/modprobe.conf -p wa -k modprobe
# System startup scripts
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/inittab -p wa -k init
# SSH configuration
-w /etc/ssh/sshd_config -k sshd
# Hostname
-a exit,always -F arch=b32 -S sethostname -k hostname
-a exit,always -F arch=b64 -S sethostname -k hostname
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
# Makes the configuration immutable
-e 2
" > /etc/audit/rules.d/audit.rules
  systemctl enable auditd.service
  service auditd restart
}
automatic_updates() {
  # Enables automatic updates
  apt install unattended-upgrades 
  dpkg-reconfigure -plow unattended-upgrades
}
disable_core_dumps() {
  # Disables core dumps
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo "ulimit -c 0" >> /etc/profile
}
disable_firewire() {
  echo "install udf /bin/true
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
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
  echo "install dccp /bin/true
install sctp /bin/true
install tipc /bin/true
install rds /bin/true" >> /etc/modprobe.d/protocols.conf
}
disable_usb() {
  echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
}
enable_process_accounting() {
  # Enables process accounting
  systemctl enable acct.service
  systemctl start acct.service
}

fail2ban_installation() {
  # Installs fail2ban
  apt install fail2ban 
}
install_lynis_recommended_packages() {
  # Installs lynis recommended packages
  apt install apt-listbugs apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard acct 
}
iptable_configuration() {
  # Installs Iptables
  apt install iptables-persistent 

  # Flushes existing iptable rules
  iptables -F
  
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

  # Blocks Ip adresses from doing portscans
  iptables -A INPUT   -m recent --name portscan --rcheck  -j DROP
  iptables -A FORWARD -m recent --name portscan --rcheck  -j DROP
  
  # Allows ssh
  iptables -A INPUT -p tcp -m tcp --dport 652 -j ACCEPT
   
   # Allow one ssh connection at a time
  iptables -A INPUT -p tcp --syn --dport 652 -m connlimit --connlimit-above 2 -j REJECT
  
  # Allows Ping
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
  
  # Saves iptable configurations
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
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
}
restrict_access_to_compilers() {
  # Restricts access to compilers
  chmod o-x /usr/bin/as /usr/bin/g++ /usr/bin/gcc
  chmod o-r /usr/bin/as /usr/bin/g++ /usr/bin/gcc
  chmod o-w /usr/bin/as /usr/bin/g++ /usr/bin/gcc
restrict_logins() {
  # Configures login.defs
  sed -i s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\ 7/ /etc/login.defs
  sed -i s/UMASK.*/UMASK\ 027/ /etc/login.defs
  sed -i s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\ 90/ /etc/login.defs
  echo "SHA_CRYPT_MIN_ROUNDS 1000000
SHA_CRYPT_MAX_ROUNDS 100000000" >> /etc/login.defs
}
revert_/root_permissions() {
 # Reverts /root permissions
  chmod 750 /home/debian
  chmod 700 /root

}
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
  while true
  do
  echo -n "Enter the adminstrators username:"
  read username
  ad=$(groups $username)
  d="$ad" | grep -oF "sudo"
  case $d in
    "sudo")
      echo "
      AllowUsers $username
      PermitRootLogin no
      " >> /etc/ssh/sshd_config
      ;;
    *)
      echo -e "Please enter a valid username:"
      ;;
  esac    
  done
}
setup_aide() {
  # Setups aide
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

upgrade_update() {
  # Updates system packages in a secure way
  apt-get upgrade
  # Updates system package information
  apt-get update

}
initiate_function() {
  typeset -f "$1" | tail -n +2
  echo "$2"
  echo "Run the above commands? [Y/n]"
  read -r answer
  if [ "$answer" != "${answer#[yY]}" ] 
  then
    $1
  fi
}
reboot() {
  # Reboots the system
  sudo reboot
}
while [[ $EUID -ne 0 ]]
do
echo "Please run this script as root"
exit 
done
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
echo -e "${RED}                 Shield:            ${NC}"
echo -e "${GREEN}=========================================${NC}"
echo -e "${RED}        Created by: Jan Heymann${NC}"   
echo -e "${GREEN}     GNU GPL v3.0 Public Liscence${NC}"

echo -e "${RED}Usage: Shield [command]${NC}"
echo -e "${GREEN}Commands:${NC}"
echo -e "${RED}=======================${NC}"
echo -e "${GREEN}--sysharden Run the system hardener and auditor${NC}"
echo -e "${RED}--info Display project information${NC}"
info="Shield was created by Jan Heymann on May 15 2020 with the purpose of securing and hardening your Debian and Debian based OS.
Shield does a number of things to secure and harden your system, for instance Shield purges old and removed packages to remove the
vulnerability they pose to your system."
while true
do
read -p "Please enter a command, according to the usage stated above:" a 
case $a in
  "Shield --sysharden")
    initiate_function add_legal_banner "Would you like to add a legal banner to /etc/issue and /etc/issue.net? on your system"
    intiate_function  auditd_configuration "Would you like to install and configure auditd with reasonable rules on your system?"
    initiate_function automatic_updates "Would you like to enable automatic update on your systems?"
    initiate_function disable_core_dumps "Would you like to disable core dumps on your system?"
    initiate_function disable_firewire "Would you like to disable firewire on your system?"
    initiate_function disable_uncommon_filesystems "Would you like to disable uncommon filesystems on your system?"
    initiate_function disable_uncommon_network_protocols "Would you like to disable uncommon network protocol on your systems?"
    initiate_function disable_usb "Would you like to disable usb on your system?"
    initiate_function enable_process_accounting "Would you like to enable process accounting on your system?"
    initiate_function fail2ban_installation "Would you like to install fail2ban on your system?"
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
    initiate_function setup_aide "Would you like to setup aide on your system?"
    initiate_function upgrade_update "Would you like to upgrade your system packages and upgrade your system package list on your system?"
    initiate_function reboot "Would you like to reboot your system"
    ;;
  "Shield --info")
    echo "$info"
    ;;
  *)
    echo -e "Please enter a valid command"
    ;;
esac
done

