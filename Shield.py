import os
import subprocess as su
from pathlib import Path

# Exits program if the script is not run as root
if os.getuid() != 0:
  exit("Please run this script as root")

# Returning to the directory where the shell scripts are located
d = (str(Path.home()))
e = ("/Shield/Hardening_Scripts")
r = (d+e)
os.chdir(r)
 
def legal_banner():
  # This function adds a legal banner to /etc/motd, /etc/issue, /etc/issue.net
  g = su.check_output("bash Legal_Banner.sh",shell = True)

def auditd_configuration():
  # This function downloads auditd and configures it with reasonable rules
  d = su.check_output("bash Auditd_Configuration.sh",shell = True)

def automatic_updates():
  # This function enables automatic updates
  h = su.check_output("bash Automatic_Updates.sh",shell = True)

def disable_core_dumps():
  # This function disables core dumps
  j = su.check_output("bash Disable_Core_Dumps.sh",shell = True)

def disable_firewire():
  # This function disables firewire
  k = su.check_output("bash Disable_Firewire.sh")
  
def disable_uncommon_filesystems():
  # This function disables uncommon filesystems
  t = su.check_output("bash Disable_Uncommon_Filesystems.sh",shell = True)

def disable_uncommon_network_protocols():
  # This function disables uncommon network protocols
  u = su.check_output("bash Disable_Uncommon_Network_Protocols.sh",shell = True)

def disable_usb():
  # This function disables usb
  y = su.check_output("bash Disable_USB.sh",shell = True)

def enable_process_accounting():
  # This function enables process accounting
  s = su.check_output("bash Enable_Process_Accounting.sh",shell = True)

def fail2ban_installation():
  # This function installs fail2ban
  b = su.check_output("bash Fail2ban_Installation.sh",shell = True)

def lynis_recommended_packages_installation():
  # This function installs lynis recomended packages
  a = su.check_ouput("bash Lynis_Recomended_Packages.sh",shell = True)

def iptable_configuration():
  # This function configures the iptables
  t = su.check_output("bash Iptable_Configuration.sh",shell = True)

def kernel_configuration():
  # This function configures the kernel
  e = su.check_output("bash Kernel_Configuration.sh",shell = True)
  
def move_tmp_to_tmpfs():
  # This function moves /tmp to /tmpfs
  w = su.check_output("bash Move_Tmp_To_Tmpfs.sh",shell = True)

def purge_old_removed_packages():
  # This function purges old and removed packages
  z = su.check_output("bash Purges_Old_Removed_Packages.sh",shell = True)

def remount_directories_with_restrictions():
  # This function remount directories with restrictions
  l = su.check_output("bash Remount_Directories_With_Restrictions.sh",shell = True)

def restrict_access_to_compilers():
  # This function restricts access to compilers
  r = su.check_output("bash Restrict_Access_To_Compilers.sh",shell = True)

def restrict_logins():
  # This function restricts logins
  x = su.check_output("bash Restrict_Logins.sh",shell = True)
  
def revert_root_permissions():
  # This function reverts /root permissions
  q = su.check_output("bash Revert_Root_Permission.sh",shell = True)

def secure_ssh():
  # This function secures ssh
  v = input("Please enter the adminstrators username:")
  d = su.check_output("getent group sudo | cut -d: -f4",shell = True)
  while v not in d:
    print("Please enter a valid username:")
    v = input("Please enter the adminstrators username:")
  if v in d:
    with open("/etc/ssh/sshd_config","a") as ssconf:
      ssconf.append('''
      AllowUsers %s
      PermitRootLogin no
      ''' % v)
    f = su.check_output("Secure_Ssh.sh",shell = True)

def setup_aide():
  # This function setsup aide
  b = su.check_output("Setup_Aide.sh",shell = True)
  
def update_upgrade():
  # This function updates and upgrades your system
  y = su.check_output("Update_Upgrade.sh",shell = True)

def reboot():
  # This function reboots the system to save all changes made
  e = su.check_output("sudo reboot",shell = True)
