import os
import subprocess as su
from pathlib import Path

# Exits program if the script is not run as root
if os.getuid() != 0:
  exit("Please run this script as root")

# Returning to the directory where the shell scripts are located
r = ("Hardening_Scripts")
os.chdir(r)

# Make every script executable
qw = ["Auditd_Configuration.sh","Automatic_Updates.sh","Disable_Core_Dumps.sh","Disable_Firewire.sh","Disable_Uncommon_Filesystems.sh",
"Disable_Uncommon_Network_Protocols.sh","Disable_USB.sh","Fail2ban_Installation.sh","Legal_Banner.sh","Lynis_Recomended_Packages.sh","Iptable_Configuration.sh","Kernel_Configuration.sh",
"Move_Tmp_To_Tmpfs.sh","Purge_Old_Removed_Packages.sh","Remount_Directories_With_Restrictions.sh","Restrict_Access_To_Compilers.sh",
"Restrict_Logins.sh","Revert_Root_Permission.sh","Secure_Ssh.sh","Setup_Aide.sh","Update_Upgrade.sh"]

for i in qw:
  os.chmod(i,100)
  
def auditd_configuration():
  # This function downloads auditd and configures it with reasonable rules
  d = os.popen("bash Auditd_Configuration.sh")

def automatic_updates():
  # This function enables automatic updates
  h = os.popen("bash Automatic_Updates.sh")

def disable_core_dumps():
  # This function disables core dumps
  j = os.popen("bash Disable_Core_Dumps.sh")

def disable_firewire():
  # This function disables firewire
  k = os.popen("bash Disable_Firewire.sh")
  
def disable_uncommon_filesystems():
  # This function disables uncommon filesystems
  t = os.popen("bash Disable_Uncommon_Filesystems.sh")

def disable_uncommon_network_protocols():
  # This function disables uncommon network protocols
  u = os.popen("bash Disable_Uncommon_Network_Protocols.sh")

def disable_usb():
  # This function disables usb
  y = os.popen("bash Disable_USB.sh")

def fail2ban_installation():
  # This function installs fail2ban
  b = os.popen("bash Fail2ban_Installation.sh")

def legal_banner():
  # This function adds a legal banner to /etc/motd, /etc/issue, /etc/issue.net
  g = os.popen("bash Legal_Banner.sh",shell = True)
  
def lynis_recommended_packages_installation():
  # This function installs lynis recomended packages
  a = os.popen("bash Lynis_Recomended_Packages.sh")

def iptable_configuration():
  # This function configures the iptables
  t = os.popen("bash Iptable_Configuration.sh")

def kernel_configuration():
  # This function configures the kernel
  e = os.popen("bash Kernel_Configuration.sh")
  
def move_tmp_to_tmpfs():
  # This function moves /tmp to /tmpfs
  w = os.popen("bash Move_Tmp_To_Tmpfs.sh")

def purge_old_removed_packages():
  # This function purges old and removed packages
  z = os.popen("bash Purge_Old_Removed_Packages.sh")

def remount_directories_with_restrictions():
  # This function remount directories with restrictions
  l = os.popen("bash Remount_Directories_With_Restrictions.sh")

def restrict_access_to_compilers():
  # This function restricts access to compilers
  r = os.popen("bash Restrict_Access_To_Compilers.sh")

def restrict_logins():
  # This function restricts logins
  x = os.popen("bash Restrict_Logins.sh")
  
def revert_root_permissions():
  # This function reverts /root permissions
  q = os.popen("bash Revert_Root_Permission.sh")

def secure_ssh():
  # This function secures ssh
  v = input("Please enter the adminstrators username:")
  d = os.popen("getent group sudo | cut -d: -f4",)
  while v not in d:
    print("Please enter a valid username:")
    v = input("Please enter the adminstrators username:")
  if v in d:
    with open("/etc/ssh/sshd_config","a") as ssconf:
      ssconf.append('''AllowUsers %s
      PermitRootLogin no''' % v)
    f = os.popen("Secure_Ssh.sh")

def setup_aide():
  # This function setsup aide
  b = os.popen("Setup_Aide.sh")
  
def update_upgrade():
  # This function updates and upgrades your system
  y = os.popen("Update_Upgrade.sh")

def reboot():
  # This function reboots the system to save all changes made
  e = os.popen("sudo reboot")

# UI
def prGreen(srt):
  # This function prints a string in a green color
  print("\033[92m {}\033[00m".format(srt))
  
def prRed(trs):
  # This function prints a string in a red color
  print("\033[91m {}\033[00m".format(trs))

def callfunc(v):
  # This function calls other functions
  z = v
  return z()

def Input(d,z):
  # This function gives users a choice, via user input for which aspects of their computer they would like to harden
  # As well as those they do not want to harden
  while True:
    cont = input(d + "[y/N]")
    while cont.lower() not in ("y","n"):
        print("Please enter a valid response :")
        cont = input(d+"[y/N]?")   
    if cont == "N":
        break
        pass
    if cont == "y":
      callfunc(z)
      break
prRed("           Shield")
prGreen("  Liscence: GNU GPL v3.0")
prRed("    Created by: Jan Heymann\n")
prGreen("Usage: Shield [Command]")

prRed("Commands:\n")

prGreen("-sysharden Begin the system audit and harden")
prRed("-info Display project information")
while True:
  v = input("Please enter a command according to the usage stated above:")
  while v not in ("Shield -sysharden", "Shield -info"):
    prGreen("Please enter a valid command")
    v = input("Please enter a command according to the usage stated above:")
  if v == "Shield -sysharden":
    Input("Would you like to install auditd and configure it with reasonable rules on your system",auditd_configuration)
    Input("Would you like to allow automatic updates on your system",automatic_updates)
    Input("Would you like to disable core dumps on your system",disable_core_dumps)
    Input("Would you like to disable firewire storage on your system",disable_firewire)
    Input("Would you like to disable usb storage on your system",disable_usb)
    Input("Would you like to disable uncommon filesystems on your system",disable_uncommon_filesystems)
    Input("Would you like to disable uncommon network protocols on your system",disable_uncommon_network_protocols)
    Input("Would you like to install fail2ban on your system",fail2ban_installation)
    Input("Would you like to install iptables and configure the iptables on your system",iptable_configuration)
    Input("Would you like to configure your kernel on your system",kernel_configuration)
    Input("Would you like to add a legal banner to your system",legal_banner)
    Input("Would you like to install lynis recommended packages on your system",lynis_recommended_packages_installation)
    Input("Would you like to move /tmp to /tmpfs on your system",move_tmp_to_tmpfs)
    Input("Would you like to purge old and removed packages on your system",purge_old_removed_packages)
    Input("Would you like to remount directories on your system with restrictions",remount_directories_with_restrictions)
    Input("Would you like to restrict access to compilers on your system",restrict_access_to_compilers)
    Input("Would you like to restrict logins on your system",restrict_logins)
    Input("Would you like to revert /root permissions on your system",revert_root_permissions)
    Input("Would you like to secure ssh on your system",secure_ssh)
    Input("Would you like to setup aide on your system",setup_aide)
    Input("Would you like to update your system package list and upgrade your system packages on your system",update_upgrade) 
  if v == "Shield -info":
    v = prGreen("""\
    Shield was created on May 27 2020, by Jan Heymann with the purpose of creating a Debian hardener.
    Shield does many things to harden your system, for example Shield purges old and removed packages to remove
    the vulnerability they pose.
    """)
