import os
import subprocess as su

# Exits program if the script is not run as root
if os.getuid() != 0:
  exit("Please run this script as root")

# Returning to the directory where the shell scripts are located
v = su.check_output("cd",shell = True)
f = su.check_output("cd Shield/Hardening_Scripts",shell = True)
 
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

  

  
