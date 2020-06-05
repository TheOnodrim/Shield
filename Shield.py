import os
import subprocess as su
from pathlib import Path

if os.getuid() != 0:
  exit("Please run this script as root")
else:
  pass
home = str(Path.home())
 
def legal_banner():
  # This function adds a legal banner to /etc/motd, /etc/issue, /etc/issue.net
  if os.getcwd() != ("%s/Shield/Hardening_Scripts" % home):
    v = su.check_output("cd Shield/Hardening_Scripts",shell = True)
  else:
    pass
  g = su.check_output("bash Legal_Banner.sh",shell = True)

def auditd_configuration():
  # This function downloads auditd and configures it with reasonable rules
  if os.getcwd() != ("%s/Shield/Hardening_Scripts" % home):
    g = su.check_output("cd Shield/Hardening_Scripts",shell = True)
  else:
    pass
  d = su.check_output("bash Auditd_Configuration.sh",shell = True)
  
  

