#!/bin/bash

disable_uncommon_network_protocols() {
  # Disables uncommon network protocols
  echo "install dccp /bin/true
install sctp /bin/true
install tipc /bin/true
install rds /bin/true" >> /etc/modprobe.d/protocols.conf
  sudo apt-get --purge remove xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server
}
disable_uncommon_network_protocols
