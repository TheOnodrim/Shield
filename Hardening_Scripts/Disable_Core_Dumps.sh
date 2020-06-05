#!/bin/bash
disable_core_dumps() {
  # Disables core dumps
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "ulimit -c 0" >> /etc/profile
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf  
}
disable_core_dumps
