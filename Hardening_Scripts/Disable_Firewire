#!/bin/bash
disable_firewire() {
  # Disables firewire
  echo "install udf /bin/true
blacklist firewire-core
blacklist firewire-ohci
blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
}
disable_firewire
