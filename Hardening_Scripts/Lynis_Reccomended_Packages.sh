#!/bin/bash

install_lynis_recommended_packages() {
  # Installs lynis recommended packages
  apt install apt-listchanges needrestart debsecan debsums libpam-cracklib aide usbguard acct 
}
install_lynis_recommended_packages
