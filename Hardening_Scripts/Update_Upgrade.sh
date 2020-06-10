#!/bin/bash

update_upgrade() {
  
  # Updates the package list
  apt-get update
  
  # Upgrades packages
  apt-get upgrade
  
  # Does a dist upgrade, which "intelligently" handles changing dependencies
  apt-get dist-upgrade
}
update_upgrade
