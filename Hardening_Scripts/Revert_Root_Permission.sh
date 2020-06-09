#!/bin/bash  

revert_/root_permissions() {
 # Reverts /root permissions
  chmod 750 /home/debian
  chmod 700 /root
}
revert_/root_permissions
