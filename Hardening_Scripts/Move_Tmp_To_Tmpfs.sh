#!/bin/bash

move_/tmp_to_/tmpfs() {
  # Moves /tmp to /tmpfs
  echo "tmpfs /tmp tmpfs rw,nosuid,nodev" >> /etc/fstab
}
move_/tmp_to_/tmpfs
