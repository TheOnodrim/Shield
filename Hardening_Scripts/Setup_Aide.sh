#!/bin/bash
setup_aide() {
  # Setups aide
  aideinit
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}
setup_aide
