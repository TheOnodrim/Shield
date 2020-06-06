#!/bin/bash

enable_process_accounting() {
  # Enables process accounting
  systemctl enable acct.service
  systemctl start acct.service
}
enable_process_accounting
