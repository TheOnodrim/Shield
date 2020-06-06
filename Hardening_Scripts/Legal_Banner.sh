#!/bin/bash
legal_banner() {
  # Adds a legal banner to /etc/motd, /etc/issue and /etc/issue.net
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/motd  
  
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/issue
  
  echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" > /etc/issue.net
}
legal_banner
