#!/bin/bash

iptable_configuration() {
  # Installs Iptables
  apt-get install iptables-persistent
  
   # Flushes existing iptable rules
  iptables -F
  
  # Installs prips
  apt-get install prips
  ip=$(prips 0.0.0.0 239.255.255.255)
  
  # Blocks and rejects all ip addresses
  for i in ip
  do
    iptables -A INPUT -s ${i} -j REJECT
  done
  
  # Logs and drops packets
  iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j LOG --log-prefix "IP_SPOOF A: "
  iptables -A INPUT -i eth1 -s 10.0.0.0/8 -j DROP
  
  # Load balancing
  _ips=("172.31.250.10" "172.31.250.11" "172.31.250.12" "172.31.250.13")
  for ip in "${_ips[@]}" ; do
    iptables -A PREROUTING -i eth0 -p tcp --dport 80 -m state --state NEW -m nth --counter 0 --every 4 --packet 0 \
    -j DNAT --to-destination ${ip}:80
  done
  
  # Restricts the number of connections
  iptables -A INPUT -p tcp -m state --state NEW --dport http -m iplimit --iplimit-above 5 -j DROP
  iptables -A FORWARD -m state --state NEW -p tcp -m multiport --dport http,https -o eth0 -i eth1 -m limit --limit 20/hour --limit-burst 5 -j ACCEPT
  
  # Maintains a list of recent connections to match against
  iptables -A FORWARD -m recent --name portscan --rcheck --seconds 100 -j DROP
  iptables -A FORWARD -p tcp -i eth0 --dport 443 -m recent --name portscan --set -j DROP
  
  # Matching against a string in a packet's data payload
  iptables -A FORWARD -m string --string '.com' -j DROP
  iptables -A FORWARD -m string --string '.exe' -j DROP
  
  # Time-based rules
  iptables -A FORWARD -p tcp -m multiport --dport http,https -o eth0 -i eth1 -m time --timestart 21:30 --timestop 22:30 --days Mon,Tue,Wed,Thu,Fri -j ACCEPT
  
  # Packet matching based on TTL values
  iptables -A INPUT -s 1.2.3.4 -m ttl --ttl-lt 40 -j REJECT
 
  # Configures Iptable Defaults
  iptables -P INPUT DROP
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD DROP
  
  # Drops Spoofing attacks
  iptables -A INPUT -s 10.0.0.0/8 -j DROP
  iptables -A INPUT -s 169.254.0.0/16 -j DROP
  iptables -A INPUT -s 172.16.0.0/12 -j DROP
  iptables -A INPUT -s 127.0.0.0/8 -j DROP
  iptables -A INPUT -s 192.168.0.0/24 -j DROP
  iptables -A INPUT -s 224.0.0.0/4 -j DROP
  iptables -A INPUT -d 224.0.0.0/4 -j DROP
  iptables -A INPUT -s 240.0.0.0/5 -j DROP
  iptables -A INPUT -d 240.0.0.0/5 -j DROP
  iptables -A INPUT -s 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 0.0.0.0/8 -j DROP
  iptables -A INPUT -d 239.255.255.0/24 -j DROP
  iptables -A INPUT -d 255.255.255.255 -j DROP
  
  # Accepts loopback input
  iptables -A INPUT -i lo -p all -j ACCEPT
  
  # Allows a three-way Handshake
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  
  # Drops packets with excessive RST to avoid Masked attacks
  iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
  
  # Stops Masked Attacks
  iptables -A INPUT -p icmp --icmp-type 13 -j DROP
  iptables -A INPUT -p icmp --icmp-type 14 -j DROP
  iptables -A INPUT -p icmp --icmp-type 17 -j DROP
  iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
  
  # Discards Invalid Packets
  iptables -A INPUT -m state --state INVALID -j DROP
  iptables -A FORWARD -m state --state INVALID -j DROP
  iptables -A OUTPUT -m state --state INVALID -j DROP
  
  # Allows ssh
  iptables -A INPUT -p tcp -m tcp --dport 652 -j ACCEPT
   
   # Allow one ssh connection at a time
  iptables -A INPUT -p tcp --syn --dport 652 -m connlimit --connlimit-above 2 -j REJECT
  
  # Allows Ping
  iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
  
  # Protection against port scanning
  iptables -N port-scanning
  iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
  iptables -A port-scanning -j DROP
 
  # SSH brute-force protection
  iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
  iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
  
  # Syn-flood protection
  iptables -N syn_flood
  iptables -A INPUT -p tcp --syn -j syn_flood
  iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
  iptables -A syn_flood -j DROP
  iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
  iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-prefix PING-DROP:
  iptables -A INPUT -p icmp -j DROP
  iptables -A OUTPUT -p icmp -j ACCEPT
  
  # Mitigating SYN floods with SYNPROXY
  iptables -t raw -A PREROUTING -p tcp -m tcp --syn -j CT --notrack
  iptables -A INPUT -p tcp -m tcp -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
  iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
  
  # Block new packets that aren't SYN packets
  iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
  
  # Force fragments packets check
  iptables -A INPUT -f -j DROP
  
  # XMAS packets
  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  
  # Drop all null packets
  iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

  # Block uncommon MSS values
  iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP

  # Block packets with bogus TCP flags
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
  iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

  
  # Saves iptable configurations
  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
}
iptable_configuration
