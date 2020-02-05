#!/bin/bash

# NAME: anonymizer.sh                                                          #
# DESCRIPTION: Transparently routing traffic through Tor                       #
# VERSION: 0.1.0                                                               #
# AUTHOR: netico <netico@riseup.net>                                           #
# ---------------------------------------------------------------------------- #
# This code is free software; you can redistribute it and/or modify it under   #
# the terms of the GNU General Public License version 3 only, as published by  #
# the Free Software Foundation.                                                #
# This code is distributed in the hope that it will be useful, but WITHOUT ANY #
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS    #
# FOR A PARTICULAR PURPOSE.                                                    #

# DOCUMENTATION -------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
# https://www.torproject.org/                                                  #
# https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy           #
# https://www.netfilter.org/projects/iptables/index.html                       #
#                                                                              #
# To enable the transparent proxy and the DNS proxy add the following lines to #
# /etc/tor/torrc:                                                              #
#                                                                              #
# VirtualAddrNetworkIPv4 10.192.0.0/10                                         #
# AutomapHostsOnResolve 1                                                      #
# TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr \     #
#	IsolateDestPort                                                        #
# DNSPort 5353                                                                 #
#                                                                              #
# Configure your system's DNS resolver to use Tor's DNSPort on the loopback    #
# interface by modifying /etc/resolv.conf:                                     #
#                                                                              #
# nameserver 127.0.0.1                                                         #

# CONFIGURATION -------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
INTERFACE=enp7s0
TOR_UID=112
TOR_PORT=9040
TOR_DNS_PORT=5353
VIRTUAL_ADDRESS="10.192.0.0/10"
IPTABLES=$(which iptables)

# FUNCTIONS ------------------------------------------------------------------ #
# ---------------------------------------------------------------------------- #
reset_iptables () {	
	echo "Resetting iptables rules"

	# Reset policies	
	$IPTABLES -P INPUT ACCEPT
	$IPTABLES -P FORWARD ACCEPT
	$IPTABLES -P OUTPUT ACCEPT
	$IPTABLES -t nat -P PREROUTING ACCEPT
	$IPTABLES -t nat -P POSTROUTING ACCEPT
	$IPTABLES -t nat -P OUTPUT ACCEPT
	$IPTABLES -t mangle -P PREROUTING ACCEPT
	$IPTABLES -t mangle -P OUTPUT ACCEPT

	# Flush rules and erase non default chains
	$IPTABLES -F
	$IPTABLES -X
	$IPTABLES -t nat -F
	$IPTABLES -t nat -X
	$IPTABLES -t mangle -F
	$IPTABLES -t mangle -X	
}

transparent_proxy () {
	echo "Adding iptables rules for interface $INTERFACE"

	# *nat OUTPUT (local redirection)
	# .onion addresses
	$IPTABLES -t nat -A OUTPUT -d $VIRTUAL_ADDRESS -p tcp -m tcp \
		--tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $TOR_PORT

	# DNS requests to Tor
	$IPTABLES -t nat -A OUTPUT -d 127.0.0.1/32 -p udp -m udp \
		--dport 53 -j REDIRECT --to-ports $TOR_DNS_PORT

	# Don't nat the Tor process and the loopback interface
	$IPTABLES -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
	$IPTABLES -t nat -A OUTPUT -o lo -j RETURN

	# Redirect all other to Tor's TransPort
	$IPTABLES -t nat -A OUTPUT -p tcp -m tcp \
		--tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $TOR_PORT
	
	# *filter INPUT	
	$IPTABLES -A INPUT -m state --state ESTABLISHED -j ACCEPT
	$IPTABLES -A INPUT -i lo -j ACCEPT
	$IPTABLES -A INPUT -j DROP

	# *filter FORWARD
	$IPTABLES -A FORWARD -j DROP

	# *filter OUTPUT
	$IPTABLES -A OUTPUT -m state --state INVALID -j DROP
	$IPTABLES -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

	# Allow Tor process output
	$IPTABLES -A OUTPUT -o $INTERFACE -m owner --uid-owner $TOR_UID \
		-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state \
		--state NEW -j ACCEPT

	# Allow loopback output
	$IPTABLES -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

	# Tor transproxy magic
	$IPTABLES -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $TOR_PORT \
		--tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

	# Log & Drop everything else
	$IPTABLES -A OUTPUT -j LOG \
		--log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
	$IPTABLES -A OUTPUT -j DROP

	# Set default policies to DROP
	$IPTABLES -P INPUT DROP
	$IPTABLES -P FORWARD DROP
	$IPTABLES -P OUTPUT DROP
}

# MAIN ----------------------------------------------------------------------- #
# ---------------------------------------------------------------------------- #
if [ $USER != 'root' ]
then
	echo "Must be root for run this script! Bye."
	exit 99
fi

case "$1" in
	start)
	 	echo -n "Starting tor service..."
		service tor start && echo "Done!"
		;;
	stop)
	 	echo -n "Stopping tor service..."
		service tor stop && echo "Done!"
		;;
	restart)
	 	echo -n "Restarting tor service..."
		service tor restart && echo "Done!"
		;;
	status)
		service tor status &
		;;
	reset)
		reset_iptables
		;;
	proxy)
		$0 reset
		$0 restart
		transparent_proxy
		;;
	log)
		tail -20 /var/log/tor/notices.log
		;;
	*)	
		echo "Usage: $0 {start|stop|status|restart|reset|proxy|log}"
		exit 2
		;;
esac
exit 0
