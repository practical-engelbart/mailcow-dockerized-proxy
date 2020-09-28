# mailcow-dockerized-proxy

Proxy Setup for Mailcow.  
The script is designed to be copy and pasted during the cloud vpc deployment.
It will setup the recommeded docker environment settings, 
install usbguard, created docker auditd rules and deploy apparmor as well as harden ssh, etc.

The ipv4.conf and ipv6.conf are easy to deploy, simply edit and copy them over then run:

sudo iptables-restore -n ipv4.conf
sudo ip6tables-restore -n ipv6.conf
sudo apt install iptables-persistent
