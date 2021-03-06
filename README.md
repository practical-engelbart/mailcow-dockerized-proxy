# mailcow-dockerized-proxy

Proxy Setup for Mailcow. Includes a simple and tested VPS deploy script that I use. The script will install and configure Golang-go, Docker CE and docker-compose, harden the VPS including deploying mtls certiciates using cfssl to protect the Docker Socket, setup Auditd, Apparmor, USB Guard, and harden SSH.

## Usage

Deploy a new VPS on either Vultr.com or Digital Ocean, select Ubuntu 20.0.4 LTS, choose IPv6 and User Data. Edit and copy the vps script.  Digital Ocean uses VPC private addresses and the NIC will be eth0 and eth1, while Vultr uses ens3.  Log into the new VPS and create a new user and add the user to the docker group and setup SSH keys for the new user.  Make sure to copy the /root/.docker to $HOME/.docker for the new user.

## Advanced configuration

To setup the two iptables files simply use the following commands:

```
iptables-restore -n $HOME/mailcow-dockerized-proxy/iptables/rules4.conf
ip6tables-restore -n $HOME/mailcow-dockerized-proxy/iptables/rules6.conf

iptables-save
ip6tables-save

apt install iptables-persistent
```
