# mailcow-dockerized-proxy

Proxy Setup for Mailcow. Includes a simple and tested VPS deploy script that I use. The script will install and configure Golang-go, Docker CE and docker-compose, harden the VPS including deploying mtls certiciates using cfssl to protect the Docker Socket, setup Auditd, Apparmor, USB Guard, and harden SSH.

## Usage

Deploy a new VPS on either Vultr.com or Digital Ocean, select Ubuntu 20.0.4 LTS, choose IPv6 and User Data. Edit and copy the vps script.  Digital Ocean uses VPC private addresses and the NIC will be eth0 and eth1, while Vultr uses ens3.  Log into the new VPS and create a new user and add the user to the docker group and setup SSH keys for the new user.  Make sure to copy the /root/.docker to $HOME/.docker for the new user.

## Advanced configuration

To setup the two iptables files simply use the following commands (Remember to edit the rules to your environment first):

```bash
sudo iptables-restore -n $HOME/mailcow-dockerized-proxy/iptables/rules4.conf
sudo ip6tables-restore -n $HOME/mailcow-dockerized-proxy/iptables/rules6.conf

sudo iptables-save
sudo ip6tables-save

sudo apt install iptables-persistent
```

## Letsencrypt 

Setup Letsencrypt and add the following to /etc/crontab.

```nano
00 21   16 *  * root    /usr/bin/certbot renew --agree-tos --email letsencrypt@example.com -n -c /etc/letsencrypt/cli.ini --deploy-hook /etc/letsencrypt/renewal-hooks/post/nginx-reload.sh
```

Example renewal script and configurations.

```bash
sudo nano /etc/letsencrypt/cli.ini

max-log-backups = 0
email = <your_email>
domains = email.example.com, autodiscover.example.com, autoconfig.example.com, webmail.example.com, matrix.example.com, im.example.com, *.im.example.com 
non-interactive = True
staple-ocsp = True
rsa-key-size = 4096
webroot-path = /var/lib/letsencrypt/
agree-tos = True
```

Example renewal-hooks.

```bash
sudo nano /etc/letsencrypt/renewal-hooks/post/nginx-reload.sh

#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

cp /etc/letsencrypt/live/email.example.com/fullchain.pem /opt/mailcow-dockerized/data/assets/ssl/cert.pem
cp /etc/letsencrypt/live/email.example.com/privkey.pem /opt/mailcow-dockerized/data/assets/ssl/key.pem

/usr/sbin/nginx -t && systemctl reload nginx
```

