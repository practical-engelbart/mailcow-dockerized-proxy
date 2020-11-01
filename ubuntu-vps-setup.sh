#!/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Setting umask
echo "umask 027" >> /etc/profile

rm /etc/cron.deny 2> /dev/null
rm /etc/at.deny 2> /dev/null
echo 'root' > /etc/cron.allow
echo 'root' > /etc/at.allow
chown root:root /etc/cron*
chown root:root /etc/at*

echo 'sshd : ALL : ALLOW' > /etc/hosts.allow
echo 'ALL: LOCAL, 127.0.0.1' >> /etc/hosts.allow
echo 'ALL: PARANOID' > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny

# update fstab PID 2
echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab

# Harden Sysctl
cat <<-EOF > /etc/sysctl.d/20-sysctl.conf
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.panic = 60
kernel.panic_on_oops = 60
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
net.ipv4.conf.wg0.forwarding = 1
net.ipv4.conf.wg0.accept_source_route = 1
net.ipv4.conf.wg0.secure_redirects = 1
net.ipv4.conf.wg0.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter= 1
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_challenge_ack_limit = 1000000
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.use_tempaddr = 1
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.default.autoconf = 1
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 1
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.ens3.accept_ra_rtr_pref = 2
net.ipv6.conf.ens3.accept_ra = 2
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_loose = 0
vm.swappiness = 0
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_syncookies = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF

cat <<-EOF > /etc/sysctl.d/10-bridge.conf
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF

# Backup SSH_CONFIG
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Harden SSH Settings
cat <<-EOF > /etc/ssh/sshd_config
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
AcceptEnv LANG LC_*
AllowGroups root sudo
Banner /etc/issue.net
ChallengeResponseAuthentication no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
ClientAliveCountMax 0
ClientAliveInterval 300
Compression no
HostbasedAuthentication no
IgnoreUserKnownHosts yes
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256                                                                                                                                
LoginGraceTime 20
LogLevel VERBOSE
Macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
MaxAuthTries 3
MaxSessions 3
MaxStartups 10:30:60
PermitEmptyPasswords no
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication no
PermitUserEnvironment no
PrintLastLog yes
PrintMotd no
StrictModes yes
Subsystem sftp internal-sftp
UseDNS no
UsePAM yes
X11Forwarding no
AllowTcpForwarding yes
EOF

# Disable unattended-upgrades to prevent it from holding the dpkg frontend lock
sudo systemctl disable unattended-upgrades.service
sudo systemctl stop unattended-upgrades.service

echo "Provision a new server"
sudo apt-get update
sudo apt-get install -y --allow-downgrades \
    curl jq apt-transport-https htop bmon \
    debhelper ccze debsums \
    ca-certificates libelf-dev \
    software-properties-common \
    dh-golang devscripts fakeroot \
    dh-make libmnl-dev git \
    libdistro-info-perl libssl-dev \
    dh-systemd build-essential \
    gcc make git-buildpackage \
    pkg-config bison flex \
    zip g++ zlib1g-dev unzip python \
    libtool cmake coreutils m4 automake \
    libprotobuf-dev libyaml-cpp-dev \
    socat pv tmux bc gcc-multilib binutils-dev \
    binutils wget rsync ifupdown \
    python3-sphinx python3-pip \
    libncurses5-dev libslang2-dev gettext \
    libselinux1-dev debhelper lsb-release \
    po-debconf autoconf autopoint moreutils \
    libseccomp2 libenchant1c2a ninja-build \
    golang-cfssl ntp apparmor apparmor-profiles \
    apparmor-utils apparmor-easyprof auditd usbguard haveged \
    libpam-tmpdir libpam-apparmor libpam-cracklib \
    libpam-cgroup tree neofetch dbconfig-common \
    libnss3-tools conntrack iproute2 ipvsadm \
    iputils-arping iputils-clockdiff iputils-ping \
    iputils-tracepath iproute2 traceroute tcptraceroute \
    gnupg2 net-tools
    
# Setup Auditd Rules    
cat <<-EOF > /etc/audit/rules.d/docker.rules
# Remove any existing rules
-D
# Buffer Size
-b 8192
# Ignore errors
-i
# Failure Mode
-f 1
# Audit the audit logs
-w /var/log/audit/ -k auditlog
# Auditd configuration
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
# Monitor for use of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
# Monitor AppArmor configuration changes
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
# Monitor usage of AppArmor tools
-w /sbin/apparmor_parser -p x -k apparmor_tools
-w /usr/sbin/aa-complain -p x -k apparmor_tools
-w /usr/sbin/aa-disable -p x -k apparmor_tools
-w /usr/sbin/aa-enforce -p x -k apparmor_tools
# Monitor Systemd configuration changes
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd
# Monitor usage of systemd tools
-w /bin/systemctl -p x -k systemd_tools
-w /bin/journalctl -p x -k systemd_tools
# Special files
-a always,exit -F arch=x86_64 -S mknod -S mknodat -k specialfiles
-a always,exit -F arch=b32 -S mknod -S mknodat -k specialfiles
# Mount operations
-a always,exit -F arch=x86_64 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -F key=export
# Changes to the time
-a always,exit -F arch=x86_64 -S settimeofday -k audit_time_rules
-a always,exit -F arch=x86_64 -S adjtimex -k audit_time_rules
-a always,exit -F arch=x86_64 -S clock_settime -k audit_time_rules
-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules
-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules
# Cron configuration & scheduled jobs
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/crontabs/ -k cron
# User, group, password databases
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification
# MAC-policy
-w /etc/selinux/ -p wa -k MAC-policy
# Monitor usage of passwd
-w /usr/bin/passwd -p x -k passwd_modification
# Monitor for use of tools to change group identifiers
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
# Monitor module tools
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
# Login configuration and information
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/run/faillock/ -p wa -k logins
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
# Network configuration
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/network/ -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
# System startup scripts
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
# Library search paths
-w /etc/ld.so.conf -p wa -k libpath
# Local time zone
-w /etc/localtime -p wa -k localtime
# Time zone configuration
-w /etc/timezone -p wa -k audit_time_ruleszone
# Kernel parameters
-w /etc/sysctl.conf -p wa -k sysctl
# Modprobe configuration
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/modprobe.d/ -p wa -k modprobe
-w /etc/modules -p wa -k modprobe
# Module manipulations
-a always,exit -F arch=x86_64 -S init_module -S delete_module -F key=modules
-a always,exit -F arch=x86_64 -S init_module -F key=modules
-a always,exit -F arch=b32 -S init_module -S delete_module -F key=modules
-a always,exit -F arch=b32 -S init_module -F key=modules
# PAM configuration
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam
# Postfix configuration
-w /etc/aliases -p wa -k mail
-w /etc/postfix/ -p wa -k mail
# SSH configuration
-w /etc/ssh/sshd_config -k sshd
# Changes to hostname
-a always,exit -F arch=x86_64 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
# Changes to issue
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
# Capture all unauthorized file accesses
-a always,exit -F arch=x86_64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=x86_64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access
# Monitor for use of process ID change (switching accounts) applications
-w /bin/su -p x -k actions
-w /usr/bin/sudo -p x -k actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d -p wa -k actions
# Make the configuration immutable
-e 2
EOF

# Load IPTables Modules
cat <<-EOF > /etc/modules-load.d/firewall.conf
overlay
br_netfilter
ip_vs
ip_vs_rr
ip_vs_wrr
ip_vs_sh
nf_conntrack
iptable_nat
iptable_filter
iptable_mangle
EOF

cd /tmp
wget https://dl.google.com/go/go1.15.2.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz
echo 'export GOPATH=$HOME/go' >> /etc/profile
echo 'export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin' >> /etc/profile

export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

## Optional Either Cloudflare DNS-over-TLS or DNSCrypt-Proxy
cd /opt
git clone https://github.com/DNSCrypt/dnscrypt-proxy.git
mkdir /etc/dnscrypt-proxy/
cp /opt/dnscrypt-proxy/dnscrypt-proxy/example-dnscrypt-proxy.toml /etc/dnscrypt-proxy/dnscrypt-proxy.toml
cp -r /opt/dnscrypt-proxy/utils/generate-domains-blocklists/ /etc/dnscrypt-proxy/utils


# Setting up USBGuard
usbguard generate-policy > /tmp/rules.conf
install -m 0600 -o root -g root /tmp/rules.conf /etc/usbguard/rules.conf
# Enforce apparmor profiles
echo 'session optional pam_apparmor.so order=user,group,default' > /etc/pam.d/apparmor

timedatectl set-ntp true
timedatectl set-timezone America/Los_Angeles
echo 'servers=0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org' >> /etc/systemd/timesyncd.conf

mkdir -p /usr/local/etc/cloudflared/
cat << EOF > /usr/local/etc/cloudflared/config.yml
proxy-dns: true
proxy-dns-upstream:
 - https://1.1.1.1/dns-query
 - https://1.0.0.1/dns-query
EOF

cd /tmp
wget https://github.com/cloudflare/cloudflared/releases/download/2020.8.0/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
ln -s /usr/bin/cloudflared /usr/local/bin/cloudflared

touch /usr/local/etc/cloudflared/.installedFromPackageManager || true

systemctl disable systemd-resolved.service
service systemd-resolved stop

unlink /etc/resolv.conf || true

sudo tee /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
EOF

# CoreDumps https://github.com/cilium/cilium/issues/3399
systemctl disable apport.service
sh -c 'echo "sysctl kernel.core_pattern=/tmp/core.%e.%p.%t" > /etc/sysctl.d/66-core-pattern.conf'

# journald configuration
bash -c "echo RateLimitIntervalSec=1s >> /etc/systemd/journald.conf"
bash -c "echo RateLimitBurst=10000 >> /etc/systemd/journald.conf"
systemctl restart systemd-journald

# Kernel parameters
sh -c 'echo "kernel.randomize_va_space=0" > /etc/sysctl.d/67-randomize_va_space.conf'

# Setup Docker
# Add Docker's official GPG key:
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
apt-get update && apt-get install -y apt-transport-https ca-certificates curl software-properties-common gnupg2
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update && apt-get install -y containerd.io=1.2.13-2 docker-ce=5:19.03.11~3-0~ubuntu-$(lsb_release -cs) docker-ce-cli=5:19.03.11~3-0~ubuntu-$(lsb_release -cs)                                                                     

cat > /etc/docker/daemon.json <<EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "dns": ["1.1.1.1", "1.0.0.1"]
}
EOF

mkdir -p /etc/systemd/system/docker.service.d
mkdir -p /etc/docker/ssl
mkdir -p /etc/docker/certs.d/peer
mkdir -p /etc/docker/certs.d/client
echo 'GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"' >> /etc/default/grub
echo 'export DOCKER_HOST=tcp://127.0.0.1:2376' >> /etc/profile
echo 'export DOCKER_TLS_VERIFY=1' >> /etc/profile
echo 'export DOCKER_CERT_PATH=$HOME/.docker/' >> /etc/profile
# CFSSL Setup for mTLS on Docker Socket
mkdir -p /etc/cfssl/cacert
cat > /etc/cfssl/cacert/config.json <<EOF
{
    "signing": {
        "default": {
            "expiry": "43800h"
        },
        "profiles": {
            "server": {
                "expiry": "43800h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            },
            "client": {
                "expiry": "43800h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "client auth"
                ]
            },
            "peer": {
                "expiry": "43800h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            }
        }
    }
}
EOF
cat > /etc/cfssl/cacert/ca-csr.json <<EOF
{
  "CN": "Docker Internal CA",
  "key": {
    "algo": "ecdsa",
    "size": 521
  },
  "names": [
    {
      "C": "US",
      "L": "CA",
      "O": "Docker Host",
      "ST": "Los Angeles",
      "OU": "Docker Internal CA"
    }
  ]
}
EOF
cat > /etc/cfssl/cacert/server.json <<EOF
{
  "CN": "server",
  "hosts": [
    "172.17.0.1",
    "172.22.1.1",
    "fd4d:6169:6c63:6f77::1",
    "127.0.0.1",
    "127.0.1.1",
    "::1",
    "ip6-localhost",
    "localhost",
    "localhost.localdomain"
  ],
  "key": {
    "algo": "ecdsa",
    "size": 521
  },
  "names": [
    {
      "C": "US",
      "L": "CA",
      "O": "Docker Host",
      "ST": "Los Angeles",
      "OU": "Server"
    }
  ]
}
EOF
cat > /etc/cfssl/cacert/client.json <<EOF
{
  "CN": "client",
  "hosts": [
    ""
  ],
  "key": {
    "algo": "ecdsa",
    "size": 521
  },
  "names": [
    {
      "C": "US",
      "L": "CA",
      "O": "Docker Host",
      "ST": "Los Angeles",
      "OU": "Client"

    }
  ]
}
EOF
cat > /etc/cfssl/cacert/peer.json <<EOF
{
  "CN": "peer",
  "hosts": [
    "172.17.0.1",
    "172.22.1.1",
    "fd4d:6169:6c63:6f77::1",
    "127.0.0.1",
    "127.0.1.1",
    "::1",
    "ip6-localhost",
    "localhost",
    "localhost.localdomain"
  ],
  "key": {
    "algo": "ecdsa",
    "size": 521
  },
  "names": [
    {
      "C": "US",
      "L": "CA",
      "O": "Docker Host",
      "ST": "Los Angeles",
      "OU": "Peer"
    }
  ]
}
EOF
cd /etc/cfssl/cacert
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=server server.json | cfssljson -bare server
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=peer peer.json | cfssljson -bare peer
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=config.json -profile=client client.json | cfssljson -bare client
mkdir -p /root/.docker
cp /etc/cfssl/cacert/ca.pem /usr/local/share/ca-certificates/ca.pem
cp /etc/cfssl/cacert/ca.pem /root/.docker/ca.pem
cp /etc/cfssl/cacert/client.pem /root/.docker/cert.pem
cp /etc/cfssl/cacert/client-key.pem /root/.docker/key.pem
cp /etc/cfssl/cacert/server.pem /etc/docker/ssl/server.pem
cp /etc/cfssl/cacert/server-key.pem /etc/docker/ssl/server-key.pem
cp /etc/cfssl/cacert/ca.pem /etc/docker/ssl/ca.pem
cp /etc/cfssl/cacert/ca.pem /etc/docker/certs.d/peer/ca.pem
cp /etc/cfssl/cacert/ca.pem /etc/docker/certs.d/client/ca.pem
mv /etc/cfssl/cacert/client.pem /etc/docker/certs.d/client/cert.pem
mv /etc/cfssl/cacert/client-key.pem /etc/docker/certs.d/client/key.pem
mv /etc/cfssl/cacert/peer.pem /etc/docker/certs.d/peer/cert.pem
mv /etc/cfssl/cacert/peer-key.pem /etc/docker/certs.d/peer/key.pem
mv /etc/cfssl/cacert/ca.pem /etc/ssl/certs/ca.pem
mv /etc/cfssl/cacert/ca-key.pem /etc/ssl/private/ca-key.pem
mv /usr/local/share/ca-certificates/ca.pem /usr/local/share/ca-certificates/dockerCA.crt
chmod 600 /root/.docker/
chmod 700 /etc/docker/ssl/
chmod 600 /etc/docker/ssl/server-key.pem
chmod 700 /etc/docker/certs.d/
chmod 600 /etc/docker/certs.d/peer/key.pem
chmod 600 /etc/docker/certs.d/client/key.pem
chmod 600 /etc/ssl/private/

curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

cat > /etc/systemd/system/docker.service.d/override.conf <<EOF
[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.io

[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:2376 --tlsverify --tlscacert /etc/docker/ssl/ca.pem --tlscert /etc/docker/ssl/server.pem --tlskey /etc/docker/ssl/server-key.pem -H unix:///var/run/docker.sock
 
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl enable auditd
systemctl enable apparmor
systemctl enable haveged
systemctl enable docker
systemctl enable unattended-upgrades
update-grub
update-ca-certificates

