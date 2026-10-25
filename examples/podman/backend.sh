#!/bin/sh
set -eu

mkdir -p /www /home/demo/.ssh /run/sshd
printf 'srp %s\n' "$BACKEND_NAME" > /www/index.html
cp /www/index.html /etc/srp-example-name
cp /run/example/id_ed25519.pub /home/demo/.ssh/authorized_keys
chown -R demo:demo /home/demo/.ssh
chmod 700 /home/demo/.ssh
chmod 600 /home/demo/.ssh/authorized_keys
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
fi
busybox-extras httpd -p 8080 -h /www
exec /usr/sbin/sshd -D -e
