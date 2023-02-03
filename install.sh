#!/bin/sh

# Check privileges
if [ $(id -u) != 0 ]; then
    echo "$0 must be run as root, try sudo $0"
    exit
fi

# Create hide.me directory
mkdir -p /opt/hide.me/
cp hide.me CA.pem hide.me@.service config /opt/hide.me
chmod +x /opt/hide.me/hide.me
touch /opt/hide.me/config
echo "Binary, CA certificate, SystemD service and config file installed in /opt/hide.me"

# Check for the token
if [ ! -f /opt/hide.me/accessToken.txt ]; then
    echo "Hide.me CLI needs to fetch a token. Please, provide your hide.me credentials"
    cd /opt/hide.me
    ./hide.me token free.hideservers.net
else
    echo "Reusing token in /opt/hide.me/accessToken.txt"
fi

# Check for systemctl
_=$(which systemctl)
if [ $? -eq 0 ]; then
    echo "Using SystemD"
    systemctl link /opt/hide.me/hide.me@.service
    echo "In order to set up and start a connection execute:"
    echo "  systemctl enable hide.me@SERVER"
    echo "  systemctl start hide.me@SERVER"
    echo "Where SERVER is a server name ( e.g. amsterdam-1 ) or a region ( e.g. nl )"
fi

echo "Finished"