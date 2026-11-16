#!/bin/bash
if [[ ! -e "configuration.json" ]]; then
  echo "Fetch configuration with 'curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/configuration > configuration.json' and edit the Host,Username and Password attributes"
  exit 0
fi
printf "Send configuration: "
curl -s -X POST --unix-socket /run/hide.me/hide.me.sock http://localhost/configuration --data @configuration.json
printf "\n"
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/token
printf "\n"