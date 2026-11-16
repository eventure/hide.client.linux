#!/bin/bash
if [[ ! -e "configuration.json" ]]; then
  echo "Fetch configuration with 'curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/configuration > configuration.json' and edit the Host attribute"
  exit 0
fi

printf "Send configuration: "
curl -s -X POST --unix-socket /run/hide.me/hide.me.sock http://localhost/configuration --data @configuration.json
printf "\nState: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/state

printf "\nRoute: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/route
printf "\nState: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/state

printf "\nConnect: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/connect
printf "\nState: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/state

printf "\nSleep for 5 seconds"
sleep 5

printf "\nDisconnect: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/disconnect
printf "\nState: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/state

printf "\nDestroy: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/destroy
printf "\nState: "
curl -s --unix-socket /run/hide.me/hide.me.sock http://localhost/state
printf "\n"