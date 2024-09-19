#!/bin/bash
if [[ ! -e "configuration.json" ]]; then
  echo "Fetch configuration with 'curl -s --abstract-unix-socket hide.me http://localhost/configuration > configuration.json' and edit the Host attribute"
  exit 0
fi

printf "Send configuration: "
curl -s -X POST --abstract-unix-socket hide.me http://localhost/configuration --data @configuration.json
printf "\nState: "
curl -s --abstract-unix-socket hide.me http://localhost/state

printf "\nRoute: "
curl -s --abstract-unix-socket hide.me http://localhost/route
printf "\nState: "
curl -s --abstract-unix-socket hide.me http://localhost/state

printf "\nConnect: "
curl -s --abstract-unix-socket hide.me http://localhost/connect
printf "\nState: "
curl -s --abstract-unix-socket hide.me http://localhost/state

printf "\nSleep for 5 seconds"
sleep 5

printf "\nDisconnect: "
curl -s --abstract-unix-socket hide.me http://localhost/disconnect
printf "\nState: "
curl -s --abstract-unix-socket hide.me http://localhost/state

printf "\nDestroy: "
curl -s --abstract-unix-socket hide.me http://localhost/destroy
printf "\nState: "
curl -s --abstract-unix-socket hide.me http://localhost/state
printf "\n"