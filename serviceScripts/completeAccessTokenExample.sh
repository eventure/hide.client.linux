#!/bin/bash
if [[ ! -e "configuration.json" ]]; then
  echo "Fetch configuration with 'curl -s --abstract-unix-socket hide.me http://localhost/configuration > configuration.json' and edit the Host,Username and Password attributes"
  exit 0
fi
printf "Send configuration: "
curl -s -X POST --abstract-unix-socket hide.me http://localhost/configuration --data @configuration.json
printf "\n"
curl -s --abstract-unix-socket hide.me http://localhost/token
printf "\n"