#!/bin/bash
curl -s -X POST --unix-socket /run/hide.me/hide.me.sock http://localhost/configuration --data @$1