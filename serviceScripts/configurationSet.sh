#!/bin/bash
curl -s -X POST --abstract-unix-socket hide.me http://localhost/configuration --data @$1