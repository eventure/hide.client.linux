#!/bin/ash
# Contacts a hide.me VPN server and authenticates with user credentials to generate an access token.
# This access token is relatively long-lived and may be reused across multiple connect-disconnect cycles.
# Args:
#   None
# Env:
#   HIDE_ME_USERNAME: Required. The user's username
#   HIDE_ME_PASSWORD: Required. The user's password
#   HIDE_ME_TOKEN_FILE: Optional. The file to write the base64 encoded access token to. Default=stdout
#   HIDE_ME_SERVER: Optional. The subdomain of hideservers.net to use. Access tokens from any server can be used when connecting to
#                   any other server. Default=any
# example usage:
# HIDE_ME_SERVER="any" HIDE_ME_USERNAME="myUsername" HIDE_ME_PASSWORD="myPassword" HIDE_ME_TOKEN_FILE=accessToken.txt ./hide.me-accessToken.ash

# All the variables should be passed through the environment
if [[ -z "${HIDE_ME_SERVER}" ]]; then HIDE_ME_SERVER="any"; fi
if [[ -z "${HIDE_ME_USERNAME}" ]]; then echo "Missing username in the environment "; exit 1; fi
if [[ -z "${HIDE_ME_PASSWORD}" ]]; then echo "Missing password in the environment "; exit 1; fi

if ! command -v curl &>/dev/null; then echo "Missing tool: cURL"; exit 1; fi

url='https:/'${HIDE_ME_SERVER}'.hideservers.net:432/v1.0.0/accessToken'

data="{"
data=${data}'"domain":"hide.me",'
data=${data}'"host":"",'
data=${data}'"username":"'${HIDE_ME_USERNAME}'",'
data=${data}'"password":"'${HIDE_ME_PASSWORD}'"'
data=${data}"}"

# Fetch the token
echo "Invoking ${url}"
accessToken=$(curl -s -f --cacert CA.pem -X POST --data-binary ${data} ${url})
if [[ $? == "22" ]]; then echo "Token fetch failed"; exit 1; fi

accessToken=${accessToken//"\""/}

if [[ -z "${HIDE_ME_TOKEN_FILE}" ]]; then
	echo ${accessToken}
else
	echo ${accessToken} > ${HIDE_ME_TOKEN_FILE}
	echo "Access-Token stored in ${HIDE_ME_TOKEN_FILE}"
fi
