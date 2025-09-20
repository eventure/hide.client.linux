#!/bin/ash
# Disables and removes the wireguard network interface created by the hide.me-connect.ash script, restores the resolv.conf,
# and immediately signals the hide.me VPN server to invalidate the session so it no longer counts againt the device limit.
# Dev Note: The SessionKey must be set in the wireguard config file as a specially formatted comment by the connect script.
#
# Args:
#   None
# Env:
#   HIDE_ME_CONF_PATH: Optional. The folder the generated wireguard config was stored in. Must match with the connect script. Default=/tmp
#   HIDE_ME_DEV_NAME: Optional. Name of the wireguard interface. Must match with teh connect script. Default=hide.me
# example:
# HIDE_ME_DEV_NAME="hide.me" HIDE_ME_CONF_PATH="/tmp" ./hide.me-disconnect.ash

if [[ -z "${HIDE_ME_CONF_PATH}" ]]; then HIDE_ME_CONF_PATH="/tmp"; fi
if [[ -z "${HIDE_ME_DEV_NAME}" ]]; then HIDE_ME_DEV_NAME="hide.me"; fi

function checkTools() {
    which curl > /dev/null
    if [[ $? == 1 ]]; then echo "Need cURL"; exit 1; fi
}

function disconnect() {
    # Deleting the interface automatically removes the associated routes/wireguard configs
    echo "Removing interface ${HIDE_ME_DEV_NAME}"
    ip link delete ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip link delete ${HIDE_ME_DEV_NAME}"; exit 1; fi

    # Get the session token from ${HIDE_ME_CONF_PATH}/hide.me-wireguard-${HIDE_ME_DEV_NAME}
    setConfFile="${HIDE_ME_CONF_PATH}/hide.me-wireguard-${HIDE_ME_DEV_NAME}"
    if [[ ! -e "${setConfFile}" ]]; then echo "[FAIL] Configuration file at ${setConfFile} does not exist"; exit 1; fi
    serverIP=$(grep "Endpoint = " "${setConfFile}" | cut -d " " -f 3 | cut -d ":" -f 1 )
    sessionToken=$(grep "# SessionToken = " "${setConfFile}" | cut -d " " -f 4 )
    rm -f "${setConfFile}"

    # Remove the host route towards the server
    ip route del ${serverIP}
    if [[ $? != 0 ]]; then echo "[FAIL] ip route del ${serverIP}"; exit 1; fi

    # Restore resolv.conf
    cat "${HIDE_ME_CONF_PATH}/hide.me-resolv.conf-backup" > /etc/resolv.conf
    rm -f "${HIDE_ME_CONF_PATH}/hide.me-resolv.conf-backup"

    # Invoke the disconnect method
    HIDE_ME_SERVER=${serverIP//./-}
    HIDE_ME_SERVER=${HIDE_ME_SERVER//:/-}
    url="https://${HIDE_ME_SERVER}.hideservers.net:432/v1.0.0/disconnect"
    data='{
      "domain":"hide.me",
      "host":"'${HIDE_ME_SERVER}'",
      "sessionToken":"'${sessionToken}'"
    }'
    echo "Invoking ${url}"
    jsonConf=$(curl --cacert CA.pem -s -f -X POST --data-binary "${data}" "${url}")
    returnValue=$?
    if [[ ${returnValue} != 0 ]]; then echo "cURL failed with "${returnValue}; exit 1; fi
}

checkTools
disconnect
