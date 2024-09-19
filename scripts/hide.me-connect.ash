#!/bin/ash
# example usage:
# HIDE_ME_DEV_NAME="hide.me" HIDE_ME_SERVER="any" HIDE_ME_CONF_PATH="/tmp" HIDE_ME_TOKEN_FILE="accessToken.txt" ./hide.me-connect.ash

if [[ -z "${HIDE_ME_SERVER}" ]]; then echo "Missing server name"; exit 1; fi
if [[ -z "${HIDE_ME_CONF_PATH}" ]]; then HIDE_ME_CONF_PATH="/tmp"; fi
if [[ -z "${HIDE_ME_TOKEN_FILE}" ]]; then HIDE_ME_TOKEN_FILE="accessToken.txt"; fi
if [[ -z "${HIDE_ME_DEV_NAME}" ]]; then HIDE_ME_DEV_NAME="hide.me"; fi

function checkTools() {
    which curl > /dev/null
    if [[ $? == 1 ]]; then echo "Need cURL"; exit 1; fi
    which wg > /dev/null
    if [[ $? == 1 ]]; then echo "Need wg"; exit 1; fi
    which jq > /dev/null
    if [[ $? == 1 ]]; then echo "Need jq"; exit 1; fi
}

function generateKeys() {
    privateKey=$(wg genkey)
    pubKey=$(printf "${privateKey}" | wg pubkey)
}

function connect() {
    serverIP=$(dig -t A ${HIDE_ME_SERVER}.hideservers.net +short)
    serverEndpoint=${serverIP}":432"
    echo "Resolved "${HIDE_ME_SERVER}" to "${serverIP}
    url="https://${HIDE_ME_SERVER}.hideservers.net:432/v1.0.0/connect"
    accessToken=$(cat ${HIDE_ME_TOKEN_FILE})
    data='{
      "domain":"hide.me",
      "host":"'${HIDE_ME_SERVER}'",
      "accessToken":"'${accessToken}'",
      "publicKey":"'${pubKey}'"
    }'
    echo "Invoking ${url}"
    jsonConf=$(curl --connect-to ${HIDE_ME_SERVER}.hideservers.net:432:${serverIP}:432 --cacert CA.pem -s -f -X POST --data-binary "${data}" "${url}")
    returnValue=$?
    if [[ ${returnValue} != 0 ]]; then echo "cURL failed with "${returnValue}; exit 1; fi
    if [[ ${#jsonConf} == 0 ]]; then echo "Authentication failed"; exit 1; fi

    serverPublicKey=$(echo "${jsonConf}" | jq -r '.publicKey')
    presharedKey=$(echo "${jsonConf}" | jq -r '.presharedKey')
    persistentKeepalive=$(echo "${jsonConf}" | jq -r '(.persistentKeepalive/1000000000)')
    allowedIp1=$(echo "${jsonConf}" | jq -r '(.allowedIps[0])')
    allowedIp2=$(echo "${jsonConf}" | jq -r '(.allowedIps[1])')
    dnsIp1=$(echo "${jsonConf}" | jq -r '(.DNS[0])')
    dnsIp2=$(echo "${jsonConf}" | jq -r '(.DNS[1])')
    gatewayIp1=$(echo "${jsonConf}" | jq -r '(.gateway[0])')
    gatewayIp2=$(echo "${jsonConf}" | jq -r '(.gateway[1])')
    sessionToken=$(echo "${jsonConf}" | jq -r '.sessionToken')

    echo "Server public key: "${serverPublicKey}
    echo "Server address: "${serverEndpoint}
    echo "Persistent keepalive: "${persistentKeepalive}" seconds"
    echo "Local IPs: "${allowedIp1}", "${allowedIp2}
    echo "DNS servers: "${dnsIp1}", "${dnsIp2}
    echo "Gateways: "${gatewayIp1}", "${gatewayIp2}
    echo "Session Token: "${sessionToken}

    setConfFile="${HIDE_ME_CONF_PATH}/hide.me-wireguard-${HIDE_ME_DEV_NAME}"
    echo '[Interface]' > ${setConfFile}
    echo 'PrivateKey = '${privateKey} >> ${setConfFile}
    echo '[Peer]' >> ${setConfFile}
    echo 'PublicKey = '${serverPublicKey} >> ${setConfFile}
    echo 'PresharedKey = '${presharedKey} >> ${setConfFile}
    echo 'AllowedIPs = 0.0.0.0/0, ::/0' >> ${setConfFile}
    echo 'Endpoint = '${serverEndpoint} >> ${setConfFile}
    echo 'PersistentKeepalive = '${persistentKeepalive} >> ${setConfFile}
    echo '# SessionToken = '${sessionToken} >> ${setConfFile}

    echo "Bringing ${HIDE_ME_DEV_NAME} interface up"
    ip link add ${HIDE_ME_DEV_NAME} type wireguard
    if [[ $? != 0 ]]; then echo "[FAIL] ip link add ${HIDE_ME_DEV_NAME} type wireguard"; exit 1; fi
    ip link set ${HIDE_ME_DEV_NAME} up
    if [[ $? != 0 ]]; then echo "[FAIL] ip link set ${HIDE_ME_DEV_NAME} up"; exit 1; fi

    echo "Adding route to ${serverIP}"
    # Add a host route towards the VPN server
    hostRoute=$(ip route get ${serverIP} | head -n1 | cut -d ' ' -f -5)
    ip route add ${hostRoute} &> /dev/null

    echo "Applying wireguard settings on ${HIDE_ME_DEV_NAME} interface"
    wg syncconf ${HIDE_ME_DEV_NAME} ${setConfFile}
    if [[ $? != 0 ]]; then echo "[FAIL] wg syncconf ${HIDE_ME_DEV_NAME} ${setConfFile}"; exit 1; fi

    echo "Setting IPs: ${allowedIp1}, ${allowedIp2}"
    ip address add ${allowedIp1} dev ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip address add ${allowedIp1} dev ${HIDE_ME_DEV_NAME}"; exit 1; fi
    ip address add ${allowedIp2}/64 dev ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip address add ${allowedIp2}/64 dev ${HIDE_ME_DEV_NAME}"; exit 1; fi

    # OpenVPN def1 style routes avoid overriding default routes
    echo "Adding in-tunnel routes"
    ip route add 0.0.0.0/1 via ${gatewayIp1} dev ${HIDE_ME_DEV_NAME} onlink
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add 0.0.0.0/1 via ${gatewayIp1} dev ${HIDE_ME_DEV_NAME} onlink"; exit 1; fi
    ip route add 128.0.0.0/1 via ${gatewayIp1} dev ${HIDE_ME_DEV_NAME} onlink
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add 128.0.0.0/1 via ${gatewayIp1} dev ${HIDE_ME_DEV_NAME} onlink"; exit 1; fi
    ip route add ::/3 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME} onlink
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add ::/3 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}"; exit 1; fi
    ip route add 2000::/4 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add 2000::/4 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}"; exit 1; fi
    ip route add 3000::/4 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add 3000::/4 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}"; exit 1; fi
    ip route add fc00::/7 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}
    if [[ $? != 0 ]]; then echo "[FAIL] ip route add fc00::/7 via ${gatewayIp2} dev ${HIDE_ME_DEV_NAME}"; exit 1; fi

    # Back the contents of /etc/resolv.conf up
    echo "Storing original resolv.conf in ${HIDE_ME_CONF_PATH}/hide.me-resolv.conf-backup"
    cat /etc/resolv.conf > ${HIDE_ME_CONF_PATH}/hide.me-resolv.conf-backup
    echo "nameserver ${dnsIp1}" > /etc/resolv.conf
    echo "nameserver ${dnsIp2}" >> /etc/resolv.conf
    echo "DNS servers set"
}

checkTools
generateKeys
connect