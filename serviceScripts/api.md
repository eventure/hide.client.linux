# Hide.me CLI VPN client for Linux REST API
The Hide.me CLI offers a RESTful control interface (API) when running in service mode. This API allows for full control and monitoring
of the client, providing an efficient way to manage operations programmatically.

## Preparation
1. Download the latest release from the [releases page](https://github.com/eventure/hide.client.linux/releases).
2. Unpack the downloaded file — installation is not required at this stage.

To start the `hide.me` service, run the following command:
```
./hide.me service
```
The expected output should be:
```
Init: Starting HTTP server on @hide.me
```
If not configured otherwise, hide.me client listens on a UNIX socket in the abstract namespace for HTTP requests. The socket is named
@hide.me.

### Changing the Listener Address
You can modify the listener's address using the --caddr option. For example, to bind hide.me CLI to a TCP port:
```
./hideGuard --caddr 127.0.0.1:5050 service
```
The output would then be:
```
Init: Starting HTTP server on 127.0.0.1:5050
```

### Examples
The [serviceScripts](../serviceScripts) folder contains example shell scripts and cURL commands for interacting with the API.
[completeConnectExample.sh](completeConnectExample.sh) and
[completeAccessTokenExample.sh](completeAccessTokenExample.sh) provide a complete solution for connecting and obtaining the access-token.

## How does this all work ?
Before connecting or requesting an Access Token, the client must be configured through the API interface. Configuration is a prerequisite
for making any requests, such as:

- Access Token retrieval
- Route management
- Connect or disconnect actions
- Destroying sessions
- Watching status
- Viewing logs

### REST API Structure

- **Configuration**: The configuration is set using a HTTP `POST` request.
- **Other Actions**: All other actions (like connecting or requesting logs) use simple HTTP `GET` requests.

Most API calls return a JSON response object in a JSON-RPC 2.0 style (without the `Id` attribute, which is not required). For more details, refer to the [JSON-RPC 2.0 Specification, section 5](https://www.jsonrpc.org/specification#response_object).

### Configuration
Configuring the client is the first step before making any API requests. The default configuration is mostly complete, with only the
**`Hostname`** attribute needing to be set.
Access-Token may be set directly through the AccessToken attribute or may be stored in a file at AccessTokenPath.
```
curl -s -X GET --abstract-unix-socket hide.me http://localhost/configuration
```
fetches the current configuration:
```
{
  "Rest": {
    "APIVersion": "v1.0.0",
    "Host": "",
    "Port": 432,
    "Domain": "hide.me",
    "AccessTokenPath": "accessToken.txt",
    "AccessToken": "",
    "Username": "",
    "Password": "",
    "RestTimeout": 10000000000,
    "ReconnectWait": 30000000000,
    "AccessTokenUpdateDelay": 2000000000,
    "CA": "CA.pem",
    "Mark": 0,
    "DnsServers": "3.2.1.0:53",
    "Filter": {},
    "PortForward": {}
  },
  "Wireguard": {
    "Name": "vpn",
    "ListenPort": 0,
    "Mark": 0,
    "RPDBPriority": 10,
    "PrivateKey": "",
    "RoutingTable": 55555,
    "LeakProtection": true,
    "ResolvConfBackupFile": "",
    "DpdTimeout": 60000000000,
    "SplitTunnel": "",
    "IPv4": true,
    "IPv6": true
  }
}
```
Any attribute in the client configuration can be modified as needed. For **Access Token** requests, both **`Username`** and **`Password`**
must be set.<br>
Once you've completed the configuration, send it to the service:

```
curl -s -X POST --abstract-unix-socket hide.me http://localhost/configuration --data @configuration.json
```
Only the changed attributes need to be sent via a `POST` request. For example, if you're just connecting to `hide.me`, it's enough
to update the **`Host`** attribute. The configuration JSON can be as simple as:
```
{
  "Rest": {
    "Host": "nl.hideservers.net"
  }
}
```
For issuing an Access-Token the configuration JSON might look like:
```
{
  "Rest": {
    "Host": "nl.hideservers.net",
    "Username": "USERNAME",
    "Password": "PASSWORD"
  }
}
```
Service responds with:
```
{"result":true}
```

### Access-Token
To fetch an Access Token, the client must be configured with the following attributes:

- **Hostname**
- **Username**
- **Password**

Once these attributes are set, you can retrieve the Access Token by issuing the following command:
```
curl -s --abstract-unix-socket hide.me http://localhost/token
```
A successful response will return an object which contains the issued token:
```
{"result":"token_base64_here"}
```
The issued token will be stored in the runtime configuration and the filename specified by AccessTokenPath attribute (if any).  

### Routing
When started in service mode hide.me CLI won't create a WireGuard interface, won't apply any settings or routing. It has to be instructed
to do so by invoking the route method:
```
curl -s --abstract-unix-socket hide.me http://localhost/route
```
This will bring up a wireguard interface, enable or disable configured features, especially the kill-switch, and get ready for
connection establishment. If you forget to call route, the connect method will automatically invoke it. Routing is a prerequisite
for connection establishments. A successful route request returns:
```
{"result":{"code":"routed"}}
```

### Destruction
Destroy is an inverse operation of routing:
```
curl -s --abstract-unix-socket hide.me http://localhost/destroy
```
Destroy will clean up the system and remove the wireguard interface. Destroy may be called even while connected. In that case, destroy will
disconnect and clean up. A successful destroy request returns:
```
{"result":{"code":"routed"}}
```
When in "routed" state you may change configuration attributes, but changing most of them within the _Wireguard_ attribute requires calling
destroy and calling route again. _ResolvConfBackupFile_ and _DpdTimeout_ are the only attributes within the _Wireguard_ attribute safe to
modify without going through the destroy/route cycle.

### Connect
Connection establishment is as easy as issuing:
```
curl -s --abstract-unix-socket hide.me http://localhost/connect
```
A successful connect response might look like the following:
```
{
  "result": {
    "code": "connected",
    "publicKey": "DV4UWlB7PJa3j6uvtpRLObilcMY0gqrePtfSOsJIlzc=",
    "endpoint": {
      "IP": "1.2.3.4",
      "Port": 432,
      "Zone": ""
    },
    "presharedKey": "ZpJf9/OwzaXzjNvK6R1sz2LkNoamAfmKBCNSfI/gwXw=",
    "persistentKeepalive": 20000000000,
    "allowedIps": [
      "10.140.242.229",
      "fd00:6968:6564:679::a8c:f2e5"
    ],
    "DNS": [
      "10.140.242.1",
      "fd00:6968:6564:679::1"
    ],
    "gateway": [
      "10.140.242.1",
      "fd00:6968:6564:679::1"
    ],
    "sessionToken": "hBjYXiMCF1bSnyuQ0Gu42U2x1SRHC/UVxOeCVqI/tAYJjZ7Tg7YgbKqQT71eQyAE8ndSLuCwVGzigkNLnA7nByWnyL3s7vaUKkmVVBvA8xx1Fg==",
    "tx": 148
  }
}
```
If anything goes wrong, e.g. DNS lookup fails, the response will be a JSON-RPC error: 
```
{
    "error": {
        "code": "connect",
        "message": "lookup nl-test.hideservers.net on 192.168.0.1:53: no such host"
    }
}
```
Once a connection is successfully established, the `hide.me` CLI remembers the remote endpoint's IP address. If any DNS errors
occur during reconnection attempts, the CLI will automatically reuse the remembered IP.

### Disconnect
Disconnect is just as easy as connect:
```
curl -s --abstract-unix-socket hide.me http://localhost/disconnect
```
Disconnect should always succeed and would respond with:
```
{"result":{"code":"routed"}}
```
Disconnect puts the client back into the "routed" state.

### State
State method will dump the client's current status. For example, when connected one could invoke:
```
curl -s --abstract-unix-socket hide.me http://localhost/state
```
The result will contain all the information about the client state:
```
{
  "result": {
    "code": "connected",
    "publicKey": "DV4UWlB7PJa3j6uvtpRLObilcMY0gqrePtfSOsJIlzc=",
    "endpoint": {
      "IP": "1.2.3.4",
      "Port": 432,
      "Zone": ""
    },
    "presharedKey": "WQSBSc1HOdACApr3/2GLMsnlvGON/8VrAPaPK4i0JtQ=",
    "persistentKeepalive": 20000000000,
    "allowedIps": [
      "10.140.242.97",
      "fd00:6968:6564:679::a8c:f261"
    ],
    "DNS": [
      "10.140.242.1",
      "fd00:6968:6564:679::1"
    ],
    "gateway": [
      "10.140.242.1",
      "fd00:6968:6564:679::1"
    ],
    "sessionToken": "kgqE8+g35TOq/wIx7eFv9KIzQPQDoC54JPEfknYIA3WvHtMgggvh+sE+ILqu7np3coZq28rXMw+SBXc0PJX5xqq0BUoNH5tDWfqWKNN5PuKV3w==",
    "rx": 156,
    "tx": 3236
  }
}
```
State response is almost identical to connect response. However, state provides rx and tx counters.

### Watch
Some integrations might require an event stream. By invoking the watch method such an event stream is made available to the consumer.
```
curl -s --abstract-unix-socket hide.me http://localhost/watch
```

### Log
Hide.me CLI keeps a copy of its logs in a circular ring-buffer. To fetch a copy of those logs issue:
```
curl -s --abstract-unix-socket hide.me http://localhost/log
``` 