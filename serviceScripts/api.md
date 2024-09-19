# Hide.me CLI VPN client for Linux REST API
Hide.me CLI provides a RESTful control interface (API) when ran in the service mode. API can be used to completely control and monitor the
client

## Preparation
Download the latest release from [releases](https://github.com/eventure/hide.client.linux/releases). Unpack it, there's no need to install it
yet.

Start hide.me like this:
```
./hide.me service
```

The output should be like:
```
Init: Starting HTTP server on @hide.me
```
By default, hide.me binary listens on a UNIX socket in the abstract namespace called hide.me for HTTP (not HTTPS) requests. Alternatively,
one could specify the exact listener socket address:
```
./hideGuard --caddr 127.0.0.1:5050 service
```
hide.me would listen on a TCP port then:
```
Init: Starting HTTP server on 127.0.0.1:5050
```

[serviceScripts](../serviceScripts) folder contains all the example cURLs one would ever need.
[completeConnectExample.sh](completeConnectExample.sh) and
[completeAccessTokenExample.sh](completeAccessTokenExample.sh) provide a complete solution for connecting and obtaining the access-token.

## How does it work ?
Before connecting or requesting an Access-Token, the client needs to be configured first. Configuration must be provided through the API
interface. Only then access-token, route, connect, disconnect, destroy, watch or logs requests can be made.

Every REST call is a simple HTTP GET call except for the configuration POST call. Most of the calls return a JSON response object
(JSON-RPC 2.0 style, without the Id attribute as it is not required). Check https://www.jsonrpc.org/specification section 5.

### Configuration
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
Any attribute may be changed. Host attribute is mandatory and has to be set. Other attributes may be left at their default values.
Once satisfied, send configuration to the service:
```
curl -s -X POST --abstract-unix-socket hide.me http://localhost/configuration --data @configuration.json
```
You do not need to send the whole configuration, but only the changed attributes. For instance, for the purposes of connecting to hide.me
it is enough to send the Host attribute, so the JSON might be as simple as:
```
{
  "Rest": {
    "Host": "nl.hideservers.net"
  }
}
```
For issuing an Access-Token the JSON might look like:
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
In order to fetch an Access-Token the client must be configured with a hostname, username and a password, just like outlined above. It
is a matter of issuing:
```
curl -s --abstract-unix-socket hide.me http://localhost/token
```
A successful response will return an object which contains a token:
```
{"result":"token_base64_here"}
```
Also, the token will be stored in the file specified by AccessTokenPath attribute.

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
Once a successful connection establishment happens hide.me CLI remembers the remote endpoint IP. If any DNS errors happen while
reconnecting hide.me CLI will reuse the remembered IP. This is a feature of our client, i.e. it needs to resolve an endpoint only
once and will use the resolved IP for future connections if and when DNS starts to fail.

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