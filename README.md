# Hide.me CLI VPN client for Linux

Hide.me CLI is a VPN client for use with eVenture Ltd. Hide.me VPN service based on the WireGuard protocol. Client's
features include:

* Completely standalone solution which does not depend on any external binaries or tools
* Key exchange via RESTful requests secured with TLS 1.3
* TLS certificate pinning of server's certificates to defeat man-in-the-middle sort of attacks
* Dead peer detection
* Leak protection a.k.a. kill-switch based on routing subsystem
* Mobility/Roaming support
* DNS management
* IPv6 support
* systemd notification support
* Split tunneling
* DNS filter (SmartGuard)

TODO:
* Server lists and server chooser
* Automatic server selection
* Client certificate authentication/authorization

## Build

You may clone this repository and run:

```go build -o hide.me```

Alternatively, download the latest build from the releases section.

## Installation (Manual)

Source tree and binary releases contain simple installation and uninstallation scripts. Hide.me CLI gets installed
in /opt/hide.me directory. Apart from copying hide.me files to /opt/hide.me no modifications to the system are done.<br>
When systemd based distribution is detected the installer links a template unit file which can be used to instantiate
connections.

## Installation (ArchLinux Package)

You can build the package using the PKGBUILD provided in packaging/archlinux/
(requires `git clone --recurse-submodules`) or
from https://aur.archlinux.org/packages/hide-client/

To build:
```
makepkg && sudo pacman -U hide-client-0.9.1-1-any.pkg.tar.zst 
```
Note that the ArchLinux package changes the default locations of the installed files to
`/usr/bin/hide.me` for the binary,
`/etc/hide.me/accessToken.txt` for the accessToken,
`/usr/share/hide.me/CA.pem` for the certificate and
`/usr/lib/systemd/system/hide.me@service` for the systemd unit.

## Hide.me WireGuard implementation details

WireGuard is one of the most secure and simplest VPN tunneling solutions in the industry. It is easy to set up and use as
long as no WireGuard public key exchange over an insecure medium (such as Internet) is required. Any sort of WireGuard
public key exchange is out of the scope of the WireGuard specification.

### Key exchange

The complicated task of public key exchange and secret key negotiation over an insecure medium is, usually, being handled
by:
* IKE protocol - a hard to understand, and a rather complicated part of IPSec
* TLS protocol - a foundation for HTTPS and virtually any other secure protocol

hide.me implementation of WireGuard leverages HTTPS (TLS) for the exchange of:
* WireGuard Public keys
* WireGuard Shared keys
* IP addressing information (IP addresses, DNS server addresses,gateways...)

Authentication for all operations requires the use of an Access-Token. An Access-Token is a just a binary blob which is
cryptographically tied to a hide.me account.

### Connection setup flow

Connection to a hide.me VPN server gets established in these steps:
1. hide.me CLI contacts a REST endpoint, over a secured channel, requesting a public key exchange and a server-side
connection setup
2. Server authenticates the request, sets up the connection and serves the IP addressing information (including
the WireGuard endpoint address). Server issues a randomized Session-Token which may be used to disconnect this
particular session
3. hide.me CLI sets up a WireGuard peer according to the server's instruction and starts the DPD check loop

### Leak protection

In contrast with many other solutions, hide.me CLI does not use any sort of Linux firewalling technology (IPTables, NFTables
or eBPF). Instead of relying on Linux'es IP filtering frameworks, hide.me CLI selectively routes traffic by setting up a
special routing table and a set of routing policy database rules. Blackhole routes in the aforementioned routing table drop
all traffic unless it meets one of the following conditions:
* Traffic is local ( loopback interfaces, local broadcasts and IPv6 link-local multicast )
* DHCPv4 traffic
* Traffic is explicitly allowed by the means of the Split-tunneling option
* Traffic is about to be tunneled

This mode of operation makes it possible for the users to establish their own firewalling policies with which hide.me CLI
won't interfere.

## Usage
Usage instructions may be printed by running hide.me CLI without any parameters.
```
Usage:
  ./hide.me [options...] <command> [host]
...
```
### Commands
hide.me CLI user interface is quite simple. There are just three commands available:
```
command:
  token - request an Access-Token (required for connect)
  connect - connect to a vpn server
  conf - generate a configuration file to be used with the -c option
  categories - fetch and dump filtering category list
  service - run in remotely controlled service mode
```
In order to connect to a VPN server an Access-Token must be requested from a VPN server. An Access-Token request is
issued by the **token** command.
An Access-Token issued by any server may be used, for authentication purposes, with any other hide.me VPN server.
When a server issues an Access-Token that token must be stored in a file. Default filename for an Access-Token is
"accessToken.txt".

Once an Access-Token is in place it may be used for **connect** requests. Stale access tokens get updated automatically.

hide.me CLI does not necessarily have to be invoked with a bunch of command line parameters. Instead, a YAML formatted
configuration file may be used to specify all the options. To generate such a configuration file the **conf** command
may be used.

For the purposes of DNS filtering (SmartGuard), a list of filtering categories can be obtained with **categories** command

hide.me CLI can be run in **service** mode. When started in service mode, hide.me CLI just exposes a REST interface for
control. The controller is responsible for configuring connections, activation of the kill-switch or any other operation.
REST interface listen address is configurable through -caddr option. 

Note that there are a few options which are configurable only through the configuration file. Such options are:
* Password - **DANGEROUS**, do not use this option unless you're aware of the security implications 
* ConnectTimeout
* AccessTokenUpdateDelay
```
host:
  fqdn, short name or an IP address of a hide.me server
  Required when the configuration file does not contain it
```
The hostname of a hide.me REST endpoint may be specified as a fully qualified domain name (nl.hide.me), short name (nl)
or an IP address. There's no guarantee that the REST endpoint will match a WireGuard endpoint.

### Options
```
  -4    Use IPv4 tunneling only
```
Limit all IP protocol operations to IPv4. Even though the server will provide IPv4 and IPv6 addressing only IPv4
addresses, IPv4 rules and IPv4 routes get installed. Leak protection/kill-switch works for IPv4 traffic only. IPv6 
traffic flow remains unsecured.

**WARNING**: This option degrades security and should be used only when it's safe to do so, e.g. when the client machine
has it's IPv6 stack disabled. Please, do not use it otherwise because IPv6 leaks may happen.
```
  -6   	Use IPv6 tunneling only
```
Limit all IP protocol operations to IPv6. Even though the server will provide IPv4 and IPv6 addressing only IPv6
addresses, IPv6 rules and IPv6 routes get installed. Leak protection/kill-switch works for IPv6 traffic only. IPv4 
traffic flow remains unsecured.

**WARNING**: This option degrades security and should not be used unless the client wishes to tunnel the IPv6 traffic only.
```
  -b filename
    	resolv.conf backup filename (default "")
```
Hide.me CLI keeps a backup of /etc/resolv.conf in memory. In addition to that backup hide.me CLI may back up /etc/resolv.conf
to a file specified by this option.
```
  -c filename
    	Configuration filename
```
Use a configuration file named "filename".
```
  -ca string
    	CA certificate bundle (default "CA.pem")
```
During TLS negotiation the VPN server's certificate needs to be verified. This option makes it possible to specify
an alternate CA certificate bundle file.
```
  -caddr address
    	Control interface listen address (default "@hide.me")
```
Set the service mode control interface listen address. hide.me CLI, by default, listens on an abstract UNIX socket hide.me 
```
  -ccert certificate
    	Control interface certificate file
```
Set the service mode control interface X509 certificate in PEM format
```
  -ckey key
    	Control interface key file
```
Set the service mode control interface private key in PEM format
```
  -d DNS servers
    	comma separated list of DNS servers used for client requests (default "209.250.251.37:53,217.182.206.81:53")
```
By default, Hide.me CLI uses hide.me operated DNS servers to resolve VPN server names when requesting a token or during
connect requests. The set of DNS servers used for these purposes may be customized with this option.
```
  -dpd duration
    	DPD timeout (default 1m0s)
```
In order to detect if a connection has stalled, usually due to networking issues, hide.me CLI periodically checks
the connection state. The checking period can be changed with this option, but can't be higher than a minute.
```
  -i interface
    	network interface name (default "vpn")
```
Use this option to specify the name of the networking interface to create or use.
```
  -l port
    	listen port
```
Specify a listen port for encrypted WireGuard traffic.
```
  -m mark
    	firewall mark for wireguard traffic (default 0 - no packet marks)
```
Set the firewall mark the WireGuard kernel module will mark its packets with.
```
  -p port
    	remote port (default 432)
```
Remote REST endpoint port may be changed with this option.
```
  -pf
    	enable dynamic port-forwarding technologies (uPnP and NAT-PMP)
```
Dynamic port-forwarding is, by default, disabled. Use this option to turn it on for a particular connection attempt.
Alternatively, port-forwarding may be enabled by adding a **@pf** suffix to the username when requesting a token. Such tokens
activate port-forwarding on each connection attempt, and you should not use this option when using them.   
```
  -r table
    	routing table to use (default 55555)
```
Set the routing table to use for general traffic and leak protection mechanism.
```
  -R priority
    	RPDB rule priority (default 10)
```
Set the priority of installed RPDB rules. Hide.me CLI takes advantage of policy routing by installing a RPDB rule (one per
IP protocol) in order to drive traffic to a chosen routing table and ensure IP leak protection.
```
  -s networks
    	comma separated list of networks (CIDRs) for which to bypass the VPN
```
List of split-tunneled networks, i.e. the networks for which the traffic should not be tunneled over the VPN.
```
  -t string
    	access token filename (default "accessToken.txt")
```
Name of the file which contains an Access-Token.
```
  -u username
    	hide.me username
```
Set hide.me username.

#### DNS Filter (SmartGuard) ####
Hide.me CLI supports DNS based filtering (SmartGuard). The following options control DNS filtering: 
```
  -forceDns
    	force tunneled DNS handling on hide.me servers
```
Activate DNS redirection on a Hide.me VPN server such that each UDP or TCP DNS request will be handled by that Hide.me VPN server
```
  -whitelist dns names
    	comma separated list of allowed dns names
```
DNS suffixes which will bypass any filtering engine ( wildcards accepted )
```
  -blacklist dns names
    	comma separated list of filtered dns names
```
DNS names which will be filtered
```
  -noAds
    	filter ads
```
Activates SmartGuard based ad filtering
```
  -noCategories categories
    	comma separated list of filtered content categories
```
Activates fine-grained SmartGuard filtering. Fetch category list with categories [command](#commands)
``` 
  -noIllegal kind
    	filter illegal kind (content, warez, spyware, copyright)
```
Activates coarse level filtering of illegal content, warez, spyware and copyrighted material
```
  -noMalicious
    	filter malicious destinations
```
Activates filtering of malicious hosts, websites or domains
```
  -noMalware
    	filter malware
```
Activates a malware filter. Any site hosting or distributing malware should be filtered out
```
  -noRisk level
    	filter content according to risk level (possible, medium, high)
```
Activates a risk filter
```
  -noTrackers
    	filter trackers
```
Activates a tracking filter
```
  -pg age
    	apply a parental guidance style age filter (12, 18)
```
Activates a parental guidance style filter according to given age limit. Inappropriate content will be filtered out
```
  -safeSearch
    	force safe search with search engines
```
Enforces SafeSearch mode with supported search engines (Google, Bing)

### Integration with systemd

Hide.me CLI can be used standalone or as a systemd service. Using hide.me CLI as a systemd service allows you
to take advantage of systemd's dependancy resolution, monitoring and various hardening features.<br>
The installer script links a template unit file hide.me@.service for you or you may manually link the template
unit file by running:

systemctl link hide.me@service

To manage connections the following commands may be used:

Operation | Command
--- | ---
Create a connection | systemctl enable hide.me@SERVER<br>
Start a connection | systemctl start hide.me@SERVER
Stop a connection | systemctl stop hide.me@SERVER<br>
Remove a connection | systemctl disable hide.me@SERVER<br>

SERVER is a server name, group name or an IP address.

Additional commandline options to the `hide.me connect` command run by the
systemd service can be put into the `OPTIONS=` configuration variable in
`/opt/hide.me/config`.

Service startup is considered successful when a connection to hide.me server gets completely established. 

### Embedded device alternative to the binary CLI

Hide.me CLI is the best choice for desktop PCs, but may be inappropriate for routers or embedded devices. For those small devices we developed
a set of ash scripts (in the scripts/ directory):

1. **hide.me-accessToken.ash** obtains a Token (use it whenever you need to update the token, e.g., after a subscription renewal or a password change)
2. **hide.me-connect.ash** connects to a VPN server of choice and sets up the wireguard interface. Routing is handled in the same way
as OpenVPN handles it with it's redirect-gateway def1 setting. DNS is installed by backing up and overwriting resolv.conf
3. **hide.me-disconnect.ash** disconnects from the VPN server, removes routes and restores the DNS

In the header of each script you'll find usage examples.

The functionality of those scripts is basic, i.e. they'll get you connected/disconnected, but won't monitor your connection.
Such a limited feature set might be just enough to use hide.me with routers which have their own monitoring and fail-over techniques.<br>
Each script has been verified on OpenWRT based routers with the latest stable firmware (19.07.7) and wireguard support.
Prerequisites, which should be opkg-installed, are:

1. **curl** issues REST requests
2. **jq** parses JSON

## Contributing

If you want to contribute to this project, please read the [contribution guide](https://github.com/eventure/hide.client.linux/blob/master/CONTRIBUTING.md).