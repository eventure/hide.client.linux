0.9.12
------

Released 2026/08/17

- New /version service API endpoint
- Configuration gets saved to file on successful API-driven update
- Access-Token requests through the service API, with DoH and leak protection support
- External IPs refactored to async with state notifications; notify parameter for state notifications, TokenUpdateDone state
- Access-Token no longer exposed in JSON/YAML filter and port-forwarding output
- REST client initialization ordering fix for reliable route/rule removal
- DPD refactor and connect state notification fixes
- README update to reflect new CLI options, commands, and configuration changes
- DNS-over-HTTPS resolver with a DNS stamp list updater (updateDoh command, resolvers.txt)
- Server lists: new "list" command and /serverList service API endpoint with caching
- New service API endpoints: /shutdown and /externalIps
- Multiple state watchers, timestamps and host attribute in state notifications, DNS lookup state
- Concurrency hardening: channel-based locking with timeouts, race condition fixes
- DoH gets disabled while connected
- Command line parsing switched to pflags, configuration tidy-up
- Standard resolv.conf format, HTTP/2 for REST requests
- Category list fetch fix, IPv6 rule fix, plain DNS hostname fix, IP version defaults fix
- Go toolchain and dependency updates


0.9.10
------

Released 2024/09/19

- Service API documentation (serviceScripts/api.md)
- Fixed connect state notifier, explicit server address resolution
- MTU calculation update for IPv6
- aarch64 compatibility fix (no netlink.AddrList)
- Tolerate missing /run/systemd/resolve


0.9.9
-----

Released 2024/01/25

- Line log buffering and the "log" REST method
- Access-Token deletion through the API
- resolv.conf updates use seeks and truncates, systemd-resolved path kept writable
- conf command output goes to STDOUT instead of STDERR
- HTTP statuses recorded; traffic not marked unless configured


0.9.8
-----

Released 2023/08/30

- Dynamic port-forwarding support (uPnP and NAT-PMP)


0.9.7
-----

Released 2023/08/28

- Socket marks are no longer set for in-tunnel traffic


0.9.6
-----

Released 2023/08/09

- FirewallMark renamed to Mark, marking enabled by default


0.9.5
-----

Released 2023/07/31

- Remote control interface (REST API) with examples


0.9.4
-----

Released 2023/07/26

- DNS filtering (SmartGuard): categories, whitelist/blacklist, force-DNS option, authenticated filtering
- TLS 1.3 required for REST calls, DigiCert certificate pins added
- resolv.conf handling update
- Link teardown refactored to a cleanup stack, configuration restructuring
- Updated to Go 1.20


0.9.3
-----

Released 2023/02/03

- Context-based cancellation of operations
- User-Agent header in REST requests
- ReconnectWait is now configurable
- Installer script fix


0.9.2
-----

Released 2022/03/15

- ArchLinux packaging (AUR git submodule) and installation guide
- systemd command line options configurable through an environment file (OPTIONS=)
- ASH scripts for OpenWRT
- Simplified RPDB rules without firewall-mark dependencies, configurable rule priority, throw routes
- Fixed direct-IP connect and a possible resource leak


0.9.1
-----

Released 2020/11/04

- Tunneled IP family selection options (-4 and -6)
- systemd service file, installer and uninstaller scripts


0.9.0
-----

Released 2020/07/20


- The initial release of Hide.me CLI VPN client for Linux