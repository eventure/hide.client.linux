package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/configuration"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Set up and parse flags, read the configuration file
func configure() ( conf *configuration.Configuration, command string ) {
	conf = configuration.NewConfiguration()
	configurationFileName := flag.String( "c", "", "Configuration `filename`" )																// General flags
	
	flag.Int   ( "p",  conf.Client.Port, "remote `port`" )																					// REST related flags
	flag.String( "ca", conf.Client.CA, "CA certificate bundle `filename`" )
	flag.String( "t",  conf.Client.AccessTokenFile, "access token `filename`" )
	flag.String( "u",  conf.Client.Username, "hide.me `username`" )
	flag.String( "P",  conf.Client.Password, "hide.me `password`" )
	flag.String( "d",  conf.Client.DnsServers, "comma separated list of `DNS servers` used for client requests" )
	
	flag.Bool	 ( "forceDns",		conf.Client.Filter.ForceDns, "force tunneled DNS handling on hide.me servers" )							// Filtering related flags
	flag.Bool	 ( "noAds",			conf.Client.Filter.Ads, "filter ads" )
	flag.Bool	 ( "noTrackers",	conf.Client.Filter.Trackers, "filter trackers" )
	flag.Bool	 ( "noMalware",		conf.Client.Filter.Malware, "filter malware" )
	flag.Bool	 ( "noMalicious",	conf.Client.Filter.Malicious, "filter malicious destinations" )
	flag.Int	 ( "pg",			conf.Client.Filter.PG, "apply a parental guidance style `age` filter (12, 18)" )
	flag.Bool	 ( "safeSearch",	conf.Client.Filter.SafeSearch, "force safe search with search engines" )
	flag.String  ( "noRisk",		strings.Join( conf.Client.Filter.Risk, "," ), "filter content according to risk `level` (possible, medium, high)" )
	flag.String  ( "noIllegal",		strings.Join( conf.Client.Filter.Illegal, "," ), "filter illegal `kind` (content, warez, spyware, copyright)" )
	flag.String  ( "noCategories",	strings.Join( conf.Client.Filter.Categories, "," ), "comma separated list of filtered content `categories`" )
	flag.String  ( "whitelist",		strings.Join( conf.Client.Filter.Categories, "," ), "comma separated list of allowed `dns names`" )
	flag.String  ( "blacklist",		strings.Join( conf.Client.Filter.Categories, "," ), "comma separated list of filtered `dns names`" )
	
	flag.String  ( "i",   conf.Link.Name, "network `interface` name" )																		// Link related flags
	flag.Int     ( "l",   conf.Link.ListenPort, "listen `port`" )
	flag.Int     ( "m",   conf.Link.FirewallMark, "firewall `mark` for wireguard and hide.me client originated traffic" )
	flag.Int     ( "r",   conf.Link.RoutingTable, "routing `table` to use" )
	flag.Int     ( "R",   conf.Link.RPDBPriority, "RPDB rule `priority`" )
	flag.Bool	 ( "k",   conf.Link.LeakProtection, "enable/disable leak protection a.k.a. kill-switch" )
	flag.String  ( "b",   conf.Link.ResolvConfBackupFile, "resolv.conf backup `filename`" )
	flag.Duration( "dpd", conf.Link.DpdTimeout, "DPD `timeout`" )
	flag.String  ( "s",   conf.Link.SplitTunnel, "comma separated list of `networks` (CIDRs) for which to bypass the VPN" )
	flag.Bool	 ( "4",   false, "Use IPv4 tunneling only" )
	flag.Bool	 ( "6",   false, "Use IPv6 tunneling only" )
	
	flag.Usage = func() {
		fmt.Fprint( os.Stderr, "Usage:\n  ", os.Args[0], " [options...] <command> [host]\n\n" )
		fmt.Fprint( os.Stderr, "command:\n" )
		fmt.Fprint( os.Stderr, "  token - request an Access-Token (required for connect)\n" )
		fmt.Fprint( os.Stderr, "  connect - connect to a vpn server\n" )
		fmt.Fprint( os.Stderr, "  conf - generate a configuration file to be used with the -c option\n" )
		fmt.Fprint( os.Stderr, "  categories - fetch and dump filtering category list\n\n" )
		fmt.Fprint( os.Stderr, "host:\n" )
		fmt.Fprint( os.Stderr, "  fqdn, short name or an IP address of a hide.me server\n" )
		fmt.Fprint( os.Stderr, "  Required when the configuration file does not contain it\n\n" )
		fmt.Fprint( os.Stderr, "options:\n" )
		flag.PrintDefaults()
	}
	flag.Parse()
	
	switch command = strings.ToLower( flag.Arg(0) ); command {
		case "connect", "token", "conf", "categories": break
		default:
			if len( command ) > 0 { fmt.Fprint( os.Stderr, "Unsupported command \"" + command + "\"\n\n" ) }
			flag.Usage()
			return nil, ""
	}
	
	if len( *configurationFileName ) > 0 {
		if err := conf.Read( *configurationFileName ); err != nil { fmt.Println( "Configuration file error:", err.Error() ); return nil, "" }
	}
	
	err := error( nil )
	flag.Visit( func( f *flag.Flag ) {																										// Parse flags
		if err != nil { return }
		switch f.Name {
			case "p":  conf.Client.Port, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: Port malformed" ) }	// REST related flags
			case "ca": conf.Client.CA = f.Value.String()
			case "t":  conf.Client.AccessTokenFile = f.Value.String()
			case "u":  conf.Client.Username = f.Value.String()
			case "P":  conf.Client.Password = f.Value.String()
			case "d":  conf.Client.DnsServers = f.Value.String()
		
			case "forceDns":     conf.Client.Filter.ForceDns = f.Value.String() == "true"													// Filtering related flags
			case "noAds":        conf.Client.Filter.Ads = f.Value.String() == "true"
			case "noTrackers":   conf.Client.Filter.Trackers = f.Value.String() == "true"
			case "noMalware":    conf.Client.Filter.Malware = f.Value.String() == "true"
			case "noMalicious":  conf.Client.Filter.Malicious = f.Value.String() == "true"
			case "pg":        	 conf.Client.Filter.PG, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: PG malformed" ) }
			case "safeSearch":	 conf.Client.Filter.SafeSearch = f.Value.String() == "true"
			case "noRisk":		 conf.Client.Filter.Risk = strings.Split( f.Value.String(), "," )
			case "noIllegal":	 conf.Client.Filter.Illegal = strings.Split( f.Value.String(), "," )
			case "noCategories": conf.Client.Filter.Categories = strings.Split( f.Value.String(), "," )
			case "whitelist":	 conf.Client.Filter.Whitelist = strings.Split( f.Value.String(), "," )
			case "blacklist":	 conf.Client.Filter.Blacklist = strings.Split( f.Value.String(), "," )
		
			case "i":   conf.Link.Name = f.Value.String()																					// Link related flags
			case "l":   conf.Link.ListenPort, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: ListenPort malformed" ) }
			case "m":   conf.Link.FirewallMark, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: FirewallMark malformed" ) }
					    conf.Client.FirewallMark = conf.Link.FirewallMark
			case "R":   conf.Link.RPDBPriority, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: RPDBPriority malformed" ) }
			case "r":   conf.Link.RoutingTable, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: RoutingTable malformed" ) }
			case "k":   if f.Value.String() == "false" { conf.Link.LeakProtection = false }
			case "b":   conf.Link.ResolvConfBackupFile = f.Value.String()
			case "dpd": conf.Link.DpdTimeout, err = time.ParseDuration( f.Value.String() ); if err != nil { fmt.Println( "conf: DpdTimeout malformed" ) }
			case "s":   conf.Link.SplitTunnel = f.Value.String()
			case "4":   if f.Value.String() == "true" { conf.Link.IPv4 = true; conf.Link.IPv6 = false }
			case "6":   if f.Value.String() == "true" { conf.Link.IPv4 = false; conf.Link.IPv6 = true }
		}
	})
	if err != nil { return nil, "" }
	if hostName := flag.Arg(1); hostName != "" { conf.Client.Host = hostName }
	
	if err = conf.Check(); err != nil { fmt.Fprint( os.Stderr, "Configuration error: ", err, "\n" ); return nil, "" }						// Check configuration
	conf.AdjustHost()																														// Add .hideservers.net suffix where appropriate
	return
}

// Get the Access-Token
func accessToken( conf *configuration.Configuration ) {
	if conf.Client.AccessTokenFile == "" { fmt.Println( "Main: [ERR] Access-Token must be stored to a file" ); return }
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if !client.HaveAccessToken() {																											// An old Access-Token may be used to obtain a new one, although that process may be done by "connect" too
		if err = conf.InteractiveCredentials(); err != nil { fmt.Println( "Main: [ERR] Credential error,", err ); return }					// Try to obtain the credentials through the terminal
	}
	tokenCtx, cancel := context.WithTimeout( context.Background(), conf.Client.RestTimeout )
	defer cancel()
	if err = client.Resolve( tokenCtx ); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }								// Resolve the REST endpoint
	if err = client.GetAccessToken( tokenCtx ); err != nil { fmt.Println( "Main: [ERR] Access-Token request failed,", err ); return }		// Request an Access-Token
	fmt.Println( "Main: Access-Token stored in", conf.Client.AccessTokenFile )
	return
}

// Fetch and dump filtering categories
func categories( conf *configuration.Configuration ) {
	clientConf := conf.Client
	clientConf.Port = 443
	clientConf.CA = ""
	client, err := rest.NewClient( &clientConf )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	catCtx, cancel := context.WithTimeout( context.Background(), conf.Client.RestTimeout )
	defer cancel()
	if err = client.Resolve( catCtx ); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }									// Resolve the REST endpoint
	if err = client.FetchCategoryList( catCtx ); err != nil { fmt.Println( "Main: [ERR] GET request failed,", err ); return }				// Get JSON
	return
}

// Connect
func connect( conf *configuration.Configuration ) {
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if ! client.HaveAccessToken() { fmt.Println( "Main: [ERR] No Access-Token available" ); return }										// Access-Token is required for the Connect/Disconnect methods
	
	link := wireguard.NewLink( conf.Link )
	if err = link.Open(); err != nil { fmt.Println( "Main: [ERR] Wireguard open failed,", err ); return }									// Open or create a wireguard interface, auto-generate a private key when no private key has been configured
	defer link.Close()
	
	dhcpDestination := &net.IPNet{IP: []byte{ 255, 255, 255, 255 }, Mask: []byte{ 255, 255, 255, 255 } }									// IPv4 DHCP VPN bypass "throw" route
	if err = link.ThrowRouteAdd( "DHCP bypass", dhcpDestination ); err != nil { fmt.Println( "Main: [ERR] DHCP bypass route failed,", err ); return }
	defer link.ThrowRouteDel( "DHCP bypass", dhcpDestination )
	
	if len( conf.Client.DnsServers ) > 0 {
		for _, dnsServer := range strings.Split( conf.Client.DnsServers, "," ) {															// throw routes for configured DNS servers
			udpAddr, err := net.ResolveUDPAddr( "udp", dnsServer )
			if err != nil { fmt.Println( "Main: [ERR] DNS server address resolve failed,", err ); return }
			if err = link.ThrowRouteAdd( "DNS server", wireguard.Ip2Net( udpAddr.IP ) ); err != nil { fmt.Println( "Main: [ERR] Route DNS server failed,", err ); return }
			defer link.ThrowRouteDel( "DNS server", wireguard.Ip2Net( udpAddr.IP ) )
		}
	}
	
	if len( conf.Link.SplitTunnel ) > 0 {
		for _, network := range strings.Split( conf.Link.SplitTunnel, "," ) {																// throw routes for split-tunnel destinations
			_, ipNet, err := net.ParseCIDR( network )
			if err != nil { fmt.Println( "Main: [ERR] Parse split-tunnel route from", network, "failed,", err ); return }
			if err = link.ThrowRouteAdd( "Split-Tunnel", ipNet ); err != nil { fmt.Println( "Main: [ERR] Split-tunnel route to ", network, "failed,", err ); return }
			defer link.ThrowRouteDel( "Split-Tunnel", ipNet )
		}
	}
	
	if conf.Link.LeakProtection {																											// Add the "loopback" default routes to the configured routing tables ( IP leak protection )
		if err = link.LoopbackRoutesAdd(); err != nil { fmt.Println( "Main: [ERR] Addition of loopback routes failed,", err ); return }
		defer link.LoopbackRoutesDel()
	}
	
	err = link.RulesAdd(); defer link.RulesDel()																							// Add the RPDB rules which direct traffic to configured routing tables
	if err != nil { fmt.Println( "Main: [ERR] RPDB rules failed,", err ); return }
	
	upCh := make( chan error )																												// Carries client errors
	upCancel := context.CancelFunc(nil)																										// When a client runs it can be cancelled ( upCancel is not NIL )
	upCancelLock := sync.Mutex{}																											// Updating/testing upCancel is racy
	up := func() {
		var upErr error
		defer func() { upCancelLock.Lock(); upCancel = nil; upCancelLock.Unlock(); upCh <- upErr } ()
		var upCtx context.Context
		upCancelLock.Lock()
		upCtx, upCancel = context.WithTimeout( context.Background(), time.Second * 84000 )													// Hide.me sessions last up to 86400 seconds
		defer upCancel()
		upCancelLock.Unlock()
		
		if upErr = client.Resolve( upCtx ); upErr != nil { fmt.Println( "Main: [ERR] DNS failed,", upErr ); return }						// Resolve the remote address
		serverIpNet := wireguard.Ip2Net( client.Remote().IP )
		
		fmt.Println( "Main: Connecting to", serverIpNet.IP )																				// Add the throw route in order to reach Hide.me
		if upErr = link.ThrowRouteAdd( "VPN server", serverIpNet ); upErr != nil { return }
		defer link.ThrowRouteDel( "VPN server", serverIpNet )
	
		connectResponse, upErr := client.Connect( upCtx, link.PublicKey() )																	// Issue a REST Connect request
		if upErr != nil { if urlError, ok := upErr.( *url.Error ); ok { upErr = urlError.Unwrap() }; return }
		fmt.Println( "Main: Connected to", client.Remote() )
		connectResponse.Print()																												// Print the response attributes ( connection properties )
		
		if upErr = link.Up( connectResponse ); upErr != nil { fmt.Println( "Main: [ERR] Link up failed,", upErr ); return }					// Configure the wireguard interface, must succeed
		
		if connectResponse.StaleAccessToken && len( conf.Client.AccessTokenFile ) > 0 {														// When the Access-Token is stale and when it is kept saved refresh it
			go func() {
				if conf.Client.AccessTokenUpdateDelay > 0 {
					fmt.Println( "Main: Updating the Access-Token in", conf.Client.AccessTokenUpdateDelay )
					time.Sleep( conf.Client.AccessTokenUpdateDelay )
				}
				if tokenErr := client.GetAccessToken( upCtx ); tokenErr != nil { fmt.Println( "Main: [ERR] Access-Token update failed,", tokenErr ); return }
				fmt.Println( "Main: Access-Token updated" )
			} ()
		}
		
		if supported, notificationErr := daemon.SdNotify( false, daemon.SdNotifyReady ); supported && notificationErr != nil {				// Send SystemD ready notification
			fmt.Println( "Main: [ERR] SystemD notification failed,", notificationErr )
		}
		
		if !conf.Client.Filter.Empty() {																									// Apply filters
			switch filterErr := client.ApplyFilter(); filterErr {
				case nil: fmt.Println( "Main: Filters (", conf.Client.Filter.String(),") applied" )
				default: fmt.Println( "[ERR] Main: Filters (", conf.Client.Filter.String(), ") have not been applied,", filterErr )
			}
		}
		
		upErr = link.DPD( upCtx )																											// Start the dead peer detection loop
		if discoErr := client.Disconnect( connectResponse.SessionToken ); discoErr != nil { fmt.Println( "Main: [ERR] Disconnect POST failed,", discoErr ) }
		fmt.Println( "Main: Disconnected" )
		link.Down()																															// Remove the DNS, rules, routes, addresses and the peer, must succeed
		return
	}
	
	signalChannel := make ( chan os.Signal )																								// Signal handling
	signal.Notify( signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL )
	go up()																																	// Start the client for the first time
	
	connectLoop:
	for {
		select {
			case sig := <- signalChannel:
				fmt.Println( "Main: Terminating on", sig.String() )
				upCancelLock.Lock(); upCancelInSignal := upCancel; upCancelLock.Unlock()
				if upCancelInSignal != nil {																								// Client is running
					upCancelInSignal()																										// Cancelling the DPD context results in the client's termination
					<- upCh																													// Wait for the client to terminate
				}
				err = context.Canceled
				break connectLoop
			case err = <- upCh:
				fmt.Println( "Main: [ERR] Connection failed due to", err )
				switch err {
					case rest.ErrHttpStatusBad, rest.ErrAppUpdateRequired, rest.ErrBadPin, context.Canceled: break connectLoop				// These errors are fatal
					default:																												// Reconnect on any other error (context.DeadlineExceeded, wireguard.ErrDpdTimeout...)
						fmt.Println( "Main: Reconnecting in", conf.Client.ReconnectWait )
						time.AfterFunc( conf.Client.ReconnectWait, up )
						continue
				}
		}
	}
	if conf.Link.LeakProtection && err != context.Canceled {																				// Leak protection needs to be activated if the client stops for any reason other than context.Canceled
		fmt.Println( "Main: [ERR] Connection setup/teardown failed, traffic blocked, waiting for a termination signal" )
		<-signalChannel																														// The client won't exit yet because the traffic should be blocked until an operator intervenes
	}
	fmt.Println( "Main: Shutdown" )
	daemon.SdNotify( false, daemon.SdNotifyStopping )																						// Send SystemD notification
}

func main() {
	conf, command := configure()																											// Parse the command line flags and optionally read the configuration file
	if conf == nil { return }																												// Exit on configuration error
	
	switch command {
		case "conf": conf.Print()																											// Configuration dump
		case "token": accessToken( conf )																									// Access-Token
		case "connect": connect( conf )																										// Connect to the server
		case "categories": categories( conf )																								// Fetch the filtering categories JSON
	}
}