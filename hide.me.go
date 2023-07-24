package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Set up and parse flags, read the configuration file
func configure() ( conf *Configuration, command string, err error ) {
	conf = NewConfiguration()
	if err = conf.Parse(); err != nil { return }
	
	switch command = strings.ToLower( flag.Arg(0) ); command {
		case "": flag.Usage()
		case "connect", "token", "conf", "categories": break
		default: fmt.Fprint( os.Stderr, "Unsupported command \"" + command + "\"\n\n" ); flag.Usage(); err = errors.New( "bad command" ); return
	}
	if err = conf.Check(); err != nil { fmt.Fprint( os.Stderr, "Configuration error: ", err, "\n" ); return }								// Check configuration
	return
}

// Get the Access-Token
func accessToken( conf *Configuration ) {
	if conf.Client.AccessTokenFile == "" { fmt.Println( "Main: [ERR] Access-Token must be stored to a file" ); return }
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if !client.HaveAccessToken() {																											// An old Access-Token may be used to obtain a new one, although that process may be done by "connect" too
		if err = conf.InteractiveCredentials(); err != nil { fmt.Println( "Main: [ERR] Credential error,", err ); return }					// Try to obtain the credentials through the terminal
	}
	if err = client.Resolve(); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }											// Resolve the REST endpoint
	if err = client.GetAccessToken(); err != nil { fmt.Println( "Main: [ERR] Access-Token request failed,", err ); return }					// Request an Access-Token
	fmt.Println( "Main: Access-Token stored in", conf.Client.AccessTokenFile )
	return
}

// Fetch and dump filtering categories
func categories( conf *Configuration ) {
	clientConf := conf.Client
	clientConf.Port = 443
	clientConf.CA = ""
	client, err := rest.NewClient( &clientConf )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if err = client.Resolve(); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }											// Resolve the REST endpoint
	if err = client.FetchCategoryList(); err != nil { fmt.Println( "Main: [ERR] GET request failed,", err ); return }						// Get JSON
	return
}

// Connect
func connect( conf *Configuration ) {
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if !client.HaveAccessToken() { fmt.Println( "Main: [ERR] No Access-Token available" ); return }											// Access-Token is required for the Connect/Disconnect methods
	
	link := wireguard.NewLink( conf.Link )
	if err = link.Open(); err != nil { fmt.Println( "Main: [ERR] Wireguard open failed,", err ); return }									// Open or create a wireguard interface, auto-generate a private key when no private key has been configured
	defer link.Close()
	
	_, dhcpDestination, _ := net.ParseCIDR( "255.255.255.255/32" )																			// IPv4 DHCP VPN bypass "throw" route
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
		
		if upErr = client.Resolve(); upErr != nil { fmt.Println( "Main: [ERR] DNS failed,", upErr ); return }								// Resolve the remote address
		serverIpNet := wireguard.Ip2Net( client.Remote().IP )
		
		fmt.Println( "Main: Connecting to", serverIpNet.IP )																				// Add the throw route in order to reach Hide.me
		if upErr = link.ThrowRouteAdd( "VPN server", serverIpNet ); upErr != nil { return }
		defer link.ThrowRouteDel( "VPN server", serverIpNet )
	
		connectResponse, upErr := client.Connect( link.PublicKey() )																		// Issue a REST Connect request
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
				if tokenErr := client.GetAccessToken(); tokenErr != nil { fmt.Println( "Main: [ERR] Access-Token update failed,", tokenErr ); return }
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
	conf, command, err := configure()																										// Parse the command line flags and optionally read the configuration file
	if conf == nil || err != nil { return }																									// Exit on configuration error
	
	switch command {
		case "conf": conf.Print()																											// Configuration dump
		case "token": accessToken( conf )																									// Access-Token
		case "connect": connect( conf )																										// Connect to the server
		case "categories": categories( conf )																								// Fetch the filtering categories JSON
	}
}