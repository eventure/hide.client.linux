package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/configuration"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Set up and parse flags, read the configuration file
func configure() ( conf *configuration.HideGuardConfiguration, command string ) {
	conf = configuration.NewHideGuardConfiguration()
	configurationFileName := flag.String( "c", "", "Configuration `filename`" )																// General flags
	
	flag.Int   ( "p",  conf.Client.Port, "remote `port`" )																					// REST related flags
	flag.String( "ca", conf.Client.CA, "CA certificate bundle" )
	flag.String( "t",  conf.Client.AccessTokenFile, "access token filename" )
	flag.String( "u",  conf.Client.Username, "hide.me `username`" )
	flag.String( "P",  conf.Client.Password, "hide.me `password`" )
	flag.String( "d",  conf.Client.DnsServers, "comma separated list of `DNS servers` used for client requests" )
	
	flag.String  ( "i",   conf.Link.Name, "network `interface` name" )																		// Link related flags
	flag.Int     ( "l",   conf.Link.ListenPort, "listen `port`" )
	flag.Int     ( "m",   conf.Link.FirewallMark, "firewall `mark` for wireguard and hide.me client originated traffic" )
	flag.Int     ( "r",   conf.Link.RoutingTable, "routing `table` to use" )
	flag.Bool	 ( "k",   conf.Link.LeakProtection, "enable/disable leak protection a.k.a. kill-switch" )
	flag.String  ( "b",   conf.Link.ResolvConfBackupFile, "resolv.conf backup `filename`" )
	flag.Duration( "dpd", conf.Link.DpdTimeout, "DPD timeout" )
	flag.String  ( "s",   conf.Link.SplitTunnel, "comma separated list of `networks` (CIDRs) for which to bypass the VPN" )
	flag.Bool	 ( "4",   false, "Use IPv4 tunneling only" )
	flag.Bool	 ( "6",   false, "Use IPv6 tunneling only" )
	
	flag.Usage = func() {
		fmt.Fprint( os.Stderr, "Usage:\n  ", os.Args[0], " [options...] <command> [host]\n\n" )
		fmt.Fprint( os.Stderr, "command:\n" )
		fmt.Fprint( os.Stderr, "  token - request an Access-Token (required for connect)\n" )
		fmt.Fprint( os.Stderr, "  connect - connect to a vpn server\n" )
		fmt.Fprint( os.Stderr, "  conf - generate a configuration file to be used with the -c option\n\n" )
		fmt.Fprint( os.Stderr, "host:\n" )
		fmt.Fprint( os.Stderr, "  fqdn, short name or an IP address of a hide.me server\n" )
		fmt.Fprint( os.Stderr, "  Required when the configuration file does not contain it\n\n" )
		fmt.Fprint( os.Stderr, "options:\n" )
		flag.PrintDefaults()
	}
	flag.Parse()
	
	switch command = strings.ToLower( flag.Arg(0) ); command {
		case "connect", "token", "conf": break
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
			case "p": conf.Client.Port, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: Port malformed" ) }		// REST related flags
			case "ca": conf.Client.CA = f.Value.String()
			case "t": conf.Client.AccessTokenFile = f.Value.String()
			case "u": conf.Client.Username = f.Value.String()
			case "P": conf.Client.Password = f.Value.String()
			case "d": conf.Client.DnsServers = f.Value.String()
		
			case "i": conf.Link.Name = f.Value.String()																						// Link related flags
			case "l": conf.Link.ListenPort, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: ListenPort malformed" ) }
			case "m": conf.Link.FirewallMark, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: FirewallMark malformed" ) }
					  conf.Client.FirewallMark = conf.Link.FirewallMark
			case "r": conf.Link.RoutingTable, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: RoutingTable malformed" ) }
			case "k": if f.Value.String() == "false" { conf.Link.LeakProtection = false }
			case "b": conf.Link.ResolvConfBackupFile = f.Value.String()
			case "dpd": conf.Link.DpdTimeout, err = time.ParseDuration( f.Value.String() ); if err != nil { fmt.Println( "conf: DpdTimeout malformed" ) }
			case "s": conf.Link.SplitTunnel = f.Value.String()
			case "4": if f.Value.String() == "true" { conf.Link.IPv4 = true; conf.Link.IPv6 = false }
			case "6": if f.Value.String() == "true" { conf.Link.IPv4 = false; conf.Link.IPv6 = true }
		}
	})
	if err != nil { return nil, "" }
	if hostName := flag.Arg(1); hostName != "" { conf.Client.Host = hostName }
	
	if err = conf.Check(); err != nil { fmt.Fprint( os.Stderr, "Configuration error: ", err, "\n" ); return nil, "" }						// Check configuration
	conf.AdjustHost()																														// Add .hideservers.net suffix where appropriate
	return
}

// Get the Access-Token
func accessToken( conf *configuration.HideGuardConfiguration ) {
	if conf.Client.AccessTokenFile == "" { fmt.Println( "Main: [ERR] Access-Token must be stored to a file" ); return }
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if ! client.HaveAccessToken() {																											// An old Access-Token may be used to obtain a new one, although that process may be done by "connect" too
		if err = conf.InteractiveCredentials(); err != nil { fmt.Println( "Main: [ERR] Credential error,", err ); return }					// Try to obtain the credentials through the terminal
	}
	if err = client.Resolve(); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }											// Resolve the REST endpoint
	if err = client.GetAccessToken(); err != nil { fmt.Println( "Main: [ERR] Access-Token request failed,", err ); return }					// Request an Access-Token
	fmt.Println( "Main: Access-Token stored in", conf.Client.AccessTokenFile )
	return
}

// Connect
func connect( conf *configuration.HideGuardConfiguration ) {
	client, err := rest.NewClient( &conf.Client )																							// Create the REST client
	if err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if ! client.HaveAccessToken() { fmt.Println( "Main: [ERR] No Access-Token available" ); return }										// Access-Token is required for the Connect/Disconnect methods
	
	link := wireguard.NewLink( conf.Link )
	if err = link.Open(); err != nil { fmt.Println( "Main: [ERR] Wireguard open failed,", err ); return }									// Open or create a wireguard interface, auto-generate a private key when no private key has been configured
	defer link.Close()
	err = link.RulesAdd(); defer link.RulesDel()																							// Add the mark based RPDB rules which direct traffic to configured routing tables
	if err != nil { fmt.Println( "Main: [ERR] RPDB rules failed,", err ); return }
	if conf.Link.LeakProtection {																											// Add the "loopback" default routes to the configured routing tables ( IP leak protection )
		err = link.LoopbackRoutesAdd(); defer link.LoopbackRoutesDel()
		if err != nil { fmt.Println( "Main: [ERR] Addition of loopback routes failed,", err ); return }
	}
	
	dpdContext, dpdCancel := context.Context(nil), context.CancelFunc(nil)
	go func() {																																// Wait for signals
		signalChannel := make ( chan os.Signal )
		signal.Notify( signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL )
		for { receivedSignal := <- signalChannel; fmt.Println( "Main: Terminating on", receivedSignal.String() ); dpdCancel() }				// Cancelling the DPD context results in the client's termination
	}()

	connectLoop:
	for {
		dpdContext, dpdCancel = context.WithTimeout( context.Background(), time.Second * 86380 )											// Hide.me sessions last up to 86400 seconds ( 20 seconds of slack should be enough for DNS and connection establishment )
		if err = client.Resolve(); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); break }										// Resolve the remote address
		fmt.Println( "Main: Connecting to", client.Remote() )
		connectResponse, connectErr := client.Connect( link.PublicKey() )																	// Connect
		if connectErr != nil {
			if urlError, ok := connectErr.( *url.Error ); ok {
				if urlError.Unwrap() == context.DeadlineExceeded {																			// When the connection attempt timed out, try again
					fmt.Println( "Main: [ERR] Connection timed out, reconnecting in", conf.Client.ConnectTimeout )
					select {
					case <- dpdContext.Done(): break connectLoop
					case <- time.After( conf.Client.ConnectTimeout ): continue connectLoop
					}
				}
			}
			fmt.Println( "Main: [ERR] Connect failed,", connectErr ); err = connectErr
			break
		}
		fmt.Println( "Main: Connected to", client.Remote() )
		connectResponse.Print()																												// Print the response attributes ( connection properties )
		
		if err = link.Up( connectResponse ); err != nil { fmt.Println( "Main: [ERR] Link up failed,", err ); break }						// Configure the wireguard interface, must succeed
		
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
		
		if _, err := daemon.SdNotify( false, daemon.SdNotifyReady ); err != nil { fmt.Println( err, "Main: SystemD notification failed" ) }	// Send SystemD notification
		dpdErr := link.DPD( dpdContext )																									// Start the dead peer detection loop
		if err = client.Disconnect( connectResponse.SessionToken ); err != nil { fmt.Println( "Main: [ERR] Disconnect failed,", err )
		} else { fmt.Println( "Main: Disconnected" ) }
		
		if err = link.Down(); err != nil { fmt.Println( "Main: [ERR] link down failed,", err ); break }										// Remove the DNS, rules, routes, addresses and the peer, must succeed
		switch dpdErr {
			case context.Canceled: break connectLoop																						// DPD was explicitly cancelled
			case wireguard.ErrTooManyPeers: break connectLoop																				// Wireguard interface has more than one peer defined
			case context.DeadlineExceeded, wireguard.ErrDpdTimeout: continue connectLoop													// Reconnect when there's a DPD timeout or when this session times out
		}
	}
	if err != nil {																															// For loop exit happened because of an error
		fmt.Println( "Main: [ERR] Connection setup/teardown failed, traffic blocked, waiting for a termination signal" )					// The client won't exit yet because the traffic should be blocked until an operator intervenes
		dpdContext, dpdCancel = context.WithCancel( context.Background() )
		<- dpdContext.Done()
	}
	daemon.SdNotify( false, daemon.SdNotifyStopping )																						// Send SystemD notification
}

func main() {
	conf, command := configure()																											// Parse the command line flags and optionally read the configuration file
	if conf == nil { return }																												// Exit on configuration error
	
	switch command {
		case "conf": conf.Print()																											// Configuration dump
		case "token": accessToken( conf )																									// Access-Token
		case "connect": connect( conf )																										// Connect to the server
	}
}
