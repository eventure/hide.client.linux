package connection

import (
	"context"
	"log"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
)

const (
	Clean = "clean"
	Routed = "routed"
	Connecting = "connecting"
	Connected = "connected"
	TokenUpdate = "token update"
	ConfigurationGet = "configuration get"
	ConfigurationSet = "configuration set"
	LogDump = "logs dumped"
	Disconnecting = "disconnecting"
	DpdTimeout = "dpd timeout"
	DnsLookup = "dns lookup"
)

type State struct {
	Code			string		`json:"code"`
	Timestamp		time.Time	`json:"timestamp"`
	*rest.ConnectResponse		`json:",omitempty"`
	Rx				int64		`json:"rx,omitempty"`
	Tx				int64		`json:"tx,omitempty"`
	Host			string		`json:"host,omitempty"`
}

func ( s *State ) SetCode( code string ) *State { s.Code, s.Timestamp = code, time.Now(); return s }

type Config struct {
	Rest			*rest.Config
	Wireguard		*wireguard.Config
	DoH				*doh.Config
	Plain			*plain.Config
}

type Connection struct {
	sync.Mutex
	*Config

	restClient		*rest.Client
	link			*wireguard.Link
	dohResolver		*doh.Resolver
	plainResolver	*plain.Resolver

	initStack		[]func()
	connectStack	[]func()
	
	dpdTimer		*time.Timer
	lastRx			int64
	
	connectTimer	*time.Timer
	connectCancel	context.CancelFunc
	
	state			*State
	notifySystemd	bool

	connectNotify	func( err error )
	
	stateNotifyLock	sync.RWMutex
	stateNotifyFns	[]*func( state *State )
}

func New( config *Config ) *Connection { return &Connection{ Config: config, state: &State{ Code: Clean }, initStack: make( []func(), 0 ), connectStack: make( []func(), 0 ) } }
func ( c *Connection ) State() *State { c.Lock(); if c.state.Code == Connected { c.state.Rx, c.state.Tx, _ = c.link.Acct() }; c.Unlock(); return c.state }
func ( c *Connection ) Code() ( code string ) { c.Lock(); code = c.state.Code; c.Unlock(); return }
func ( c *Connection ) NotifySystemd( notifySystemd bool ) { c.notifySystemd = notifySystemd }
func ( c *Connection ) SetConnectNotify( connectNotify func(err error) ) { c.Lock(); c.connectNotify = connectNotify; c.Unlock() }

func ( c *Connection ) StateNotify( state *State ) { c.stateNotifyLock.RLock(); for _, stateNotifyFn := range c.stateNotifyFns { defer (*stateNotifyFn)( state ) }; c.stateNotifyLock.RUnlock() }
func ( c *Connection ) StateNotifyFnAdd( stateNotifyFn *func( state *State ) ) { c.stateNotifyLock.Lock(); c.stateNotifyFns = append( c.stateNotifyFns, stateNotifyFn ); c.stateNotifyLock.Unlock() }
func ( c *Connection ) StateNotifyFnDel( stateNotifyFn *func( state *State ) ) { c.stateNotifyLock.Lock(); c.stateNotifyFns = slices.DeleteFunc( c.stateNotifyFns, func( fn *func( state *State ) ) bool { return fn == stateNotifyFn } ); c.stateNotifyLock.Unlock() }

func ( c *Connection ) Init() ( err error ) {
	defer func() { if err != nil { c.Shutdown() } } ()																							// If anything fails, undo changes
	c.Lock(); defer c.Unlock()

	c.link = wireguard.New( c.Config.Wireguard )
	if err = c.link.Open(); err != nil { log.Println( "Init: [ERR] Wireguard open failed:", err ); return }										// Open or create a wireguard interface, auto-generate a private key when no private key has been configured
	c.initStack = append( c.initStack, c.link.Close )

	c.dohResolver = doh.New( c.Config.DoH )
	c.dohResolver.Init()																														// Initialize DoHResolver
	c.dohResolver.SetRouteOps( c.link )

	c.plainResolver = plain.New( c.Config.Plain )
	if err = c.plainResolver.Init(); err != nil { log.Println( "Init: [ERR] Plain resolver failed:", err ); return }
	c.plainResolver.SetRouteOps( c.link )

	_, dhcpDestination, _ := net.ParseCIDR( "255.255.255.255/32" )																				// IPv4 DHCP VPN bypass "throw" route
	if err = c.link.ThrowRouteAdd( "DHCP bypass", dhcpDestination ); err != nil { log.Println( "Init: [ERR] DHCP bypass route failed:", err ); return }
	c.initStack = append( c.initStack, func() { _ = c.link.ThrowRouteDel( "DHCP bypass", dhcpDestination ) } )

	if c.link.Config.LeakProtection {																											// Add the "loopback" default routes to the configured routing tables ( IP leak protection )
		if err = c.link.LoopbackRoutesAdd(); err != nil { log.Println( "Init: [ERR] Addition of loopback routes failed:", err ); return }
		c.initStack = append( c.initStack, c.link.LoopbackRoutesDel )
	}

	err = c.link.RulesAdd()																														// Add the RPDB rules which direct traffic to configured routing tables
	c.initStack = append( c.initStack, c.link.RulesDel )
	if err != nil { log.Println( "Init: [ERR] RPDB rules failed:", err ); return }

	c.restClient = rest.New( c.Config.Rest )
	if err = c.restClient.Init(); err != nil { log.Println( "Init: [ERR] REST Client setup failed:", err ); return }							// Initialize the REST client
	if !c.restClient.HaveAccessToken() { log.Println( "Init: [ERR] No Access-Token available" ); return }										// Access-Token is required for the Connect/Disconnect methods
	c.restClient.SetDohResolver( c.dohResolver )
	c.restClient.SetPlainResolver( c.plainResolver )

	c.StateNotify( c.state.SetCode( Routed ) )																									// Set state to routed
	log.Println( "Init: Done" )
	return
}

func ( c *Connection ) Shutdown() { c.Lock(); for i := len(c.initStack)-1; i >= 0; i-- { c.initStack[i]() }; c.initStack = c.initStack[:0]; c.StateNotify( c.state.SetCode( Clean ) ); c.Unlock() }

func ( c *Connection ) ScheduleConnect( in time.Duration ) {
	c.Lock()
	if c.connectTimer == nil { c.connectTimer = time.AfterFunc( in, c.Connect ) } else { c.connectTimer.Reset( in ) }
	c.state.Host = c.Config.Rest.Host																											// Set the hostname to Host
	log.Println( "Conn: Connecting in", in )
	c.Unlock()
}

func ( c *Connection ) Connect() {
	var err error
	defer func() {
		if err != nil { c.Disconnect() } else { c.StateNotify( c.state ) }																		// Disconnect/rewind stack on error, notify otherwise
		if c.connectNotify != nil { c.connectNotify( err ); c.connectNotify = nil }
	}()
	
	c.Lock()
	c.StateNotify( c.state.SetCode( Connecting ) )																								// Set state to connecting
	
	ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
	c.connectCancel = cancel
	
	for network := range strings.SplitSeq( c.link.Config.SplitTunnel, "," ) {																	// throw routes for split-tunnel destinations
		if len( network ) == 0 { continue }
		_, ipNet, parseErr := net.ParseCIDR( network )
		if parseErr != nil { log.Println( "Init: [ERR] Parse split-tunnel route from", network, "failed:", parseErr ); c.Unlock(); err = parseErr; return }
		if err = c.link.ThrowRouteAdd( "Split-Tunnel", ipNet ); err != nil { c.Unlock(); return }
		c.connectStack = append( c.connectStack, func() { _ = c.link.ThrowRouteDel( "Split-Tunnel", ipNet ) } )
	}
	c.Unlock()

	c.StateNotify( &State{ Code: DnsLookup, Timestamp: time.Now() } )																			// Broadcast "dns lookup" state
	if err = c.restClient.Resolve( ctx ); err != nil { log.Println( "Conn: [ERR] Resolve", c.Config.Rest.Host, "failed" ); return }				// Resolve the remote address
	serverIpNet := wireguard.Ip2Net( c.restClient.Remote().IP )
	c.StateNotify( c.state )																													// Rebroadcast "connecting"
	
	c.Lock()
	if c.link.Config.Mark == 0 {																												// throw route for VPN server's IP ( only when marks are not being used )
		if err = c.link.ThrowRouteAdd( "VPN server", serverIpNet ); err != nil { c.Unlock(); return }											// throw route towards the VPN server
		c.connectStack = append( c.connectStack, func() { _ = c.link.ThrowRouteDel( "VPN server", serverIpNet ) } )
	}
	c.Unlock()
	
	log.Println( "Conn: Connecting to", serverIpNet.IP )																						// Add the throw route in order to reach Hide.me
	c.state.ConnectResponse, err = c.restClient.Connect( ctx, c.link.PublicKey() )																// Issue a REST Connect request
	if err != nil { if urlError, ok := err.( *url.Error ); ok { err = urlError.Unwrap() }; log.Println( "Conn: [ERR] REST failed:", err.Error() ); return }
	c.state.ConnectResponse.Print()																												// Print the response attributes ( connection properties )
	c.Lock(); defer c.Unlock()																													// No errors, lock this Connection until done
	cancel()
	c.connectCancel = nil
	c.connectStack = append( c.connectStack, func() {
		ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
		defer cancel()
		switch err := c.restClient.Disconnect( ctx, c.state.ConnectResponse.SessionToken ); err {
			case nil: log.Println( "Conn: Disconnected" )
			default:  log.Println( "Conn: [ERR] Disconnect POST failed:", err )
		}
	})
	
	if err = c.link.Up( c.state.ConnectResponse ); err != nil { log.Println( "Conn: [ERR] Link up failed:", err ); return }						// Configure the wireguard interface (DNS, rules, routes, addresses and the peer), must succeed
	c.connectStack = append( c.connectStack, c.link.Down )
	
	if supported, err := daemon.SdNotify( false, daemon.SdNotifyReady ); c.notifySystemd && supported && err != nil {							// Send SystemD ready notification
		log.Println( "Conn: [ERR] SystemD notification failed:", err )
	}

	if c.link.Config.DpdTimeout > 0 {																											// Start the dead peer detection loop when configured
		c.dpdTimer = time.AfterFunc( c.link.Config.DpdTimeout, c.DPD )
		c.connectStack = append( c.connectStack, func() { c.dpdTimer.Stop(); c.dpdTimer = nil } )
		log.Println( "Conn: DPD started" )
	}
	
	go c.AccessTokenRefresh()																													// Refresh the Access-Token when required
	go c.Filter()																																// Apply possible filters
	go c.PortForward()																															// Activate port-forwarding
	c.state.SetCode( Connected )																												// Connection is running now so set state to connected
}

func ( c *Connection ) Disconnect() {
	c.Lock()
	c.StateNotify( c.state.SetCode( Disconnecting ) )
	if c.connectTimer != nil { c.connectTimer.Stop(); c.connectTimer = nil }																	// Stop a possible scheduled connect
	if c.connectCancel != nil { c.connectCancel(); c.connectCancel = nil  }																		// Stop a possible concurrent connect
	for i := len(c.connectStack)-1; i >= 0; i-- { c.connectStack[i]() }
	c.connectStack = c.connectStack[:0]
	c.state.ConnectResponse = nil
	c.state.Rx,c.state.Tx = 0, 0
	c.StateNotify( c.state.SetCode( Routed ) )																									// Set state to routed
	c.Unlock()
}

func ( c *Connection ) AccessTokenRefresh() {
	if !c.state.ConnectResponse.StaleAccessToken { return }																						// Access token is not stale
	if len( c.restClient.Config.AccessTokenPath ) == 0 { return }																				// Access token is not stored
	log.Println( "AcRe: Updating the Access-Token in", c.restClient.Config.AccessTokenUpdateDelay )
	time.AfterFunc( c.restClient.Config.AccessTokenUpdateDelay, func() {
		ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
		defer cancel()
		c.StateNotify( &State{ Code: TokenUpdate, Timestamp: time.Now() } )																		// TokenUpdate is a temporary client state
		if accessToken, err := c.restClient.GetAccessToken( ctx ); err != nil { log.Println( "AcRe: [ERR] Access-Token update failed:", err ); return } else { c.Config.Rest.AccessToken = accessToken }
		log.Println( "AcRe: Access-Token updated" )
		c.StateNotify( c.state )																												// Broadcast our state
	})
}

func ( c *Connection ) AccessTokenFetch() ( accessToken string, err error ) {
	c.Lock(); defer c.Unlock()
	restClient := rest.New( c.Config.Rest )
	if err = restClient.Init(); err != nil { log.Println( "AcFe: REST client failed:", err ); return }
	ctx, cancel := context.WithTimeout( context.Background(), c.Config.Rest.RestTimeout )
	defer cancel()
	c.StateNotify( &State{ Code: TokenUpdate, Timestamp: time.Now() } )																			// TokenUpdate is a temporary client state
	if err = restClient.Resolve( ctx ); err != nil {  log.Println( "AcFe: [ERR] Access-Token fetch ( resolve ) failed:", err ); return }
	if accessToken, err = restClient.GetAccessToken( ctx ); err != nil { log.Println( "AcFe: [ERR] Access-Token fetch failed:", err ); return }
	c.Config.Rest.AccessToken = accessToken
	c.StateNotify( c.state )																													// Broadcast our state
	log.Println( "AcFe: Access-Token updated" )
	return
}

func ( c *Connection ) Filter() {
	if c.restClient.Config.Filter.Empty() { return }
	ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
	defer cancel()
	switch err := c.restClient.ApplyFilter( ctx ); err {
		case nil: log.Println( "Fltr: Filters (", c.restClient.Config.Filter.String(),") applied" )
		default:  log.Println( "Fltr: Filters (", c.restClient.Config.Filter.String(), ") have not been applied:", err )
	}
}

func ( c *Connection ) PortForward() {
	if !c.restClient.Config.PortForward.Enabled { return }
	ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
	defer cancel()
	switch err := c.restClient.EnablePortForwarding( ctx ); err {
		case nil: log.Println( "PFwd: Port-Forwarding enabled" )
		default:  log.Println( "PFwd: Port-Forwarding has not been enabled:", err )
	}
}

func ( c *Connection ) DPD() {
	c.Lock()
	currentRx, err := c.link.GetRx()
	if err != nil { c.Unlock(); log.Println( "DPD: Failed:", err.Error() ); c.Disconnect(); c.Shutdown(); return }
	if currentRx == c.lastRx {
		c.lastRx = 0
		c.StateNotify( c.state.SetCode( DpdTimeout ) )
		c.Unlock()
		log.Println( "DPD: Timeout" )
		c.Disconnect()
		c.ScheduleConnect( c.restClient.Config.ReconnectWait )
		return
	}
	c.lastRx = currentRx
	c.dpdTimer.Reset( c.link.Config.DpdTimeout )
	c.Unlock()
}