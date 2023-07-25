package main

import (
	"context"
	"fmt"
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Connection struct {
	sync.Mutex

	restClient		*rest.Client
	link			*wireguard.Link

	initStack		[]func()
	connectStack	[]func()
	response		*rest.ConnectResponse
	
	dpdTimer		*time.Timer
	lastRx			int64
	
	connectTimer	*time.Timer
	connectCancel	context.CancelFunc
}

func NewConnection( conf *Configuration ) *Connection { return &Connection{ link: wireguard.NewLink( conf.Link ), restClient: rest.New( conf.Client ) } }

func ( c *Connection ) Init() ( err error ) {
	defer func() { if err != nil { c.Shutdown() } } ()																							// If anything fails, undo changes
	c.Lock(); defer c.Unlock()
	
	if err = c.restClient.Init(); err != nil { fmt.Println( "Init: [ERR] REST Client setup failed,", err ); return }							// Initialize the REST client
	if !c.restClient.HaveAccessToken() { fmt.Println( "Init: [ERR] No Access-Token available" ); return }										// Access-Token is required for the Connect/Disconnect methods
	
	if err = c.link.Open(); err != nil { fmt.Println( "Init: [ERR] Wireguard open failed,", err ); return }										// Open or create a wireguard interface, auto-generate a private key when no private key has been configured
	c.initStack = append( c.initStack, c.link.Close )
	
	_, dhcpDestination, _ := net.ParseCIDR( "255.255.255.255/32" )																				// IPv4 DHCP VPN bypass "throw" route
	if err = c.link.ThrowRouteAdd( "DHCP bypass", dhcpDestination ); err != nil { fmt.Println( "Init: [ERR] DHCP bypass route failed,", err ); return }
	c.initStack = append( c.initStack, func() { _ = c.link.ThrowRouteDel( "DHCP bypass", dhcpDestination ) } )
	
	var udpAddr *net.UDPAddr
	for _, dnsServer := range strings.Split( c.restClient.Config.DnsServers, "," ) {															// throw routes for configured DNS servers
		if len( dnsServer ) == 0 { continue }
		if udpAddr, err = net.ResolveUDPAddr( "udp", dnsServer ); err != nil { fmt.Println( "Init: [ERR] DNS server address resolve failed,", err ); return }
		dns := wireguard.Ip2Net( udpAddr.IP )
		if err = c.link.ThrowRouteAdd( "DNS server", dns  ); err != nil { fmt.Println( "Init: [ERR] Route DNS server failed,", err ); return }
		c.initStack = append( c.initStack, func() { _ = c.link.ThrowRouteDel( "DNS server", dns ) } )
	}
	
	for _, network := range strings.Split( c.link.Config.SplitTunnel, "," ) {																	// throw routes for split-tunnel destinations
		if len( network ) == 0 { continue }
		_, ipNet, err := net.ParseCIDR( network )
		if err != nil { fmt.Println( "Init: [ERR] Parse split-tunnel route from", network, "failed,", err ); return err }
		if err = c.link.ThrowRouteAdd( "Split-Tunnel", ipNet ); err != nil { fmt.Println( "Init: [ERR] Split-tunnel route to ", network, "failed,", err ); return err }
		c.initStack = append( c.initStack, func() { _ = c.link.ThrowRouteDel( "Split-Tunnel", ipNet ) } )
	}
	
	if c.link.Config.LeakProtection {																											// Add the "loopback" default routes to the configured routing tables ( IP leak protection )
		if err = c.link.LoopbackRoutesAdd(); err != nil { fmt.Println( "Init: [ERR] Addition of loopback routes failed,", err ); return }
		c.initStack = append( c.initStack, c.link.LoopbackRoutesDel )
	}
	
	err = c.link.RulesAdd()																														// Add the RPDB rules which direct traffic to configured routing tables
	c.initStack = append( c.initStack, c.link.RulesDel )
	if err != nil { fmt.Println( "Init: [ERR] RPDB rules failed,", err ); return }
	fmt.Println( "Init: Done" )
	return
}

func ( c *Connection ) Shutdown() { c.Lock(); for i := len( c.initStack )-1; i >= 0; i-- { c.initStack[i]() }; c.initStack = c.initStack[:0]; c.Unlock() }

func ( c *Connection ) ScheduleConnect( in time.Duration ) {
	c.Lock(); defer c.Unlock()
	if c.connectTimer != nil { c.connectTimer.Stop() }
	c.connectTimer = time.AfterFunc( in, func() { _ = c.Connect() } )
	fmt.Println( "Conn: Connecting in", in )
}

func ( c *Connection ) Connect() ( err error ) {
	defer func() {
		switch err {
			case nil, context.Canceled: return																									// No error (successful connection) or a cancelled context (interrupted connection attempt) may not cause a reconnect
			case rest.ErrHttpStatusBad, rest.ErrAppUpdateRequired, rest.ErrBadPin: c.Disconnect(); return										// These errors are fatal, do not reconnect
			default: c.Disconnect(); c.ScheduleConnect( c.restClient.Config.ReconnectWait )
		}
	}()
	
	ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
	c.Lock(); c.connectCancel = cancel; c.Unlock()

	if err = c.restClient.Resolve( ctx ); err != nil { return }																					// Resolve the remote address
	serverIpNet := wireguard.Ip2Net( c.restClient.Remote().IP )
	
	c.Lock()
	if err = c.link.ThrowRouteAdd( "VPN server", serverIpNet ); err != nil { c.Unlock(); return }												// throw route towards the VPN server
	c.connectStack = append( c.connectStack, func() { _ = c.link.ThrowRouteDel( "VPN server", serverIpNet ) } )
	c.Unlock()
	
	fmt.Println( "Conn: Connecting to", serverIpNet.IP )																						// Add the throw route in order to reach Hide.me
	c.response, err = c.restClient.Connect( ctx, c.link.PublicKey() )																			// Issue a REST Connect request
	if err != nil { if urlError, ok := err.( *url.Error ); ok { err = urlError.Unwrap() }; fmt.Println( "Conn: [ERR] REST failed,", err.Error() ); return }
	c.response.Print()																															// Print the response attributes ( connection properties )
	c.Lock(); defer c.Unlock()																													// No errors, lock this Connection until done
	cancel()
	c.connectCancel = nil
	c.connectStack = append( c.connectStack, func() {
		ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
		defer cancel()
		switch err := c.restClient.Disconnect( ctx, c.response.SessionToken ); err {
			case nil: fmt.Println( "Conn: Disconnected" )
			default:  fmt.Println( "Conn: [ERR] Disconnect POST failed,", err )
		}
	})
	
	if err = c.link.Up( c.response ); err != nil { fmt.Println( "Conn: [ERR] Link up failed,", err ); return }									// Configure the wireguard interface (DNS, rules, routes, addresses and the peer), must succeed
	c.connectStack = append( c.connectStack, c.link.Down )
	
	if supported, err := daemon.SdNotify( false, daemon.SdNotifyReady ); supported && err != nil {												// Send SystemD ready notification
		fmt.Println( "Conn: [ERR] SystemD notification failed,", err )
	}

	if c.link.Config.DpdTimeout > 0 {																											// Start the dead peer detection loop when configured
		c.dpdTimer = time.AfterFunc( c.link.Config.DpdTimeout, c.DPD )
		c.connectStack = append( c.connectStack, func() { c.dpdTimer.Stop(); c.dpdTimer = nil } )
		fmt.Println( "Conn: DPD started" )
	}
	
	go c.AccessTokenRefresh()																													// Refresh the Access-Token when required
	go c.Filter()																																// Apply possible filters
	return
}

func ( c *Connection ) Disconnect() {
	c.Lock()
	if c.connectTimer != nil { c.connectTimer.Stop(); c.connectTimer = nil }																	// Stop a possible scheduled connect
	if c.connectCancel != nil { c.connectCancel() }																								// Stop a possible concurrent connect
	for i := len( c.connectStack )-1; i >= 0; i-- { c.connectStack[i]() }
	c.connectStack = c.connectStack[:0]
	c.Unlock()
}

func ( c *Connection ) AccessTokenRefresh() {
	if !c.response.StaleAccessToken { return }																									// Access token is not stale
	if len( c.restClient.Config.AccessTokenFile ) == 0 { return }																				// Access token is not stored
	fmt.Println( "AcRe: Updating the Access-Token in", c.restClient.Config.AccessTokenUpdateDelay )
	time.AfterFunc( c.restClient.Config.AccessTokenUpdateDelay, func() {
		ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
		defer cancel()
		if err := c.restClient.GetAccessToken( ctx ); err != nil { fmt.Println( "AcRe: [ERR] Access-Token update failed,", err ); return }
		fmt.Println( "AcRe: Access-Token updated" )
	})
}

func ( c *Connection ) Filter() {
	if c.restClient.Config.Filter.Empty() { return }
	ctx, cancel := context.WithTimeout( context.Background(), c.restClient.Config.RestTimeout )
	defer cancel()
	switch err := c.restClient.ApplyFilter( ctx ); err {
		case nil: fmt.Println( "Fltr: Filters (", c.restClient.Config.Filter.String(),") applied" )
		default:  fmt.Println( "Fltr: Filters (", c.restClient.Config.Filter.String(), ") have not been applied,", err )
	}
}

func ( c *Connection ) DPD() {
	c.dpdTimer.Reset( c.link.Config.DpdTimeout )
	currentRx, err := c.link.GetRx()
	if err != nil { fmt.Println( "DPD: Failed,", err.Error() ); c.Disconnect(); c.Shutdown(); return }
	if currentRx == c.lastRx { fmt.Println( "DPD: Timeout" ); c.lastRx = 0; c.Disconnect(); c.ScheduleConnect( c.restClient.Config.ReconnectWait ) }
	c.lastRx = currentRx
}