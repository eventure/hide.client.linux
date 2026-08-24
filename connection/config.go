package connection

import (
	"reflect"
	
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
)

const (
	NO_CHANGE  = iota
	CHANGED
	CHANGED_REQUIRES_SHUTDOWN
)

type Config struct {
	Rest			*rest.Config
	WireGuard		*wireguard.Config
	DoH				*doh.Config
	Plain			*plain.Config
}

func ( c *Config ) Compare( d *Config ) ( changeType int ) {
	if c == nil { changeType = CHANGED_REQUIRES_SHUTDOWN; return }
	if c.Rest == nil { changeType = CHANGED_REQUIRES_SHUTDOWN; return }
	if c.WireGuard == nil { changeType = CHANGED_REQUIRES_SHUTDOWN; return }
	if c.DoH == nil { changeType = CHANGED; return }
	if c.Plain == nil { changeType = CHANGED; return }
	
	cRest, dRest := c.Rest, d.Rest
	
	if dRest.Host != cRest.Host { changeType |= CHANGED }
	if dRest.Port != cRest.Port { changeType |= CHANGED }
	if dRest.Domain != cRest.Domain { changeType |= CHANGED }
	if dRest.AccessTokenPath != cRest.AccessTokenPath { changeType |= CHANGED }
	if dRest.AccessToken != cRest.AccessToken { changeType |= CHANGED }
	if dRest.Username != cRest.Username { changeType |= CHANGED }
	if dRest.Password != cRest.Password { changeType |= CHANGED }
	if dRest.RestTimeout != cRest.RestTimeout { changeType |= CHANGED }
	if dRest.ReconnectWait != cRest.ReconnectWait { changeType |= CHANGED }
	if dRest.AccessTokenUpdateDelay != cRest.AccessTokenUpdateDelay { changeType |= CHANGED }
	
	if dRest.CA != cRest.CA { changeType |= CHANGED }
	if dRest.Mark != cRest.Mark { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if !reflect.DeepEqual( dRest.Filter, cRest.Filter ) { changeType |= CHANGED }
	if !reflect.DeepEqual( dRest.PortForward, cRest.PortForward ) { changeType |= CHANGED }
	if dRest.UseDoH != cRest.UseDoH { changeType |= CHANGED }
	
	cWg, dWg := c.WireGuard, d.WireGuard
	
	if dWg.Name != cWg.Name { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.ListenPort != cWg.ListenPort { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.Mark != cWg.Mark { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.RPDBPriority != cWg.RPDBPriority { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.PrivateKey != cWg.PrivateKey { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.RoutingTable != cWg.RoutingTable { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	if dWg.LeakProtection != cWg.LeakProtection { changeType |= CHANGED_REQUIRES_SHUTDOWN }
	
	if dWg.ResolvConfBackupFile != cWg.ResolvConfBackupFile { changeType |= CHANGED }
	if dWg.DpdTimeout != cWg.DpdTimeout { changeType |= CHANGED }
	if dWg.SplitTunnel != cWg.SplitTunnel { changeType |= CHANGED }
	if dWg.IPv4 != cWg.IPv4 { changeType |= CHANGED }
	if dWg.IPv6 != cWg.IPv6 { changeType |= CHANGED }
	
	if !reflect.DeepEqual( d.DoH, c.DoH ) { changeType |= CHANGED }
	if !reflect.DeepEqual( d.Plain, c.Plain ) { changeType |= CHANGED }
	return
}

// Apply applies the configuration in *d. c.Rest, c.WireGuard, c.DoH and c.Plain are held by their corresponding structs
func ( c *Config ) Apply( d *Config ) {
	if c.Rest != nil && d.Rest != nil { *c.Rest = *d.Rest }
	if c.WireGuard != nil && d.WireGuard != nil { *c.WireGuard = *d.WireGuard }
	if c.DoH != nil && d.DoH != nil { *c.DoH = *d.DoH }
	if c.Plain != nil && d.Plain != nil { *c.Plain = *d.Plain }
}