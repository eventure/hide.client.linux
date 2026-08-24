package connection

import (
	"net"
	"time"
	
	"github.com/eventure/hide.client.linux/rest"
)

const (
	Clean = "clean"
	Routed = "routed"
	Connecting = "connecting"
	Connected = "connected"
	TokenUpdate = "token update"
	TokenUpdateDone = "token update done"
	ConfigurationGet = "configuration get"
	ConfigurationSet = "configuration set"
	LogDump = "logs dumped"
	Disconnecting = "disconnecting"
	DpdTimeout = "dpd timeout"
	DnsLookup = "dns lookup"
	ExternalIps = "external ips"
)

type State struct {
	Code			string		`json:"code"`
	Timestamp		time.Time	`json:"timestamp"`
	*rest.ConnectResponse		`json:",omitempty"`
	Rx				int64		`json:"rx,omitempty"`
	Tx				int64		`json:"tx,omitempty"`
	Host			string		`json:"host,omitempty"`
	ExternalIpv4	net.IP		`json:"external_ip,omitempty"`
	ExternalIpv6	net.IP		`json:"external_ipv6,omitempty"`
}

func ( s *State ) SetCode( code string ) *State { s.Code, s.Timestamp = code, time.Now(); return s }
func ( s *State ) ClearIps() *State { s.ExternalIpv4 = nil; s.ExternalIpv6 = nil; return s }
func ( s *State ) SetIps( ip4, ip6 net.IP ) *State { s.ExternalIpv4 = ip4; s.ExternalIpv6 = ip6; return s }