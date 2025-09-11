package plain

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net"
	"syscall"
	"time"
	
	"golang.org/x/sys/unix"
)

type RouteOps interface {
	ThrowRouteAdd( logPrefix string, dst *net.IPNet ) ( err error )
	ThrowRouteDel( logPrefix string, dst *net.IPNet ) ( err error )
}

type Config struct {
	Servers		[]string		`yaml:"servers,omitempty"`										// DNS server IP addresses
}

type Resolver struct {
	*Config
	dialer		*net.Dialer
	mark		int
	routeOps	RouteOps
}

func New( config *Config ) *Resolver { if config == nil { config = &Config{} }; return &Resolver{ Config: config } }
func (d *Resolver) SetRouteOps(routeOps RouteOps) { d.routeOps = routeOps }
func (d *Resolver) SetMark(mark int) { d.mark = mark }

func (d *Resolver) Init() ( err error ) {
	for _, server := range d.Servers {
		if _, addrErr := net.ResolveUDPAddr("udp", server); addrErr != nil { log.Println( "Init: Bad DNS server endpoint", server ); return addrErr }
	}
	d.dialer = &net.Dialer{																		// Use a custom dialer to set the socket mark on sockets when those are configured
		Control: func( network, address string, rawConn syscall.RawConn ) ( err error ) {
			if d.mark == 0 { return }
			_ = rawConn.Control( func( fd uintptr ) {
				if err = syscall.SetsockoptInt( int(fd), unix.SOL_SOCKET, unix.SO_MARK, d.mark ); err != nil { log.Println( "Dial: [ERR] Set mark failed:", err ) }
			})
			return
		},
	}
	log.Println( "Init: Using", len( d.Config.Servers ), "DNS servers")
	return
}

func ( d *Resolver ) Resolve( ctx context.Context, name string ) ( ips []net.IP, err error ) {
	if len(d.Config.Servers) == 0 { err = errors.New( "empty DNS server list" ); return }
	
	endpoint := d.Config.Servers[ rand.Intn( len(d.Config.Servers) ) ]							// Random DNS server
	resolver := &net.Resolver{ PreferGo: true, Dial: func(ctx context.Context, network string, addr string) (net.Conn, error) { return d.dialer.DialContext( ctx, network, endpoint ) } }
	
	if d.routeOps != nil {																		// Add a throw route when required
		host, _, _ := net.SplitHostPort(endpoint)
		if ip := net.ParseIP(host); ip != nil {
			mask := net.CIDRMask(128,128)
			if ip4 := ip.To4(); ip4 != nil { ip, mask = ip4, net.CIDRMask(32,32) }
			if err = d.routeOps.ThrowRouteAdd( "DNS server " + endpoint, &net.IPNet{IP: ip, Mask: mask }); err != nil { return nil, err }
			defer d.routeOps.ThrowRouteDel( "DNS server " + endpoint, &net.IPNet{IP: ip, Mask: mask } )
		}
	}
	
	dnsCtx, cancel := context.WithTimeout( ctx, time.Second * 5 )
	addrs, err := resolver.LookupIPAddr( dnsCtx, name )
	cancel()
	if err != nil { log.Println( "Name: [ERR]", name, "lookup failed:", err ); return }
	for _, addr := range addrs { if addr.IP == nil { continue }; ips = append( ips, addr.IP ) }
	return
}