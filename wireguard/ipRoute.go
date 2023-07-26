package wireguard

import (
	"github.com/eventure/hide.client.linux/rest"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"strconv"
)

var Mask32 = net.CIDRMask( 32, 32 )
var Mask128 = net.CIDRMask( 128, 128 )

func routeString( route *netlink.Route ) ( routeString string ) {
	routeOnes, _ := route.Dst.Mask.Size()
	routeString = route.Dst.IP.String() + "/" + strconv.Itoa( routeOnes )
	if route.Gw != nil { routeString += " via " + route.Gw.String() }
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err == nil { routeString += " dev " + link.Attrs().Name }
	routeString += " mtu " + strconv.Itoa( route.MTU )
	if route.Table != 254 { routeString += " table " + strconv.Itoa( route.Table ) }
	return
}

func Ip2Net( ip net.IP ) *net.IPNet {
	if ip.To4() != nil { return &net.IPNet{ IP: ip, Mask: Mask32 } }
	return &net.IPNet{ IP: ip, Mask: Mask128 }
}

// Add the routes to the configured table
func (l *Link) ipRoutesAdd( response *rest.ConnectResponse ) ( err error ) {
	// Override default routes OpenVPN def1 style
	for _, gw := range response.Gateway {
		if gw.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		gatewayRoute := &netlink.Route{ LinkIndex: l.wireguardLink.Attrs().Index, Scope: unix.RT_SCOPE_LINK, Dst: netlink.NewIPNet( gw ), Protocol: unix.RTPROT_BOOT, Table: l.Config.RoutingTable, Type: unix.RTN_UNICAST, MTU: l.mtu }
		// Flags: unix.RTNH_F_ONLINK cannot be used due to missing support on IPv6 with the older kernels, host routes must be used instead
		// defaultRoute := &netlink.Route{ LinkIndex: l.wireguardLink.Attrs().Index, Scope: unix.RT_SCOPE_UNIVERSE, Gw: gw, Protocol: unix.RTPROT_BOOT, Table: l.Config.RoutingTable, Type: unix.RTN_UNICAST }
		if err = netlink.RouteAdd( gatewayRoute ); err != nil { log.Println( "Link: [ERR] Gateway route", routeString( gatewayRoute ), "addition failed:", err ); continue }
		log.Println( "Link: Gateway route", routeString( gatewayRoute ), "added" )
		l.gatewayRoutes = append( l.gatewayRoutes, gatewayRoute)
		
		routes := []netlink.Route(nil)
		if gw.To4() != nil {
			halfSpaceRoute := netlink.Route{
				LinkIndex: l.wireguardLink.Attrs().Index,
				Scope: unix.RT_SCOPE_UNIVERSE,
				Dst: &net.IPNet{ IP: net.ParseIP( "0.0.0.0" ), Mask: net.CIDRMask( 1, 32 ) },					// 0.0.0.0/1
				Gw: gw,
				Protocol: unix.RTPROT_BOOT,
				Table: l.Config.RoutingTable,
				Type: unix.RTN_UNICAST,
				MTU: l.mtu,
			}
			routes = append(routes, halfSpaceRoute )
			halfSpaceRoute.Dst = &net.IPNet{ IP: net.ParseIP( "128.0.0.0" ), Mask: net.CIDRMask( 1, 32 ) }		// 128.0.0.0/1
			routes = append(routes, halfSpaceRoute )
		} else {
			overrideRoute := netlink.Route{
				LinkIndex: l.wireguardLink.Attrs().Index,
				Scope: unix.RT_SCOPE_UNIVERSE,
				Dst: &net.IPNet{ IP: net.ParseIP( "::" ), Mask: net.CIDRMask( 3, 128 ) },						// ::/3
				Gw: gw,
				Protocol: unix.RTPROT_BOOT,
				Table: l.Config.RoutingTable,
				Type: unix.RTN_UNICAST,
				MTU: l.mtu,
			}
			routes = append(routes, overrideRoute )
			overrideRoute.Dst = &net.IPNet{ IP: net.ParseIP( "2000::" ), Mask: net.CIDRMask( 4, 128 ) }			// 2000::/4
			routes = append(routes, overrideRoute )
			overrideRoute.Dst = &net.IPNet{ IP: net.ParseIP( "3000::" ), Mask: net.CIDRMask( 4, 128 ) }			// 3000::/4
			routes = append(routes, overrideRoute )
			overrideRoute.Dst = &net.IPNet{ IP: net.ParseIP( "fc00::" ), Mask: net.CIDRMask( 7, 128 ) }			// fc00::/7
			routes = append(routes, overrideRoute )
		}
		
		for i, route := range routes {
			if err = netlink.RouteAdd( &route ); err != nil { log.Println( "Link: [ERR] Route", routeString( &route ), "addition failed:", err ); continue }
			log.Println( "Link: Route", routeString( &route ), "added" )
			l.routes = append( l.routes, &routes[i] )
		}
	}
	return
}

// Remove the default routes
func (l *Link) ipRoutesRemove() ( err error ) {
	for _, route := range l.routes {
		if err = netlink.RouteDel( route ); err != nil { log.Println( "Link: [ERR] Route", routeString( route ), "removal failed:", err ); continue }
		log.Println( "Link: Route", routeString( route ), "removed" )
	}
	l.routes = nil
	for _, route := range l.gatewayRoutes {
		if err = netlink.RouteDel( route ); err != nil { log.Println( "Link: [ERR] Gateway route", routeString( route ), "removal failed:", err ); continue }
		log.Println( "Link: Gateway route", routeString( route ), "removed" )
	}
	l.gatewayRoutes = nil
	return
}

// LoopbackRoutesAdd adds default routes to l.Config.RoutingTable table which point to loopback interface
func (l *Link) LoopbackRoutesAdd() ( err error ) {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	routes := []netlink.Route(nil)
	lo, err := net.InterfaceByName( "lo" )
	if err != nil { log.Println( "Link: [ERR] Loopback interface lookup failed:", err ); return }
	
	route := netlink.Route{																				// IPv4
		LinkIndex: lo.Index,
		Scope: unix.RT_SCOPE_UNIVERSE,
		Dst: &net.IPNet{ IP: net.ParseIP( "0.0.0.0" ), Mask: net.CIDRMask( 0, 32 ) },					// 0.0.0.0/0 - default
		Protocol: unix.RTPROT_BOOT,
		Table: l.Config.RoutingTable,
	}
	if l.Config.IPv4 { routes = append( routes, route ) }
	route.Dst = &net.IPNet{ IP: net.ParseIP( "::" ), Mask: net.CIDRMask( 0, 128 ) }						// ::/0 - default
	if l.Config.IPv6 { routes = append( routes, route ) }
	
	for i, route := range routes {
		if err = netlink.RouteAdd( &route ); err != nil { log.Println( "Link: [ERR] Loopback route", routeString( &route ), "addition failed:", err ); continue }
		log.Println( "Link: Loopback route", routeString( &route ), "added" )
		l.loopbackRoutes = append( l.loopbackRoutes, &routes[i] )
	}
	return
}

// LoopbackRoutesDel removes default routes from l.Config.RoutingTable table
func (l *Link) LoopbackRoutesDel() {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	for _, route := range l.loopbackRoutes {
		if err := netlink.RouteDel( route ); err != nil { log.Println( "Link: [ERR] Loopback route", routeString( route ), "removal failed:", err ); continue }
		log.Println( "Link: Loopback route", routeString( route ), "removed" )
	}
	l.loopbackRoutes = nil
}

// ThrowRouteAdd adds a "throw" route
func (l *Link) ThrowRouteAdd( logPrefix string, dst *net.IPNet ) ( err error ) {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	route := netlink.Route{
		Scope:      unix.RT_SCOPE_UNIVERSE,
		Dst:        dst,
		Protocol:   unix.RTPROT_BOOT,
		Table:		l.Config.RoutingTable,
		Type:       unix.RTN_THROW,
	}
	if err = netlink.RouteAdd( &route ); err != nil { log.Println( "Link: [ERR]", logPrefix, "throw route", routeString( &route ), "addition failed:", err ); return }
	log.Println( "Link:", logPrefix, "throw route", routeString( &route ), "added" )
	return
}

// ThrowRouteDel removes a "throw" route
func (l *Link) ThrowRouteDel( logPrefix string, dst *net.IPNet ) ( err error ) {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	route := netlink.Route{
		Scope:      unix.RT_SCOPE_UNIVERSE,
		Dst:        dst,
		Protocol:   unix.RTPROT_BOOT,
		Table:		l.Config.RoutingTable,
		Type:       unix.RTN_THROW,
	}
	if err = netlink.RouteDel( &route ); err != nil { log.Println( "Link: [ERR]", logPrefix, "throw route", routeString( &route ), "deletion failed:", err ); return }
	log.Println( "Link:", logPrefix, "throw route", routeString( &route ), "deleted" )
	return
}