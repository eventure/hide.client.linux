package wireguard

import (
	"fmt"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
)

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

// Add the routes to the configured table
func (l *Link) ipRoutesAdd( response *rest.ConnectResponse ) ( err error ) {
	// Override default routes OpenVPN def1 style
	for _, gw := range response.Gateway {
		if gw.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		gatewayRoute := &netlink.Route{ LinkIndex: l.wireguardLink.Attrs().Index, Scope: unix.RT_SCOPE_LINK, Dst: netlink.NewIPNet( gw ), Protocol: unix.RTPROT_BOOT, Table: l.Config.RoutingTable, Type: unix.RTN_UNICAST, MTU: l.mtu }
		// Flags: unix.RTNH_F_ONLINK cannot be used due to missing support on IPv6 with the older kernels, host routes must be used instead
		// defaultRoute := &netlink.Route{ LinkIndex: l.wireguardLink.Attrs().Index, Scope: unix.RT_SCOPE_UNIVERSE, Gw: gw, Protocol: unix.RTPROT_BOOT, Table: l.Config.RoutingTable, Type: unix.RTN_UNICAST }
		if err = netlink.RouteAdd( gatewayRoute ); err != nil { fmt.Println( "Link: [ERR] Gateway route", routeString( gatewayRoute ), "addition failed,", err ); continue }
		fmt.Println( "Link: Gateway route", routeString( gatewayRoute ), "added" )
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
			if err = netlink.RouteAdd( &route ); err != nil { fmt.Println( "Link: [ERR] Route", routeString( &route ), "addition failed,", err ); continue }
			fmt.Println( "Link: Route", routeString( &route ), "added" )
			l.routes = append( l.routes, &routes[i] )
		}
	}
	return
}

// Remove the default routes
func (l *Link) ipRoutesRemove() ( err error ) {
	for _, route := range l.routes {
		if err = netlink.RouteDel( route ); err != nil { fmt.Println( "Link: [ERR] Route", routeString( route ), "removal failed,", err ); continue }
		fmt.Println( "Link: Route", routeString( route ), "removed" )
	}
	l.routes = nil
	for _, route := range l.gatewayRoutes {
		if err = netlink.RouteDel( route ); err != nil { fmt.Println( "Link: [ERR] Gateway route", routeString( route ), "removal failed,", err ); continue }
		fmt.Println( "Link: Gateway route", routeString( route ), "removed" )
	}
	l.gatewayRoutes = nil
	return
}

// Add loopback default routes to l.Config.RoutingTable table
func (l *Link) LoopbackRoutesAdd() ( err error ) {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	routes := []netlink.Route(nil)
	lo, err := net.InterfaceByName( "lo" )
	if err != nil { fmt.Println( "Link: [ERR] Loopback interface lookup failed,", err ); return }
	
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
		if err = netlink.RouteAdd( &route ); err != nil { fmt.Println( "Link: [ERR] Loopback route", routeString( &route ), "addition failed,", err ); continue }
		fmt.Println( "Link: Loopback route", routeString( &route ), "added" )
		l.loopbackRoutes = append( l.loopbackRoutes, &routes[i] )
	}
	return
}

// Remove default routes from l.Config.RoutingTable table
func (l *Link) LoopbackRoutesDel() {
	switch l.Config.RoutingTable { case 0, 253, 254, 255: return }										// Skip for unspecified, default, main and local routing tables
	for _, route := range l.loopbackRoutes {
		if err := netlink.RouteDel( route ); err != nil { fmt.Println( "Link: [ERR] Loopback route", routeString( route ), "removal failed,", err ); continue }
		fmt.Println( "Link: Loopback route", routeString( route ), "removed" )
	}
	l.loopbackRoutes = nil
}