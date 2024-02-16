package wireguard

import (
	"github.com/vishvananda/netlink"
	"log"
	"net"
)

// Add the addresses to the wireguard interface
func (l *Link) ipAddrsAdd( addrs []net.IP ) ( err error ) {
	l.ips = []net.IP{}
	for _, addr := range addrs {
		if addr.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		if err = netlink.AddrAdd( l.wireguardLink, &netlink.Addr{ IPNet: netlink.NewIPNet( addr ) } ); err != nil {
			log.Println( "Link: [ERR] Addition of", addr.String(), "to interface", l.wireguardLink.Attrs().Name, "failed:", err )
			return
		}
		log.Println( "Link: Address", addr.String(), "added to interface", l.wireguardLink.Attrs().Name )
		l.ips = append( l.ips, addr )
	}
	return
}

// Remove addresses from the wireguard interface
func (l *Link) ipAddrsDel() ( err error ) {
	for _, addr := range l.ips {
		if addr.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		if err = netlink.AddrDel( l.wireguardLink, &netlink.Addr{ IPNet: netlink.NewIPNet( addr ) } ); err != nil {
			log.Println( "Link: [ERR] Removal of", addr.String(), "from interface", l.wireguardLink.Attrs().Name, "failed:", err )
			continue
		}
		log.Println( "Link: Address", addr.String(), "removed from interface", l.wireguardLink.Attrs().Name )
	}
	l.ips = nil
	return
}