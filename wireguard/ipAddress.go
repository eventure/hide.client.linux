package wireguard

import (
	"github.com/vishvananda/netlink"
	"log"
	"net"
)

// Add the addresses to the wireguard interface
func (l *Link) ipAddrsAdd( addrs []net.IP ) ( err error ) {
	for _, addr := range addrs {
		if addr.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		if err = netlink.AddrAdd( l.wireguardLink, &netlink.Addr{ IPNet: netlink.NewIPNet( addr ) } ); err != nil {
			log.Println( "Link: [ERR] Addition of", addr.String(), "to interface", l.wireguardLink.Attrs().Name, "failed:", err )
			return
		}
		log.Println( "Link: Address", addr.String(), "added to interface", l.wireguardLink.Attrs().Name )
	}
	return
}

// Flushes all addresses from the wireguard interface
func (l *Link) ipAddrsFlush() ( err error ) {
	addrs, err := netlink.AddrList( l.wireguardLink, netlink.FAMILY_ALL )
	if err != nil { log.Println( "Link: [ERR] Failed to list IP addresses:", err ); return }
	for _, addr := range addrs {
		if addr.IP.To4() != nil { if ! l.Config.IPv4 { continue } } else { if ! l.Config.IPv6 { continue } }
		if err = netlink.AddrDel( l.wireguardLink, &addr ); err != nil {
			log.Println( "Link: [ERR]", addr.IP.String(), "removal from from interface", l.wireguardLink.Attrs().Name, "failed:", err )
			return
		}
		log.Println( "Link:", addr.IP.String(), "removed from interface", l.wireguardLink.Attrs().Name )
	}
	return
}