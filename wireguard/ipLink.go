package wireguard

import (
	"github.com/vishvananda/netlink"
	"log"
)

// Open an existing interface or create a new one
func ( l *Link ) ipLinkUp() ( err error ) {
	l.wireguardLink, err = netlink.LinkByName( l.Config.Name )
	if err != nil {
		switch err.(type) {
			case netlink.LinkNotFoundError: break
			default: return err
		}
		if err = netlink.LinkAdd( &netlink.GenericLink{ LinkAttrs: netlink.LinkAttrs{ Name: l.Config.Name }, LinkType:  "wireguard" }); err != nil { return }
		if l.wireguardLink, err = netlink.LinkByName( l.Config.Name ); err != nil { log.Println( "Link: [ERR] Interface lookup", l.Config.Name, "failed:", err ); return }
		if err = netlink.LinkSetUp( l.wireguardLink ); err != nil { log.Println( "Link: [ERR] Interface activation", l.Config.Name, "failed:", err ); return }
		log.Println( "Link: Wireguard interface", l.Config.Name, "activated" )
	} else {
		log.Println( "Link: Using wireguard interface", l.Config.Name )
	}
	return
}

func ( l *Link ) ipLinkSetMtu() ( err error ) {
	err = netlink.LinkSetMTU( l.wireguardLink, l.mtu )
	if err != nil { log.Println( "Link: [ERR] Set interface", l.Config.Name, "MTU to", l.mtu, "failed:", err ); return }
	log.Println( "Link: Interface", l.Config.Name, "MTU set to", l.mtu )
	return
}

// Shut down and remove a wireguard interface
func ( l *Link ) ipLinkDown() ( err error ) {
	if l.wireguardLink == nil { return }
	if err = netlink.LinkSetDown( l.wireguardLink ); err != nil { log.Println( "Link: [ERR] Deactivation of interface", l.Config.Name, "failed:", err ); return }
	if err = netlink.LinkDel( l.wireguardLink ); err != nil { log.Println( "Link: [ERR] Removal of interface", l.Config.Name, "failed:", err ); return }
	l.wireguardLink = nil
	log.Println( "Link: Interface", l.Config.Name, "deactivated" )
	return
}