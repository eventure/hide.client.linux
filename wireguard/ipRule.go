package wireguard

import (
	"github.com/vishvananda/netlink"
	"log"
)

func (l *Link) RulesAdd() ( err error ) {
	if l.Config.IPv4 {
		l.rule = netlink.NewRule()
		l.rule.Priority = l.Config.RPDBPriority
		l.rule.Family = netlink.FAMILY_V4
		l.rule.Table = l.Config.RoutingTable
		l.rule.Mark = uint32(l.Config.Mark)						// mark is zero - route all traffic to this routing table, make exceptions by installing throw routes
		if l.Config.Mark > 0 { l.rule.Invert = true }			// mark is set  - skip this routing table for marked traffic, route all other traffic to this table
		if err = netlink.RuleAdd( l.rule ); err != nil { log.Println( "Link: [ERR] IPv4 RPDB rule addition failed:", err ); return }
		log.Println( "Link: IPv4 RPDB rule added" )
	}
	
	if l.Config.IPv6 {
		l.rule6 = netlink.NewRule()
		l.rule6.Priority = l.Config.RPDBPriority
		l.rule6.Family = netlink.FAMILY_V6
		l.rule6.Table = l.Config.RoutingTable
		l.rule6.Mark = uint32(l.Config.Mark)					// mark is zero - route all traffic to this routing table, make exceptions by installing throw routes
		if l.Config.Mark > 0 { l.rule6.Invert = true }			// mark is set  - skip this routing table for marked traffic, route all other traffic to this table
		if err = netlink.RuleAdd( l.rule6 ); err != nil { log.Println( "Link: [ERR] IPv6 RPDB rule addition failed:", err ); return }
		log.Println( "Link: IPv6 RPDB rule added" )
	}
	return
}

func (l *Link) RulesDel() {
	if l.rule != nil {
		if err := netlink.RuleDel( l.rule ); err == nil { log.Println("Link: IPv4 RPDB rule removed" ) } else { log.Println( "Link: [ERR] IPv4 RPDB rule removal failed:", err ) }
	}
	if l.rule6 != nil {
		if err := netlink.RuleDel( l.rule6 ); err == nil { log.Println("Link: IPv6 RPDB rule removed" ) } else { log.Println( "Link: [ERR] IPv6 RPDB rule removal failed:", err ) }
	}
}