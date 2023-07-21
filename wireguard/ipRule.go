package wireguard

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

func (l *Link) RulesAdd() ( err error ) {
	if l.Config.IPv4 {
		l.rule = netlink.NewRule()
		l.rule.Priority = l.Config.RPDBPriority
		l.rule.Family = netlink.FAMILY_V4
		l.rule.Table = l.Config.RoutingTable
		if err = netlink.RuleAdd( l.rule ); err != nil { fmt.Println( "Link: [ERR] IPv4 RPDB rule addition failed,", err ); return }
		fmt.Println( "Link: IPv4 RPDB rule added" )
	}
	
	if l.Config.IPv6 {
		l.rule6 = netlink.NewRule()
		l.rule6.Priority = l.Config.RPDBPriority
		l.rule6.Family = netlink.FAMILY_V6
		l.rule6.Table = l.Config.RoutingTable
		if err = netlink.RuleAdd( l.rule6 ); err != nil { fmt.Println( "Link: [ERR] IPv6 RPDB rule addition failed,", err ); return }
		fmt.Println( "Link: IPv6 RPDB rule added" )
	}
	return
}

func (l *Link) RulesDel() {
	if l.rule != nil {
		if err := netlink.RuleDel( l.rule ); err == nil { fmt.Println("Link: IPv4 RPDB rule removed" ) } else { fmt.Println( "Link: [ERR] IPv4 RPDB rule removal failed,", err ) }
	}
	if l.rule6 != nil {
		if err := netlink.RuleDel( l.rule6 ); err == nil { fmt.Println("Link: IPv6 RPDB rule removed" ) } else { fmt.Println( "Link: [ERR] IPv6 RPDB rule removal failed,", err ) }
	}
	return
}