package wireguard

import (
	"fmt"
	"github.com/vishvananda/netlink"
)

func (l *Link) RulesAdd() ( err error ) {
	if l.Config.IPv4 {
		rule := netlink.NewRule()
		rule.Priority = l.Config.RPDBPriority
		rule.Family = netlink.FAMILY_V4
		rule.Table = l.Config.RoutingTable
		if err = netlink.RuleAdd( rule ); err == nil { l.rule = rule; fmt.Println( "Link: IPv4 RPDB rule added" )
		} else { fmt.Println( "Link: [ERR] IPv4 RPDB rule addition failed,", err ) }
	}
	
	if l.Config.IPv6 {
		rule := netlink.NewRule()
		rule.Priority = l.Config.RPDBPriority
		rule.Family = netlink.FAMILY_V6
		rule.Table = l.Config.RoutingTable
		if err = netlink.RuleAdd( rule ); err == nil { l.rule6 = rule; fmt.Println( "Link: IPv6 RPDB rule added" )
		} else { fmt.Println( "Link: [ERR] IPv6 RPDB rule addition failed,", err ) }
	}
	return
}

func (l *Link) RulesDel() {
	if l.rule != nil {
		if err := netlink.RuleDel( l.rule ); err == nil { fmt.Println("Link: IPv4 RPDB rule removed" )
		} else { fmt.Println( "Link: [ERR] IPv4 RPDB rule removal failed,", err ) }
	}
	if l.rule6 != nil {
		if err := netlink.RuleDel( l.rule6 ); err == nil { fmt.Println("Link: IPv6 RPDB rule removed" )
		} else { fmt.Println( "Link: [ERR] IPv6 RPDB rule removal failed,", err ) }
	}
	return
}
