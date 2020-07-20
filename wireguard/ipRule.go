package wireguard

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"strings"
)

func (l *Link) RulesAdd() ( err error ) {
	if len( l.Config.SplitTunnel ) > 0 {
		for _, netString := range strings.Split( l.Config.SplitTunnel, "," ) {
			_, ipNet, err := net.ParseCIDR( strings.TrimSpace( netString ) )
			if err != nil { fmt.Println( "Link: [ERR] Parsing the split tunnel network", netString, "failed,", err ); return err }
			splitRule := netlink.NewRule()
			splitRule.Priority = 1
			if ipNet.IP.To4() != nil { splitRule.Family = netlink.FAMILY_V4 } else { splitRule.Family = netlink.FAMILY_V6 }
			splitRule.Table = 254
			splitRule.Dst = ipNet
			if err = netlink.RuleAdd( splitRule ); err != nil { fmt.Println( "Link: [ERR] Split tunnel rule addition for ", ipNet, "failed,", err ); continue }
			fmt.Println( "Link: Split tunnel rule for", ipNet, "added" )
			l.splitRules = append( l.splitRules, splitRule )
		}
	}
	
	rule := netlink.NewRule()
	rule.Priority = 1
	rule.Family = netlink.FAMILY_V4
	rule.Table = 254
	rule.Dst = netlink.NewIPNet( net.ParseIP( "255.255.255.255" ) )
	if err = netlink.RuleAdd( rule ); err == nil { l.dhcpRule = rule; fmt.Println( "Link: IPv4 DHCP VPN bypass RPDB rule added" )
	} else { fmt.Println( "Link: [ERR] IPv4 DHCP VPN bypass RPDB rule addition failed,", err ) }
	
	rule = netlink.NewRule()
	rule.Priority = 10
	rule.Family = netlink.FAMILY_V4
	rule.Table = l.Config.RoutingTable
	rule.Mark = l.Config.FirewallMark
	rule.Invert = true
	if err = netlink.RuleAdd( rule ); err == nil { l.markRule = rule; fmt.Println( "Link: IPv4 RPDB rule for non mark", l.Config.FirewallMark, "marked traffic added" )
	} else { fmt.Println( "Link: [ERR] IPv4 RPDB rule addition failed,", err ) }
	
	rule = netlink.NewRule()
	rule.Priority = 10
	rule.Family = netlink.FAMILY_V6
	rule.Table = l.Config.RoutingTable
	rule.Mark = l.Config.FirewallMark
	rule.Invert = true
	if err = netlink.RuleAdd( rule ); err == nil { l.markRule6 = rule; fmt.Println( "Link: IPv6 RPDB rule for non mark", l.Config.FirewallMark, "marked traffic added" )
	} else { fmt.Println( "Link: [ERR] IPv6 RPDB rule addition failed,", err ) }
	return
}

func (l *Link) RulesDel() {
	if l.dhcpRule != nil {
		if err := netlink.RuleDel( l.dhcpRule ); err == nil { fmt.Println("Link: IPv4 DHCP VPN bypass RPDB rule removed" )
		} else { fmt.Println( "Link: [ERR] IPv4 VPN bypass DHCP RPDB rule removal failed,", err ) }
	}
	for _, splitRule := range l.splitRules {
		if err := netlink.RuleDel( splitRule ); err == nil { fmt.Println("Link: Split tunnel rule for", splitRule.Dst, "removed" )
		} else { fmt.Println( "Link: [ERR] Removal of the split tunnel rule for", splitRule.Dst, "failed,", err ) }
	}
	if l.markRule != nil {
		if err := netlink.RuleDel( l.markRule ); err == nil { fmt.Println("Link: IPv4 RPDB rule removed" )
		} else { fmt.Println( "Link: [ERR] IPv4 RPDB rule removal failed,", err ) }
	}
	if l.markRule6 != nil {
		if err := netlink.RuleDel( l.markRule6 ); err == nil { fmt.Println("Link: IPv6 RPDB rule removed" )
		} else { fmt.Println( "Link: [ERR] IPv6 RPDB rule removal failed,", err ) }
	}
	return
}
