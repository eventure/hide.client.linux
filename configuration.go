package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"gopkg.in/yaml.v2"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Configuration struct {
	Client	rest.Config			`yaml:"client,omitempty"`
	Link	wireguard.Config	`yaml:"link,omitempty"`
}

func NewConfiguration() *Configuration {
	h := &Configuration{														// Defaults
		Link: wireguard.Config{
			Name:					"vpn",										// command line option "-i"
			ListenPort:				0,											// command line option "-l"
			FirewallMark:			0,											// command line option "-m"
			RoutingTable:			55555,										// command line option "-r"
			RPDBPriority:			10,											// command line option "-R"
			LeakProtection:			true,										// command line option "-k"
			ResolvConfBackupFile:	"",											// command line option "-b"
			DpdTimeout:				time.Minute,								// command line option "-dpd"
			SplitTunnel:			"",											// command line option "-s"
			IPv4:					true,										// command line options "-4" and "-6"
			IPv6:					true,										// command line options "-4" and "-6"
		},
		Client: rest.Config{
			APIVersion:				"v1.0.0",									// Not configurable
			Host:           		"",											// command line option "-n"
			Port:					432,										// command line option "-p"
			Domain:					"hide.me",									// Not configurable
			CA:						"CA.pem",									// command line option "-ca"
			AccessTokenFile:		"accessToken.txt",							// command line option "-t"
			Username:       		"",											// command line option "-u"
			Password:				"",											// Only configurable through the config file
			RestTimeout:	 		10 * time.Second,							// Only configurable through the config file
			ReconnectWait:	 		30 * time.Second,							// Only configurable through the config file
			AccessTokenUpdateDelay: 2 * time.Second,							// Only configurable through the config file
			FirewallMark:			0,											// command line option "-m"
			DnsServers:				"209.250.251.37:53,217.182.206.81:53",		// command line option "-d"
		},
	}
	return h
}

func ( c *Configuration ) Read( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	bytes, err := os.ReadFile( fileName )
	if err != nil { if pathErr, ok := err.(*os.PathError); ok { return pathErr.Unwrap() }; return }
	err = yaml.Unmarshal( bytes, c )
	return
}

func ( c *Configuration ) Store( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	configurationYaml, err := yaml.Marshal( c )
	if err != nil { return }
	err = os.WriteFile(fileName, configurationYaml, 0400)
	return
}

func ( c *Configuration ) Check() ( err error ) {
	if c.Client.Domain != "hide.me" { err = errors.New( "configured domain mismatch" ); return }
	if len( c.Client.Host ) == 0 { err = errors.New( "missing hostname" ); return }
	if c.Client.Port == 0 { err = errors.New( "bad remote port " + strconv.Itoa( c.Client.Port ) ); return }
	if len( c.Link.Name ) == 0 { err = errors.New( "missing wireGuard interface name" ); return }
	if c.Link.DpdTimeout == 0 { err = errors.New( "dpd timeout not set" ); return }
	if c.Link.DpdTimeout > time.Minute { err = errors.New( "dpd timeout above 1 minute" ); return }
	if c.Client.Port == 443 {
		fmt.Println( "conf: [WARNING] Using port 443, API unstable" )
		c.Client.APIVersion = "v1"
	}
	return
}

// AdjustHost adds .hideservers.net suffix for short names ( nl becomes nl.hideservers.net ) or removes .hide.me and replaces it with .hideservers.net.
func ( c *Configuration ) AdjustHost() {
	if c.Client.Host == "" { return }
	if net.ParseIP( c.Client.Host ) != nil { return }
	if strings.HasSuffix( c.Client.Host, ".hideservers.net" ) { return }
	c.Client.Host = strings.TrimSuffix( c.Client.Host, ".hide.me" )
	c.Client.Host += ".hideservers.net"
}

func ( c *Configuration ) Print() {
	if out, err := yaml.Marshal( c ); err != nil { fmt.Println( err ) } else { fmt.Print( string( out ) ) }
	return
}

func ( c *Configuration ) Parse() ( err error ) {
	configurationFileName := flag.String( "c", "", "Configuration `filename`" )																// General flags
		
	flag.Int   ( "p",  c.Client.Port, "remote `port`" )																						// REST related flags
	flag.String( "ca", c.Client.CA, "CA certificate bundle `filename`" )
	flag.String( "t",  c.Client.AccessTokenFile, "access token `filename`" )
	flag.String( "u",  c.Client.Username, "hide.me `username`" )
	flag.String( "P",  c.Client.Password, "hide.me `password`" )
	flag.String( "d",  c.Client.DnsServers, "comma separated list of `DNS servers` used for client requests" )
	
	flag.Bool	 ( "forceDns",		c.Client.Filter.ForceDns, "force tunneled DNS handling on hide.me servers" )							// Filtering related flags
	flag.Bool	 ( "noAds",			c.Client.Filter.Ads, "filter ads" )
	flag.Bool	 ( "noTrackers",	c.Client.Filter.Trackers, "filter trackers" )
	flag.Bool	 ( "noMalware",		c.Client.Filter.Malware, "filter malware" )
	flag.Bool	 ( "noMalicious",	c.Client.Filter.Malicious, "filter malicious destinations" )
	flag.Int	 ( "pg",			c.Client.Filter.PG, "apply a parental guidance style `age` filter (12, 18)" )
	flag.Bool	 ( "safeSearch",	c.Client.Filter.SafeSearch, "force safe search with search engines" )
	flag.String  ( "noRisk",		strings.Join( c.Client.Filter.Risk, "," ), "filter content according to risk `level` (possible, medium, high)" )
	flag.String  ( "noIllegal",		strings.Join( c.Client.Filter.Illegal, "," ), "filter illegal `kind` (content, warez, spyware, copyright)" )
	flag.String  ( "noCategories",	strings.Join( c.Client.Filter.Categories, "," ), "comma separated list of filtered content `categories`" )
	flag.String  ( "whitelist",		strings.Join( c.Client.Filter.Categories, "," ), "comma separated list of allowed `dns names`" )
	flag.String  ( "blacklist",		strings.Join( c.Client.Filter.Categories, "," ), "comma separated list of filtered `dns names`" )
	
	flag.String  ( "i",   c.Link.Name, "network `interface` name" )																			// Link related flags
	flag.Int     ( "l",   c.Link.ListenPort, "listen `port`" )
	flag.Int     ( "m",   c.Link.FirewallMark, "firewall `mark` for wireguard and hide.me client originated traffic" )
	flag.Int     ( "r",   c.Link.RoutingTable, "routing `table` to use" )
	flag.Int     ( "R",   c.Link.RPDBPriority, "RPDB rule `priority`" )
	flag.Bool	 ( "k",   c.Link.LeakProtection, "enable/disable leak protection a.k.a. kill-switch" )
	flag.String  ( "b",   c.Link.ResolvConfBackupFile, "resolv.conf backup `filename`" )
	flag.Duration( "dpd", c.Link.DpdTimeout, "DPD `timeout`" )
	flag.String  ( "s",   c.Link.SplitTunnel, "comma separated list of `networks` (CIDRs) for which to bypass the VPN" )
	flag.Bool	 ( "4",   false, "Use IPv4 tunneling only" )
	flag.Bool	 ( "6",   false, "Use IPv6 tunneling only" )
	
	flag.Usage = func() {
		fmt.Fprint( os.Stderr, "Usage:\n  ", os.Args[0], " [options...] <command> [host]\n\n" )
		fmt.Fprint( os.Stderr, "command:\n" )
		fmt.Fprint( os.Stderr, "  token - request an Access-Token (required for connect)\n" )
		fmt.Fprint( os.Stderr, "  connect - connect to a vpn server\n" )
		fmt.Fprint( os.Stderr, "  conf - generate a configuration file to be used with the -c option\n" )
		fmt.Fprint( os.Stderr, "  categories - fetch and dump filtering category list\n\n" )
		fmt.Fprint( os.Stderr, "host:\n" )
		fmt.Fprint( os.Stderr, "  fqdn, short name or an IP address of a hide.me server\n" )
		fmt.Fprint( os.Stderr, "  Required when the configuration file does not contain it\n\n" )
		fmt.Fprint( os.Stderr, "options:\n" )
		flag.PrintDefaults()
	}
	flag.Parse()
	
	if len( *configurationFileName ) > 0 { if err = c.Read( *configurationFileName ); err != nil { fmt.Println( "Configuration file error:", err.Error() ); return } }
	
	flag.Visit( func( f *flag.Flag ) {																																		// Parse flags
		switch f.Name {
			case "p":				c.Client.Port, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: Port malformed" ) }							// REST related flags
			case "ca":				c.Client.CA = f.Value.String()
			case "t":				c.Client.AccessTokenFile = f.Value.String()
			case "u":				c.Client.Username = f.Value.String()
			case "P":				c.Client.Password = f.Value.String()
			case "d":				c.Client.DnsServers = f.Value.String()
			
			case "forceDns":    	c.Client.Filter.ForceDns = f.Value.String() == "true"																					// Filtering related flags
			case "noAds":       	c.Client.Filter.Ads = f.Value.String() == "true"
			case "noTrackers":  	c.Client.Filter.Trackers = f.Value.String() == "true"
			case "noMalware":   	c.Client.Filter.Malware = f.Value.String() == "true"
			case "noMalicious": 	c.Client.Filter.Malicious = f.Value.String() == "true"
			case "pg":        		c.Client.Filter.PG, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: PG malformed" ) }
			case "safeSearch":		c.Client.Filter.SafeSearch = f.Value.String() == "true"
			case "noRisk":			c.Client.Filter.Risk = strings.Split( f.Value.String(), "," )
			case "noIllegal":		c.Client.Filter.Illegal = strings.Split( f.Value.String(), "," )
			case "noCategories":	c.Client.Filter.Categories = strings.Split( f.Value.String(), "," )
			case "whitelist":		c.Client.Filter.Whitelist = strings.Split( f.Value.String(), "," )
			case "blacklist":		c.Client.Filter.Blacklist = strings.Split( f.Value.String(), "," )
			
			case "i":   			c.Link.Name = f.Value.String()																											// Link related flags
			case "l":   			c.Link.ListenPort, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: ListenPort malformed" ) }
			case "m":   			c.Link.FirewallMark, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: FirewallMark malformed" ) }
									c.Client.FirewallMark = c.Link.FirewallMark
			case "R":   			c.Link.RPDBPriority, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: RPDBPriority malformed" ) }
			case "r":   			c.Link.RoutingTable, err = strconv.Atoi( f.Value.String() ); if err != nil { fmt.Println( "conf: RoutingTable malformed" ) }
			case "k":   			if f.Value.String() == "false" { c.Link.LeakProtection = false }
			case "b":   			c.Link.ResolvConfBackupFile = f.Value.String()
			case "dpd": 			c.Link.DpdTimeout, err = time.ParseDuration( f.Value.String() ); if err != nil { fmt.Println( "conf: DpdTimeout malformed" ) }
			case "s":   			c.Link.SplitTunnel = f.Value.String()
			case "4":   			if f.Value.String() == "true" { c.Link.IPv4 = true; c.Link.IPv6 = false }
			case "6":   			if f.Value.String() == "true" { c.Link.IPv4 = false; c.Link.IPv6 = true }
		}
		if err != nil { return }
	})
	c.Client.Host = flag.Arg(1)
	c.AdjustHost()																																							// Add .hideservers.net suffix where appropriate
	return
}