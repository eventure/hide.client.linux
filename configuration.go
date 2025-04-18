package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/eventure/hide.client.linux/control"
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Configuration struct {
	Rest		*rest.Config		`yaml:"client,omitempty" json:",omitempty"`
	WireGuard	*wireguard.Config	`yaml:"link,omitempty" json:",omitempty"`
	Control		*control.Config		`yaml:"control,omitempty" json:",omitempty"`
	DoH			*doh.Config			`yaml:"doh,omitempty" json:",omitempty"`
	Plain		*plain.Config		`yaml:"plain,omitempty" json:",omitempty"`
}

func NewConfiguration() *Configuration {
	h := &Configuration{														// Defaults
		WireGuard: &wireguard.Config{
			Name:					"vpn",										// command line option "-i"
			ListenPort:				0,											// command line option "-l"
			Mark:					0,											// command line option "-m"
			RoutingTable:			55555,										// command line option "-r"
			RPDBPriority:			10,											// command line option "-R"
			LeakProtection:			true,										// command line option "-k"
			ResolvConfBackupFile:	"",											// command line option "-b"
			DpdTimeout:				time.Minute,								// command line option "-dpd"
			SplitTunnel:			"",											// command line option "-s"
			IPv4:					true,										// command line options "-4" and "-6"
			IPv6:					true,										// command line options "-4" and "-6"
		},
		Rest: &rest.Config{
			APIVersion:				"v1.0.0",									// Not configurable
			Host:           		"",											// command line option "-n"
			Port:					432,										// command line option "-p"
			Domain:					"hide.me",									// Not configurable
			CA:						"CA.pem",									// command line option "-ca"
			AccessTokenPath:		"accessToken.txt",							// command line option "-t"
			Username:       		"",											// command line option "-u"
			Password:				"",											// Only configurable through the config file
			RestTimeout:	 		90 * time.Second,							// Only configurable through the config file
			ReconnectWait:	 		30 * time.Second,							// Only configurable through the config file
			AccessTokenUpdateDelay: 2 * time.Second,							// Only configurable through the config file
			Mark:					0,											// command line option "-m"
			UseDoH:					true,										// command line option "-doh"
		},
		Control: &control.Config{
			Address:				"@hide.me",									// command line option "-caddr"
			LineLogBufferSize:		65535,										// command like option "-cllbs". Log buffer will remember 65536 log lines, when set to 0 there will be no buffering
		},
		DoH: &doh.Config {
			Servers: []string{
				"sdns://AgYAAAAAAAAADjE0OS4xMTIuMTEyLjEwILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczEwLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",		// dns10.quad9.net:443/dns-query 149.112.112.10:443
				"sdns://AgYAAAAAAAAACDkuOS45LjEwILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczEwLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",				// dns10.quad9.net:443/dns-query 9.9.9.10:443
				"sdns://AgYAAAAAAAAADjE0OS4xMTIuMTEyLjEwILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczEwLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",		// dns10.quad9.net:5053/dns-query 149.112.112.10:443
				"sdns://AgYAAAAAAAAACDkuOS45LjEwILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczEwLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",				// dns10.quad9.net:5053/dns-query 9.9.9.10:443
				"sdns://AgMAAAAAAAAADjE0OS4xMTIuMTEyLjExILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczExLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",		// dns11.quad9.net:443/dns-query 149.112.112.11:443
				"sdns://AgMAAAAAAAAACDkuOS45LjExILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczExLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",				// dns11.quad9.net:443/dns-query 9.9.9.11:443
				"sdns://AgMAAAAAAAAADjE0OS4xMTIuMTEyLjExILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczExLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",		// dns11.quad9.net:5053/dns-query 149.112.112.11:443
				"sdns://AgMAAAAAAAAACDkuOS45LjExILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczExLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",				// dns11.quad9.net:5053/dns-query 9.9.9.11:443
				"sdns://AgYAAAAAAAAADjE0OS4xMTIuMTEyLjEyILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczEyLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",		// dns12.quad9.net:443/dns-query 149.112.112.12:443
				"sdns://AgYAAAAAAAAACDkuOS45LjEyILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvE2RuczEyLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",				// dns12.quad9.net:443/dns-query 9.9.9.12:443
				"sdns://AgYAAAAAAAAADjE0OS4xMTIuMTEyLjEyILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczEyLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",		// dns12.quad9.net:5053/dns-query 149.112.112.12:443
				"sdns://AgYAAAAAAAAACDkuOS45LjEyILAZIHRLu3bJqwU-AeB7fgUORz0g95976kNfr-Q8nSQvFGRuczEyLnF1YWQ5Lm5ldDo1MDUzCi9kbnMtcXVlcnk",				// dns12.quad9.net:5053/dns-query 9.9.9.12:443
				"sdns://AgMAAAAAAAAADTE0OS4xMTIuMTEyLjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8SZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk",			// dns9.quad9.net:443/dns-query 149.112.112.9:443
				"sdns://AgMAAAAAAAAABzkuOS45LjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8SZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk",					// dns9.quad9.net:443/dns-query 9.9.9.9:443
				"sdns://AgMAAAAAAAAADTE0OS4xMTIuMTEyLjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8TZG5zOS5xdWFkOS5uZXQ6NTA1MwovZG5zLXF1ZXJ5",			// dns9.quad9.net:5053/dns-query 149.112.112.9:443
				"sdns://AgMAAAAAAAAABzkuOS45LjkgsBkgdEu7dsmrBT4B4Ht-BQ5HPSD3n3vqQ1-v5DydJC8TZG5zOS5xdWFkOS5uZXQ6NTA1MwovZG5zLXF1ZXJ5",					// dns9.quad9.net:5053/dns-query 9.9.9.9:443
				"sdns://AgMAAAAAAAAADzE0OS4xMTIuMTEyLjExMiCwGSB0S7t2yasFPgHge34FDkc9IPefe-pDX6_kPJ0kLxFkbnMucXVhZDkubmV0OjQ0MwovZG5zLXF1ZXJ5",			// dns.quad9.net:443/dns-query 149.112.112.112:443
				"sdns://AgMAAAAAAAAADzE0OS4xMTIuMTEyLjExMiCwGSB0S7t2yasFPgHge34FDkc9IPefe-pDX6_kPJ0kLxJkbnMucXVhZDkubmV0OjUwNTMKL2Rucy1xdWVyeQ",		// dns.quad9.net:5053/dns-query 149.112.112.112:443
			},
			UpdateURLs: []string{
				"https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
			},
			Filename: "resolvers.txt",
		},
		Plain: &plain.Config{
			Servers: []string{ "209.250.251.37:53", "217.182.206.81:53" },
		},
	}
	return h
}

func ( c *Configuration ) Read( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	bytes, err := os.ReadFile( fileName )
	if err != nil { if pathErr, ok := err.(*os.PathError); ok { return pathErr.Unwrap() }; return }
	if bytes[0] == '{' { err = json.Unmarshal( bytes, c ) } else { err = yaml.Unmarshal( bytes, c ) }
	return
}

func ( c *Configuration ) Store( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	configurationYaml, err := yaml.Marshal( c )
	if err != nil { return }
	err = os.WriteFile(fileName, configurationYaml, 0400)
	return
}

func ( c *Configuration ) Print() {
	if out, err := yaml.Marshal( c ); err != nil { log.Println( err ) } else { fmt.Print( string( out ) ) }
	return
}

func ( c *Configuration ) PrintJson() {
	if out, err := json.MarshalIndent( c, "", "\t" ); err != nil { log.Println( err ) } else { log.Print( string( out ) ) }
	return
}

func ( c *Configuration ) Parse() ( err error ) {
	configurationFileName := flag.String( "c", "", "Configuration `filename`" )																		// General flags
		
	flag.Int   	 ( "p",  c.Rest.Port, "remote `port`" )																								// REST related flags
	flag.String	 ( "ca", c.Rest.CA, "CA certificate bundle `filename`" )
	flag.String	 ( "t",  c.Rest.AccessTokenPath, "access token `filename`" )
	flag.String	 ( "u",  c.Rest.Username, "hide.me `username`" )
	flag.String	 ( "P",  c.Rest.Password, "hide.me `password`" )
	flag.Bool	 ( "pf", c.Rest.PortForward.Enabled, "enable port-forwarding (uPnP and NAT-PMP)" )
	
	flag.String	 ( "d",   strings.Join(c.Plain.Servers, ","), "comma separated list of `DNS servers` used for client requests" )					// Resolvers related flags
	flag.Bool	 ( "doh", c.Rest.UseDoH, "Use DNS-over-HTTPs" )
	
	flag.Bool	 ( "forceDns",		c.Rest.Filter.ForceDns, "force tunneled DNS handling on hide.me servers" )										// Filtering related flags
	flag.Bool	 ( "noAds",			c.Rest.Filter.Ads, "filter ads" )
	flag.Bool	 ( "noTrackers",	c.Rest.Filter.Trackers, "filter trackers" )
	flag.Bool	 ( "noMalware",		c.Rest.Filter.Malware, "filter malware" )
	flag.Bool	 ( "noMalicious",	c.Rest.Filter.Malicious, "filter malicious destinations" )
	flag.Int	 ( "pg",			c.Rest.Filter.PG, "apply a parental guidance style `age` filter (12, 18)" )
	flag.Bool	 ( "safeSearch",	c.Rest.Filter.SafeSearch, "force safe search with search engines" )
	flag.String  ( "noRisk",		strings.Join( c.Rest.Filter.Risk, "," ), "filter content according to risk `level` (possible, medium, high)" )
	flag.String  ( "noIllegal",		strings.Join( c.Rest.Filter.Illegal, "," ), "filter illegal `kind` (content, warez, spyware, copyright)" )
	flag.String  ( "noCategories",	strings.Join( c.Rest.Filter.Categories, "," ), "comma separated list of filtered content `categories`" )
	flag.String  ( "whitelist",		strings.Join( c.Rest.Filter.Categories, "," ), "comma separated list of allowed `dns names`" )
	flag.String  ( "blacklist",		strings.Join( c.Rest.Filter.Categories, "," ), "comma separated list of filtered `dns names`" )
	
	flag.String  ( "i",   c.WireGuard.Name, "network `interface` name" )																			// Link related flags
	flag.Int     ( "l",   c.WireGuard.ListenPort, "listen `port`" )
	flag.Int     ( "m",   c.WireGuard.Mark, "firewall `mark` for wireguard and hide.me client originated traffic" )
	flag.Int     ( "r",   c.WireGuard.RoutingTable, "routing `table` to use" )
	flag.Int     ( "R",   c.WireGuard.RPDBPriority, "RPDB rule `priority`" )
	flag.Bool	 ( "k",   c.WireGuard.LeakProtection, "enable/disable leak protection a.k.a. kill-switch" )
	flag.String  ( "b",   c.WireGuard.ResolvConfBackupFile, "resolv.conf backup `filename`" )
	flag.Duration( "dpd", c.WireGuard.DpdTimeout, "DPD `timeout`" )
	flag.String  ( "s",   c.WireGuard.SplitTunnel, "comma separated list of `networks` (CIDRs) for which to bypass the VPN" )
	flag.Bool	 ( "4",   false, "Use IPv4 tunneling only" )
	flag.Bool	 ( "6",   false, "Use IPv6 tunneling only" )
	
	flag.String  ( "caddr", c.Control.Address, "Control interface listen `address`" )																// Control interface related flags
	flag.String  ( "ccert", c.Control.Certificate, "Control interface `certificate` file" )
	flag.String  ( "ckey",  c.Control.Key, "Control interface `key` file" )
	flag.Int	 ( "cllbs",  c.Control.LineLogBufferSize, "Control interface line log buffer `size`" )
	
	flag.Usage = func() {
		_, _ = fmt.Fprint( os.Stderr, "Usage:\n  ", os.Args[0], " [options...] <command> [host]\n\n" )
		_, _ = fmt.Fprint( os.Stderr, "command:\n" )
		_, _ = fmt.Fprint( os.Stderr, "  token - request an Access-Token (required for connect)\n" )
		_, _ = fmt.Fprint( os.Stderr, "  connect - connect to a vpn server\n" )
		_, _ = fmt.Fprint( os.Stderr, "  conf - generate a configuration file to be used with the -c option\n" )
		_, _ = fmt.Fprint( os.Stderr, "  categories - fetch and dump filtering category list\n" )
		_, _ = fmt.Fprint( os.Stderr, "  service - run in remotely controlled service mode\n" )
		_, _ = fmt.Fprint( os.Stderr, "  updateDoh - update DNS-over-HTTPs server list\n" )
		_, _ = fmt.Fprint( os.Stderr, "  resolve - resolve host using DNS-over-HTTPs\n" )
		_, _ = fmt.Fprint( os.Stderr, "  lookup - resolve host using DNS\n" )
		_, _ = fmt.Fprint( os.Stderr, "host:\n" )
		_, _ = fmt.Fprint( os.Stderr, "  fqdn, short name or an IP address of a hide.me server\n" )
		_, _ = fmt.Fprint( os.Stderr, "  Required when the configuration file does not contain it\n\n" )
		_, _ = fmt.Fprint( os.Stderr, "options:\n" )
		flag.PrintDefaults()
	}
	flag.Parse()
	
	if len( *configurationFileName ) > 0 { if err = c.Read( *configurationFileName ); err != nil { log.Println( "Conf: [ERR] Read", *configurationFileName, "failed:", err.Error() ); return } }
	
	flag.Visit( func( f *flag.Flag ) {																																			// Parse flags
		switch f.Name {
			case "p":				c.Rest.Port, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: Port malformed" ) }								// REST related flags
			case "ca":				c.Rest.CA = f.Value.String()
			case "t":				c.Rest.AccessTokenPath = f.Value.String()
			case "u":				c.Rest.Username = f.Value.String()
			case "P":				c.Rest.Password = f.Value.String()
			case "pf":			   	c.Rest.PortForward.Enabled = f.Value.String() == "true"
		
			case "d":				c.Plain.Servers = strings.Split( f.Value.String(), "," )																					// Resolvers related flags
			case "doh":				if f.Value.String() == "false" { c.Rest.UseDoH = false }
		
			case "forceDns":    	c.Rest.Filter.ForceDns = f.Value.String() == "true"																							// Filtering related flags
			case "noAds":       	c.Rest.Filter.Ads = f.Value.String() == "true"
			case "noTrackers":  	c.Rest.Filter.Trackers = f.Value.String() == "true"
			case "noMalware":   	c.Rest.Filter.Malware = f.Value.String() == "true"
			case "noMalicious": 	c.Rest.Filter.Malicious = f.Value.String() == "true"
			case "pg":        		c.Rest.Filter.PG, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: PG malformed" ) }
			case "safeSearch":		c.Rest.Filter.SafeSearch = f.Value.String() == "true"
			case "noRisk":			c.Rest.Filter.Risk = strings.Split( f.Value.String(), "," )
			case "noIllegal":		c.Rest.Filter.Illegal = strings.Split( f.Value.String(), "," )
			case "noCategories":	c.Rest.Filter.Categories = strings.Split( f.Value.String(), "," )
			case "whitelist":		c.Rest.Filter.Whitelist = strings.Split( f.Value.String(), "," )
			case "blacklist":		c.Rest.Filter.Blacklist = strings.Split( f.Value.String(), "," )
			
			case "i":   			c.WireGuard.Name = f.Value.String()																											// WireGuard related flags
			case "l":   			c.WireGuard.ListenPort, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: ListenPort malformed" ) }
			case "m":   			c.WireGuard.Mark, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: FirewallMark malformed" ) }
									c.Rest.Mark = c.WireGuard.Mark
			case "R":   			c.WireGuard.RPDBPriority, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: RPDBPriority malformed" ) }
			case "r":   			c.WireGuard.RoutingTable, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: RoutingTable malformed" ) }
			case "k":   			if f.Value.String() == "false" { c.WireGuard.LeakProtection = false }
			case "b":   			c.WireGuard.ResolvConfBackupFile = f.Value.String()
			case "dpd": 			c.WireGuard.DpdTimeout, err = time.ParseDuration( f.Value.String() ); if err != nil { log.Println( "Conf: DpdTimeout malformed" ) }
			case "s":   			c.WireGuard.SplitTunnel = f.Value.String()
			case "4":   			if f.Value.String() == "true" { c.WireGuard.IPv4 = true; c.WireGuard.IPv6 = false }
			case "6":   			if f.Value.String() == "true" { c.WireGuard.IPv4 = false; c.WireGuard.IPv6 = true }
		
			case "caddr":			c.Control.Address = f.Value.String()																										// Control interface related flags
			case "ccert":			c.Control.Certificate = f.Value.String()
			case "ckey":			c.Control.Key = f.Value.String()
			case "cllbs":			c.Control.LineLogBufferSize, err = strconv.Atoi( f.Value.String() ); if err != nil { log.Println( "Conf: LineLogBufferSize malformed" ) }
		}
		if err != nil { return }
	})
	return
}