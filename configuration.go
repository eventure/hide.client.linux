package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/eventure/hide.client.linux/control"
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"gopkg.in/yaml.v2"
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

func ( c *Configuration ) Print() { if out, err := yaml.Marshal( c ); err != nil { log.Println( err ) } else { fmt.Print( string( out ) ) } }
func ( c *Configuration ) PrintJson() { if out, err := json.MarshalIndent( c, "", "\t" ); err != nil { log.Println( err ) } else { log.Print( string( out ) ) } }

func ( c *Configuration ) Parse() ( err error ) {
	configurationFileName := flag.StringP( "config", "c", "", "Configuration `filename`" )																// Configuration flag

	flag.IntVarP		( &c.Rest.Port,						"port",	"p",			c.Rest.Port, "remote `port`" )										// REST flags
	flag.StringVar		( &c.Rest.CA,						"ca",					c.Rest.CA, "CA certificate bundle `filename`" )
	flag.StringVarP		( &c.Rest.AccessTokenPath,			"tokenFile", "t",		c.Rest.AccessTokenPath, "access token `filename`" )
	flag.StringVarP		( &c.Rest.Username,					"username", "u",		c.Rest.Username, "hide.me `username`" )
	flag.StringVarP		( &c.Rest.Password,					"password", "P",		c.Rest.Password, "hide.me `password`" )
	flag.BoolVar		( &c.Rest.PortForward.Enabled,		"pf",					c.Rest.PortForward.Enabled, "enable port-forwarding (uPnP and NAT-PMP)" )
	flag.StringSliceVar	( &c.Plain.Servers,					"dns",					c.Plain.Servers, "comma separated list of DNS `servers`" )			// Resolver flags
	flag.BoolVar		( &c.Rest.UseDoH,					"doh",					c.Rest.UseDoH, "Use DNS-over-HTTPs" )

	flag.BoolVar		( &c.Rest.Filter.ForceDns,			"forceDns",				c.Rest.Filter.ForceDns, "alway use hide.me DNS servers" )			// Filtering flags
	flag.BoolVar		( &c.Rest.Filter.Ads,				"noAds",				c.Rest.Filter.Ads, "filter ads" )
	flag.BoolVar		( &c.Rest.Filter.Trackers,			"noTrackers",			c.Rest.Filter.Trackers, "filter trackers" )
	flag.BoolVar		( &c.Rest.Filter.Malware,			"noMalware",			c.Rest.Filter.Malware, "filter malware" )
	flag.BoolVar		( &c.Rest.Filter.Malicious,			"noMalicious",			c.Rest.Filter.Malicious, "filter malicious destinations" )
	flag.IntVar			( &c.Rest.Filter.PG,				"pg",					c.Rest.Filter.PG, "apply a parental guidance style `age` filter (12, 18)" )
	flag.BoolVar		( &c.Rest.Filter.SafeSearch,		"safeSearch",			c.Rest.Filter.SafeSearch, "force safe search with search engines" )
	flag.StringSliceVar	( &c.Rest.Filter.Risk,				"noRisk",				c.Rest.Filter.Risk, "filter content according to risk `level` (possible, medium, high)" )
	flag.StringSliceVar	( &c.Rest.Filter.Illegal,			"noIllegal",			c.Rest.Filter.Illegal, "filter illegal `kind` (content, warez, spyware, copyright)" )
	flag.StringSliceVar	( &c.Rest.Filter.Categories,		"noCategories",			c.Rest.Filter.Categories, "comma separated list of filtered content `categories`" )
	flag.StringSliceVar	( &c.Rest.Filter.Whitelist,			"whitelist",			c.Rest.Filter.Whitelist, "comma separated list of allowed `dns names`" )
	flag.StringSliceVar	( &c.Rest.Filter.Blacklist,			"blacklist",			c.Rest.Filter.Blacklist, "comma separated list of filtered `dns names`" )

	flag.StringVarP		( &c.WireGuard.Name,				"interface", "i",		c.WireGuard.Name, "network `interface` name" )						// Link flags
	flag.IntVarP		( &c.WireGuard.ListenPort,			"listen-port", "l",		c.WireGuard.ListenPort, "wireguard listen `port`" )
	flag.IntVarP		( &c.WireGuard.Mark,				"firewall-mark", "m",	c.WireGuard.Mark, "firewall `mark` for wireguard and hide.me client originated traffic" )
	flag.IntVarP		( &c.WireGuard.RoutingTable,		"routing-table", "r",	c.WireGuard.RoutingTable, "routing `table` to use" )
	flag.IntVarP		( &c.WireGuard.RPDBPriority,		"rule-priority", "R",	c.WireGuard.RPDBPriority, "RPDB rule `priority`" )

	flag.BoolVarP		( &c.WireGuard.LeakProtection,		"kill-switch", "k",		c.WireGuard.LeakProtection, "enable/disable leak protection a.k.a. kill-switch" )
	flag.StringVarP		( &c.WireGuard.ResolvConfBackupFile,"resolv-conf-bak", "b",	c.WireGuard.ResolvConfBackupFile, "resolv.conf backup `filename`" )

	flag.DurationVar	( &c.WireGuard.DpdTimeout,			"dpd",					c.WireGuard.DpdTimeout, "DPD `timeout`" )
	flag.StringVarP		( &c.WireGuard.SplitTunnel,			"split-tunnel", "s",	c.WireGuard.SplitTunnel, "comma separated list of `networks` (CIDRs) for which to bypass the VPN" )
	
	v4Only := flag.BoolP(									"ipv4-only", "4",		false, "Use IPv4 tunneling only" )
	v6Only := flag.BoolP(									"ipv6-only", "6",		false, "Use IPv6 tunneling only" )

	flag.StringVar		( &c.Control.Address,				"caddr", 				c.Control.Address, "Control interface listen `address`" )			// Control related flags
	flag.StringVar		( &c.Control.Certificate,			"ccert",				c.Control.Certificate, "Control interface `certificate` file" )
	flag.StringVar		( &c.Control.Key,					"ckey",					c.Control.Key, "Control interface `key` file" )
	flag.IntVar			( &c.Control.LineLogBufferSize,		"cllbs",				c.Control.LineLogBufferSize, "Control interface line log buffer `size`" )

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
		_, _ = fmt.Fprint( os.Stderr, "  list - fetch the server list\n" )
		_, _ = fmt.Fprint( os.Stderr, "host:\n" )
		_, _ = fmt.Fprint( os.Stderr, "  fqdn, short name or an IP address of a hide.me server\n\n" )
		_, _ = fmt.Fprint( os.Stderr, "options:\n" )
		flag.PrintDefaults()
	}

	flag.SetInterspersed(true)
	flag.CommandLine.SortFlags = false
	flag.Parse()

	if len(*configurationFileName) > 0 {																												// Read in the configuration file
		conf := []byte(nil)
		if conf, err = os.ReadFile(*configurationFileName); err != nil { if pathErr, ok := err.(*os.PathError); ok { return pathErr.Unwrap() }; return }
		if conf[0] == '{' { err = json.Unmarshal(conf, c) } else { err = yaml.Unmarshal(conf, c) }														// JSON or YAML
		if err != nil { return }
	}

	c.Rest.Mark = c.WireGuard.Mark																														// Fix
	if *v4Only && *v6Only { err = errors.New( "IPv4 only and IPv6 only tunneling are mutually exclusive" ); log.Println( "Conf: [ERR] Failed:", err.Error() ); return }
	if *v4Only { c.WireGuard.IPv6 = false }
	if *v6Only { c.WireGuard.IPv4 = false }
	return
}