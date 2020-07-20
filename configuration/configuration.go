package configuration

import (
	"errors"
	"fmt"
	"github.com/eventure/hide.client.linux/rest"
	"github.com/eventure/hide.client.linux/wireguard"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type HideGuardConfiguration struct {
	Client			rest.Config			`yaml:"client,omitempty"`
	Link			wireguard.Config	`yaml:"link,omitempty"`
}

func NewHideGuardConfiguration() *HideGuardConfiguration {
	h := &HideGuardConfiguration{												// Defaults
		Link: wireguard.Config{
			Name:					"vpn",										// command line option "-i"
			ListenPort:				0,											// command line option "-l"
			FirewallMark:			55555,										// command line option "-m"
			RoutingTable:			55555,										// command line option "-r"
			LeakProtection:			true,										// command line option "-k"
			ResolvConfBackupFile:	"/etc/resolv.conf.backup.hide.me",			// command line option "-b"
			DpdTimeout:				time.Minute,								// command line option "-dpd"
			SplitTunnel:			"",											// command line option "-s"
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
			ConnectTimeout: 		10 * time.Second,							// Only configurable through the config file
			AccessTokenUpdateDelay: 2 * time.Second,							// Only configurable through the config file
			FirewallMark:			55555,										// command line option "-m"
			DnsServers:				"209.250.251.37:53,217.182.206.81:53",		// command line option "-d"
		},
	}
	return h
}

func ( c *HideGuardConfiguration ) Read( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	bytes, err := ioutil.ReadFile( fileName )
	if err != nil {
		if pathErr, ok := err.(*os.PathError); ok { return pathErr.Unwrap() }
		return
	}
	err = yaml.Unmarshal( bytes, c )
	return
}

func ( c *HideGuardConfiguration ) Store( fileName string ) ( err error ) {
	if len( fileName ) == 0 { return }
	configurationYaml, err := yaml.Marshal( c )
	if err != nil { return }
	err = ioutil.WriteFile(fileName, configurationYaml, 0400)
	return
}

func ( c *HideGuardConfiguration ) Check() ( err error ) {
	if c.Client.Domain != "hide.me" { err = errors.New( "configured domain mismatch" ); return }
	if len( c.Client.Host ) == 0 { err = errors.New( "missing hostname" ); return }
	if c.Client.Port == 0 { err = errors.New( "bad remote port " + strconv.Itoa( c.Client.Port ) ); return }
	if len( c.Link.Name ) == 0 { err = errors.New( "missing wireGuard interface name" ); return }
	if len( c.Link.ResolvConfBackupFile ) == 0 { err = errors.New( "filename for a resolv.conf backup not set" ); return }
	if c.Link.DpdTimeout == 0 { err = errors.New( "dpd timeout not set" ); return }
	if c.Link.DpdTimeout > time.Minute { err = errors.New( "dpd timeout above 1 minute" ); return }
	if c.Client.Port == 443 {
		fmt.Println( "conf: [WARNING] Using port 443, API unstable" )
		c.Client.APIVersion = "v1"
	}
	if c.Link.FirewallMark == 0 { err = errors.New( "firewallMark is zero" ); return }
	return
}

// Add .hideservers.net suffix for short names ( nl becomes nl.hideservers.net ) or remove .hide.me and replace it with .hideservers.net.
func ( c *HideGuardConfiguration ) AdjustHost() {
	if net.ParseIP( c.Client.Host ) != nil { return }
	if strings.HasSuffix( c.Client.Host, ".hideservers.net" ) { return }
	c.Client.Host = strings.TrimSuffix( c.Client.Host, ".hide.me" )
	c.Client.Host += ".hideservers.net"
}

// Ask for username/password if none were configured
func ( c *HideGuardConfiguration ) InteractiveCredentials() ( err error ) {
	if len( c.Client.Username ) > 0 && len( c.Client.Password ) > 0 { return }
	if ! terminal.IsTerminal( syscall.Stdin ) { err = errors.New( "not a terminal" ); return }
	if len( c.Client.Username ) == 0 {
		fmt.Print( "Username: " )
		if _, err = fmt.Scanln( &c.Client.Username ); err != nil { return }
	}
	if len( c.Client.Password ) == 0 {
		fmt.Print( "Password: " )
		if passwordBytes, err := terminal.ReadPassword( syscall.Stdin ); err != nil {
			fmt.Println()
			return err
		} else {
			fmt.Println()
			c.Client.Password = string( passwordBytes )
		}
	}
	return
}

func ( c *HideGuardConfiguration ) Print() {
	if out, err := yaml.Marshal( c ); err != nil { fmt.Println( err ) } else { fmt.Print( string( out ) ) }
	return
}