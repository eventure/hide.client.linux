package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/eventure/hide.client.linux/connection"
	"github.com/eventure/hide.client.linux/control"
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
	flag "github.com/spf13/pflag"
)

// Get the Access-Token
func accessToken( conf *Configuration ) ( err error ) {
	if conf.Rest.AccessTokenPath == "" { log.Println( "AcTo: [ERR] Access-Token must be stored in a file" ); return }
	client := rest.New( conf.Rest )																											// Create the REST client
	if err = client.Init(); err != nil { log.Println( "AcTo: [ERR] REST Client setup failed:", err ); return }
	if !client.HaveAccessToken() {																											// An old Access-Token may be used to obtain a new one, although that process may be done by "connect" too
		if err = client.InteractiveCredentials(); err != nil { log.Println( "AcTo: [ERR] Credential error:", err ); return }				// Try to obtain credentials through the terminal
	}
	dohResolver := doh.New(conf.DoH)
	dohResolver.Init()
	client.SetDohResolver(dohResolver)
	
	plainResolver := plain.New(conf.Plain)
	if err = plainResolver.Init(); err != nil { log.Println( "AcTo: [ERR] Plain resolver init failed", err ); return }
	client.SetPlainResolver(plainResolver)
	
	ctx, cancel := context.WithTimeout( context.Background(), conf.Rest.RestTimeout )
	defer cancel()
	if err = client.Resolve( ctx ); err != nil { log.Println( "AcTo: [ERR] DNS failed:", err ); return }									// Resolve the REST endpoint
	if _, err = client.GetAccessToken( ctx ); err != nil { log.Println( "AcTo: [ERR] Access-Token request failed:", err ); return }			// Request an Access-Token
	log.Println( "AcTo: Access-Token stored in", conf.Rest.AccessTokenPath )
	return
}

// Fetch and dump filtering categories
func categories( conf *Configuration ) {
	client := rest.New( conf.Rest )																											// Create the REST client
	
	dohResolver := doh.New(conf.DoH)
	dohResolver.Init()
	client.SetDohResolver(dohResolver)
	
	plainResolver := plain.New(conf.Plain)
	if err := plainResolver.Init(); err != nil { log.Println( "Cats: [ERR] Plain resolver init failed", err ); return }
	client.SetPlainResolver(plainResolver)
	
	ctx, cancel := context.WithTimeout( context.Background(), conf.Rest.RestTimeout )
	defer cancel()
	if err := client.FetchCategoryList( ctx ); err != nil { log.Println( "Cats: [ERR] GET request failed:", err ); return }					// Get JSON
}

func serverList( conf *Configuration, kind string ) {
	client := rest.New( conf.Rest )																											// Create the REST client
	
	dohResolver := doh.New(conf.DoH)																										// Create a DoH resolver
	dohResolver.Init()
	client.SetDohResolver(dohResolver)
	
	plainResolver := plain.New(conf.Plain)																									// Create a Plain resolver
	if err := plainResolver.Init(); err != nil { log.Println( "List: [ERR] Plain resolver init failed", err ); return }
	client.SetPlainResolver(plainResolver)
	
	ctx, cancel := context.WithTimeout( context.Background(), conf.Rest.RestTimeout )
	defer cancel()
	if err := client.FetchServerList( ctx, kind ); err != nil { log.Println( "List: [ERR] GET request failed:", err ); return }				// Get JSON
}

func main() {
	log.SetFlags( 0 )
	var err error
	conf := NewConfiguration()																												// Parse the command line flags and optionally read the configuration file
	if err = conf.Parse(); err != nil { log.Println( "Main: Configuration failed due to", err.Error() ); return }							// Exit on configuration error
	
	var c *connection.Connection
	var controlServer *control.Server
	
	switch flag.Arg(0) {
		case "conf": conf.Print(); return
		case "jsonconf": conf.PrintJson(); return
		case "service":
			controlServer = control.New( conf.Control, &connection.Config{ Rest: conf.Rest, Wireguard: conf.WireGuard, DoH: conf.DoH } )
			if err = controlServer.Init(); err != nil { log.Println( "Main: [ERR] Control server initialization failed" ); return }
			go controlServer.Serve()
		case "token", "categories", "connect":
			if len( flag.Arg(1) ) == 0 { flag.Usage(); return }
			conf.Rest.SetHost( flag.Arg(1) )
			switch flag.Arg(0) {
				case "token": _ = accessToken( conf ); return																				// Access-Token
				case "categories": categories( conf ); return																				// Fetch the filtering categories JSON
				case "connect":																												// Connect to the server
					c = connection.New( &connection.Config{ Rest: conf.Rest, Wireguard: conf.WireGuard, DoH: conf.DoH, Plain: conf.Plain } )
					if err = c.Init(); err != nil { log.Println( "Main: [ERR] Connect init failed", err.Error() ); return }
					c.NotifySystemd( true )
					c.ScheduleConnect(0)
			}
		case "updateDoh":
			dohResolver := doh.New( conf.DoH )
			dohResolver.Init()
			if err = dohResolver.Update(); err != nil { log.Println( "Main: [ERR] Resolvers update failed:", err ); return }
			log.Println( "Main: Resolvers updated" )
			return
		case "resolve":
			if len( flag.Arg(1) ) == 0 { flag.Usage(); return }
			dohResolver := doh.New( conf.DoH )
			dohResolver.Init()
			switch ips, err := dohResolver.Resolve( context.Background(), flag.Arg(1) ); err {
				case nil:	log.Println( "Main: Resolved", flag.Arg(1), "to", ips )
				default:	log.Println( "Main: Resolve", flag.Arg(1), "failed:", err )
			}
			return
		case "lookup":
			if len( flag.Arg(1) ) == 0 { flag.Usage(); return }
			plainResolver := plain.New(conf.Plain)
			if err = plainResolver.Init(); err != nil { log.Println( "Main: [ERR] Plain resolver init failed", err ); return }
			switch ips, err := plainResolver.Resolve( context.Background(), flag.Arg(1) ); err {
				case nil:	log.Println( "Main: Resolved", flag.Arg(1), "to", ips )
				default:	log.Println( "Main: Resolve", flag.Arg(1), "failed:", err )
			}
			return
		case "list":
			switch flag.Arg(1) {
				case "free":	serverList( conf, "free" )
				default:		serverList( conf, "" )
			}
			return
		default: log.Println( "Main: Unsupported command", flag.Arg(0) ); flag.Usage(); return
	}
	
	signalChannel := make(chan os.Signal, 1)																								// Signal handling
	signal.Notify( signalChannel, syscall.SIGINT, syscall.SIGTERM )
	
	for sig := range signalChannel {
		switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				if c != nil { c.Disconnect(); c.Shutdown() }
				if controlServer != nil { controlServer.Shutdown() }
				return
			default: return
		}
	}
}