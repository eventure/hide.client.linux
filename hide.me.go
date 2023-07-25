package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/eventure/hide.client.linux/rest"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Set up and parse flags, read the configuration file
func configure() ( conf *Configuration, command string, err error ) {
	conf = NewConfiguration()
	if err = conf.Parse(); err != nil { return }
	
	switch command = strings.ToLower( flag.Arg(0) ); command {
		case "": flag.Usage(); return
		case "conf": return
		case "connect", "token", "categories": break
		default: fmt.Fprint( os.Stderr, "Unsupported command \"" + command + "\"\n\n" ); flag.Usage(); err = errors.New( "bad command" ); return
	}
	if err = conf.Check(); err != nil { fmt.Fprint( os.Stderr, "Configuration error: ", err, "\n" ); return }								// Check configuration
	return
}

// Get the Access-Token
func accessToken( conf *Configuration ) ( err error ) {
	if conf.Client.AccessTokenFile == "" { fmt.Println( "AcTo: [ERR] Access-Token must be stored to a file" ); return }
	client := rest.New( conf.Client )																										// Create the REST client
	if err = client.Init(); err != nil { fmt.Println( "AcTo: [ERR] REST Client setup failed,", err ); return }
	if !client.HaveAccessToken() {																											// An old Access-Token may be used to obtain a new one, although that process may be done by "connect" too
		if err = client.InteractiveCredentials(); err != nil { fmt.Println( "AcTo: [ERR] Credential error,", err ); return }				// Try to obtain credentials through the terminal
	}
	ctx, cancel := context.WithTimeout( context.Background(), conf.Client.RestTimeout )
	defer cancel()
	if err = client.Resolve( ctx ); err != nil { fmt.Println( "AcTo: [ERR] DNS failed,", err ); return }									// Resolve the REST endpoint
	if err = client.GetAccessToken( ctx ); err != nil { fmt.Println( "AcTo: [ERR] Access-Token request failed,", err ); return }			// Request an Access-Token
	fmt.Println( "AcTo: Access-Token stored in", conf.Client.AccessTokenFile )
	return
}

// Fetch and dump filtering categories
func categories( conf *Configuration ) {
	clientConf := conf.Client
	clientConf.Port = 443
	clientConf.CA = ""
	client := rest.New( clientConf )																										// Create the REST client
	ctx, cancel := context.WithTimeout( context.Background(), conf.Client.RestTimeout )
	defer cancel()
	if err := client.Init(); err != nil { fmt.Println( "Main: [ERR] REST Client setup failed,", err ); return }
	if err := client.Resolve( ctx ); err != nil { fmt.Println( "Main: [ERR] DNS failed,", err ); return }									// Resolve the REST endpoint
	if err := client.FetchCategoryList( ctx ); err != nil { fmt.Println( "Main: [ERR] GET request failed,", err ); return }					// Get JSON
	return
}

func main() {
	conf, command, err := configure()																										// Parse the command line flags and optionally read the configuration file
	if conf == nil || err != nil { return }																									// Exit on configuration error
	var c *Connection
	
	switch command {
		case "conf": conf.Print(); return																									// Configuration dump
		case "token": accessToken( conf ); return																							// Access-Token
		case "categories": categories( conf ); return																						// Fetch the filtering categories JSON
		case "connect":																														// Connect to the server
			c = NewConnection( conf )
			if err = c.Init(); err != nil { fmt.Println( "Main: [ERR] Connect init failed", err.Error() ); return }
			c.ScheduleConnect(0)
		case "": return
	}
	
	signalChannel := make ( chan os.Signal )																								// Signal handling
	signal.Notify( signalChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL )
	
	for sig := range signalChannel {
		switch sig {
			case syscall.SIGINT, syscall.SIGTERM: if c != nil { c.Disconnect(); c.Shutdown(); return }
			default: return
		}
	}
}