package rest

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"syscall"
)

// InteractiveCredentials asks for username/password when no such credentials were configured
func ( c *Client ) InteractiveCredentials() ( err error ) {
	if ! terminal.IsTerminal( syscall.Stdin ) { return errors.New( "not a terminal" ) }
	if len( c.Config.Username ) == 0 {
		fmt.Print( "Username: " )
		if _, err = fmt.Scanln( &c.Config.Username ); err != nil { return }
	}
	if len( c.Config.Password ) == 0 {
		fmt.Print( "Password: " )
		if passwordBytes, err := terminal.ReadPassword( syscall.Stdin ); err != nil { fmt.Println() } else { fmt.Println(); c.Config.Password = string( passwordBytes ) }
	}
	return
}