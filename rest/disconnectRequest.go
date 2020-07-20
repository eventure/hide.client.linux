package rest

import (
	"errors"
)

type DisconnectRequest struct {
	Host				string			`json:"host,omitempty"`						// VPN connection host
	Domain				string			`json:"domain,omitempty"`					// VPN connection domain
	SessionToken		[]byte			`json:"sessionToken,omitempty"`				// Session-Token uniquely identifies the VPN connection session to disconnect
}

func ( req *DisconnectRequest ) Check() ( err error ) {
	if len( req.SessionToken ) == 0 { err = errors.New( "no Session-Token" ) }
	return
}