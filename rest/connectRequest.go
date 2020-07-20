package rest

import (
	"errors"
)

type ConnectRequest struct {
	Host				string		`json:"host,omitempty"`													// VPN connection host
	Domain				string		`json:"domain,omitempty"`												// VPN connection Domain
	AccessToken			[]byte		`json:"accessToken,omitempty"`											// Access-Token, takes precedence over Username/Password pair
	PublicKey			[]byte		`json:"publicKey"`														// Our public key
}

func ( req *ConnectRequest ) Check() ( err error ) {
	if len( req.Host ) == 0 { err = errors.New( "no host" ); return }
	if len( req.Domain ) == 0 { err = errors.New( "no domain" ); return }
	if len( req.AccessToken ) == 0 { err = errors.New( "no Access-Token" ); return }
	if len( req.PublicKey ) != 32 { err = errors.New( "public key invalid" ); return }
	return
}