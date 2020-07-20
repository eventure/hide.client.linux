package rest

import (
	"errors"
)

type AccessTokenRequest struct {
	Host				string		`json:"host,omitempty"`												// VPN connection host
	Domain				string		`json:"domain,omitempty"`											// VPN connection Domain
	AccessToken			[]byte		`json:"accessToken,omitempty"`										// Access-Token, takes precedence over Username/Password pair
	Username			string		`json:"username,omitempty"`											// Username ( should be empty when updating an Access-Token )
	Password			string		`json:"password,omitempty"`											// Password ( should be empty when updating an Access-Token )
}

func ( a *AccessTokenRequest ) Check() ( err error ) {
	if len( a.Domain ) == 0 { err = errors.New( "no domain" ); return }
	if len ( a.AccessToken ) == 0 {																		// No access token, check username/password
		if len( a.Username ) == 0 { err = errors.New( "no username" ); return }
		if len( a.Username ) > 64 { err = errors.New( "too many characters in username" ); return }
		if len( a.Password ) == 0 { err = errors.New( "no password" ); return }
		if len( a.Password ) > 64 { err = errors.New( "too many characters in password" ); return }
	}
	return
}