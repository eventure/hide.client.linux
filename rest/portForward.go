package rest

type PortForward struct {
	AccessToken		[]byte		`json:"accessToken,omitempty"`
	Enabled			bool		`json:"enabled,omitempty"`
}