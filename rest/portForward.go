package rest

type PortForward struct {
	AccessToken		[]byte		`json:"-"`
	Enabled			bool		`json:"enabled,omitempty"`
}