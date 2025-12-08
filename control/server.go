package control

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/connection"
)

type Config struct {
	Address				string		`json:"address,omitempty"`			// Address ( IPv4, IPv6, path or an abstract socket ) the control server should listen on
	Certificate			string		`json:"certificate,omitempty"`		// Certificate file path
	Key					string		`json:"key,omitempty"`				// Key file path
	LineLogBufferSize	int			`json:"logBufferSize,omitempty"`	// Turns line log buffering on when larger than 0, affects only service mode
}

type Server struct {
	*Config
	
	listener			net.Listener
	server				*http.Server
	connection			*connection.Connection
	
	serverListBytes		atomic.Pointer[[]byte]
	serverListTimer		*time.Timer
	
	connectionOps		atomic.Uint32
}

func New( controlConfig *Config, connectionConfig *connection.Config ) *Server {
	if controlConfig == nil { controlConfig = &Config{} }
	if connectionConfig == nil { connectionConfig = &connection.Config{} }
	return &Server{ Config: controlConfig, connection: connection.New( connectionConfig )}
}

func ( s *Server ) Init() ( err error ) {
	network := "tcp"																																	// Detect network type
	if strings.Contains( s.Config.Address, "/" ) || strings.Contains( s.Config.Address, "@" ) { network = "unix" }
	
	if s.listener, err = net.Listen( network, s.Config.Address ); err != nil { log.Println( "Init: [ERR] Listen failed:", err.Error() ); return }

	mux := &http.ServeMux{}
	mux.HandleFunc( "/configuration", s.configuration )
	mux.HandleFunc( "/route", s.route )
	mux.HandleFunc( "/connect", s.connect )
	mux.HandleFunc( "/disconnect", s.disconnect )
	mux.HandleFunc( "/destroy", s.destroy )
	mux.HandleFunc( "/state", s.state )
	mux.HandleFunc( "/watch", s.watch )
	mux.HandleFunc( "/token", s.token )
	mux.HandleFunc( "/log", s.log )
	mux.HandleFunc( "/serverList", s.serverList )
	mux.HandleFunc( "/externalIps", s.externalIps )
	s.server = &http.Server{ Handler: mux, ReadHeaderTimeout: time.Second * 5 }
	
	if s.Config.LineLogBufferSize > 0 {
		log.SetFlags( log.LUTC | log.Ldate | log.Ltime )
		log.SetOutput( NewRingLog( s.Config.LineLogBufferSize, log.Writer() ) )
	}
	
	if supported, err := daemon.SdNotify( false, daemon.SdNotifyReady ); supported && err != nil {														// Send SystemD ready notification
		log.Println( "Init: [ERR] SystemD notification failed:", err )
	}
	return
}

func ( s *Server ) Serve() ( err error ) {
	if len( s.Config.Certificate ) > 0 && len( s.Config.Key ) > 0 {
		log.Println( "Init: Starting HTTPS server on", s.listener.Addr() )
		if err = s.server.ServeTLS( s.listener, s.Config.Certificate, s.Config.Key ); !errors.Is( err, http.ErrServerClosed ) {
			log.Println( "Init: HTTPS server on", s.listener.Addr(), "failed:", err.Error() )
		}
	} else {
		log.Println( "Init: Starting HTTP server on", s.listener.Addr() )
		if err = s.server.Serve( s.listener ); !errors.Is( err, http.ErrServerClosed ) {
			log.Println( "Init: HTTP server on", s.listener.Addr(), "failed:", err.Error() )
		}
	}
	return
}

func ( s *Server ) Shutdown() error {
	s.connection.Disconnect()
	s.connection.Shutdown()
	return s.server.Close()
}