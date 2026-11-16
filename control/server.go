package control

import (
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	
	"github.com/coreos/go-systemd/daemon"
	"github.com/eventure/hide.client.linux/connection"
)

type Config struct {
	Address				string		`json:"address,omitempty"`			// Address ( IPv4, IPv6, path or an abstract socket ) the control server should listen on
	Group				string		`json:"group,omitempty"`			// Group whose members may use the unix socket control interface, root and current user are always allowed
	Certificate			string		`json:"certificate,omitempty"`		// Certificate file path
	Key					string		`json:"key,omitempty"`				// Key file path
	LineLogBufferSize	int			`json:"logBufferSize,omitempty"`	// Turns line log buffering on when larger than 0, affects only service mode
}

type Server struct {
	*Config
	serverConfiguration	ServerConfiguration

	listener			net.Listener
	server				*http.Server
	connection			*connection.Connection

	serverListBytes		atomic.Pointer[[]byte]
	serverListTimer		*time.Timer

	connectionOpsLock	chan struct{}

	uid					uint32											// UserId allowed to connect to our UNIX socket. Default: running process uid
	gid					*uint32											// GroupId allowed to connect to our UNIX socket. Default: no group
}

type ServerConfiguration interface {
	GetConnectionConfiguration() *connection.Config
	GetControlConfiguration() *Config
	SaveJson() error
}

func New( serverConfiguration ServerConfiguration ) *Server {
	controlConfig, connectionConfig := serverConfiguration.GetControlConfiguration(), serverConfiguration.GetConnectionConfiguration()
	if controlConfig == nil { controlConfig = &Config{} }
	if connectionConfig == nil { connectionConfig = &connection.Config{} }
	return &Server{ Config: controlConfig, serverConfiguration: serverConfiguration, connection: connection.New( connectionConfig ), connectionOpsLock: make(chan struct{}, 1) }
}

func ( s *Server) getUidGids() ( err error ) {
	userStruct, err := user.Current()
	if err != nil { return }
	userId, err := strconv.ParseUint( userStruct.Uid, 10, 32 )
	if err != nil { return }
	s.uid = uint32( userId )
	if len( s.Config.Group ) == 0 { return }
	group, err := user.LookupGroup( s.Config.Group )																					// Lookup the group id when Config.Group set
	if err != nil { return }
	gid, err := strconv.ParseUint( group.Gid, 10, 32 )
	s.gid = new(uint32)
	*s.gid = uint32( gid )
	return
}

// ListenUnix listens on a UNIX socket accessible to root and the members of a group (gid) when that socket is not abstract. When the group can't be resolved the socket is accessible to its owner only
func ( s *Server ) ListenUnix() ( listener net.Listener, err error ) {
	defer func() { if err == nil { return }; log.Println( "LiUn: [ERR] ListenUnix failed:", err ) } ()
	if strings.HasPrefix( strings.TrimSpace( s.Config.Address ), "@" ) { return net.Listen( "unix", s.Config.Address ) }				// For abstract sockets a simple Listen does the job
	
	dir := filepath.Dir( s.Config.Address )
	if err = os.MkdirAll( dir, 0755 ); err != nil { return }																			// MkdirAll doesn't do anything when dir exists
	
	info, err := os.Lstat( dir )																										// Check if the directory exists after Mkdir
	if err != nil { return }
	if !info.IsDir() { err = errors.New( dir + " is not a directory" ); return }														// or is it a symlink ?
	if info.Mode().Perm() & 0022 != 0 { err = errors.New( dir + " is writable by group or others" ); return }							// Are the permissions appropriate ?
	
	if info, err = os.Lstat( s.Config.Address ); err != nil {																			// Check if a socket or something else already exists at s.Config.Address
		if !errors.Is( err, fs.ErrNotExist ) { return }
	} else {
		if info.Mode().Type() != os.ModeSocket { err = errors.New( s.Config.Address + " exists and is not a socket" ); return }
		if err = os.Remove( s.Config.Address ); err != nil { return }																	// Remove a stale socket
	}
	
	user, err := user.Current()																											// Fetch the current user
	if err != nil { return }
	
	oldUmask := syscall.Umask( 0177 ); defer syscall.Umask( oldUmask )																	// The socket is never more open than 0600 before chown and chmod
	if listener, err = net.Listen( "unix", s.Config.Address ); err != nil { return }													// Open the socket
	
	if s.gid == nil {																													// There was no group configured
		if err = os.Chmod( s.Config.Address, 0600 ); err != nil { listener.Close() }
		log.Println( "LiUn: Control socket", s.Config.Address, "is accessible to the", user.Username, "user" )
		return
	}
	if err = os.Lchown( s.Config.Address, -1, int( *s.gid ) ); err != nil { listener.Close(); return }
	if err = os.Chmod( s.Config.Address, 0660 ); err != nil { listener.Close() }
	log.Println( "LiUn: Control socket", s.Config.Address, "is accessible to the", user.Username, "user and members of", s.Config.Group, "group" )
	return
}

func ( s *Server ) Init() ( err error ) {
	defer func() { if err == nil { return }; log.Println( "Init: [ERR] Init failed:", err ) } ()
	
	network := "tcp"																													// Detect network type
	if strings.Contains( s.Config.Address, "/" ) || strings.Contains( s.Config.Address, "@" ) { network = "unix" }

	mux := &http.ServeMux{}
	mux.HandleFunc( "/configuration", s.configuration )
	mux.HandleFunc( "/route", s.route )
	mux.HandleFunc( "/connect", s.connect )
	mux.HandleFunc( "/configureConnect", s.configureConnect )
	mux.HandleFunc( "/disconnect", s.disconnect )
	mux.HandleFunc( "/shutdown", s.shutdown )
	mux.HandleFunc( "/destroy", s.destroy )
	mux.HandleFunc( "/state", s.state )
	mux.HandleFunc( "/watch", s.watch )
	mux.HandleFunc( "/requestToken", s.requestToken )
	mux.HandleFunc( "/token", s.token )
	mux.HandleFunc( "/log", s.log )
	mux.HandleFunc( "/serverList", s.serverList )
	mux.HandleFunc( "/externalIps", s.externalIps )
	mux.HandleFunc( "/version", s.version )
	
	handler := http.Handler( mux )
	switch network {
		case "unix":	if err = s.getUidGids(); err != nil { return }
						if s.listener, err = s.ListenUnix(); err != nil { return }
						handler = s.peerCheck( mux )																					// Abstract or not, peers will be checked
		case "tcp":		s.listener, err = net.Listen( network, s.Config.Address )
	}
	if err != nil { return }
	s.server = &http.Server{ Handler: handler, ConnContext: peerConnContext, ReadHeaderTimeout: time.Second * 5 }
	
	if s.Config.LineLogBufferSize > 0 {
		log.SetFlags( log.LUTC | log.Ldate | log.Ltime )
		log.SetOutput( NewRingLog( s.Config.LineLogBufferSize, log.Writer() ) )
	}
	
	if supported, sdErr := daemon.SdNotify( false, daemon.SdNotifyReady ); supported && err != nil { return sdErr }						// Send SystemD ready notification
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
	s.connection.Disconnect( false )
	s.connection.Shutdown( true )
	return s.server.Close()
}