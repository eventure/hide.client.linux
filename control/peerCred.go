package control

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"slices"
	"unsafe"
	
	"golang.org/x/sys/unix"
)

const CodeForbidden = "forbidden"

type peerCredKey struct{}

type peerCred struct {
	uid		uint32
	pid		int32
	gids	[]uint32																															// Groups of the peer at connect time
}

// peerConnContext stores the credentials of unix socket peers in the connection context: uid and pid from SO_PEERCRED, the groups from SO_PEERGROUPS.
// When SO_PEERGROUPS is not supported the groups get read from /proc/<pid>/status, provided that process still runs as the peer's uid.
// Nothing gets stored for TCP connections or when the credentials can't be read, peerCheck denies unix socket requests without credentials
func peerConnContext( ctx context.Context, conn net.Conn ) context.Context {
	if tlsConn, ok := conn.( *tls.Conn ); ok { conn = tlsConn.NetConn() }
	unixConn, ok := conn.( *net.UnixConn )
	if !ok { return ctx }
	
	rawConn, err := unixConn.SyscallConn()
	if err != nil { log.Println( "Serv: [ERR] Peer credentials failed:", err ); return ctx }
	
	var ucred *unix.Ucred
	var gids []uint32
	var credErr error
	
	if err = rawConn.Control( func( fd uintptr ) {
		if ucred, credErr = unix.GetsockoptUcred( int( fd ), unix.SOL_SOCKET, unix.SO_PEERCRED ); credErr != nil { return }						// Primary GID
		
		gids = make( []uint32, 64 )																												// Fetch supplementary GIDs
		for {
			size := uint32( len(gids) * 4 )
			_, _, errno := unix.Syscall6( unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_PEERGROUPS, uintptr( unsafe.Pointer( &gids[0] ) ), uintptr( unsafe.Pointer( &size ) ), 0 )
			if errors.Is( errno, unix.ERANGE ) { gids = make( []uint32, size / 4 ); continue }													// Buffer too small, size holds the required one
			if errno != 0 { credErr = errno; return }
			break
		}
	}); err == nil { err = credErr }
	if err != nil { log.Println( "pCtx: [ERR] Peer credentials failed:", err ); return ctx }
	
	if !slices.Contains( gids, ucred.Gid ) { gids = append( gids, ucred.Gid ) }																	// Add the primary GID to the gids slice if it isn't present in the slice already
	return context.WithValue( ctx, peerCredKey{}, peerCred{ uid: ucred.Uid, pid: ucred.Pid, gids: gids } )
}

// peerAllowed allows root, own user id or members of the control group if specified
func ( s *Server ) peerAllowed( uid uint32, gids []uint32 ) bool {
	if uid == 0 || uid == s.uid { return true }
	if s.gid == nil { return false }
	for _, gid := range gids { if *s.gid == gid { return true } }
	return false
}

// peerCheck rejects unix socket peers which are neither root nor members of the group
func ( s *Server ) peerCheck( next http.Handler ) http.Handler {
	return http.HandlerFunc( func( writer http.ResponseWriter, request *http.Request ) {
		cred, ok := request.Context().Value( peerCredKey{} ).( peerCred )
		if !ok { log.Println( "PChk: [ERR] Peer without credentials not allowed" ); forbidden( writer ); return }
		if !s.peerAllowed( cred.uid, cred.gids ) { log.Println( "PChk: [ERR] Peer uid", cred.uid, "pid", cred.pid, "gids", cred.gids, "not allowed" ); forbidden( writer ); return }
		next.ServeHTTP( writer, request )
	})
}

func forbidden( writer http.ResponseWriter ) {
	writer.Header().Set( "Content-Type", "application/json" )
	writer.WriteHeader( http.StatusForbidden )
	writer.Write( Result{ Error: &Error{ Code: CodeForbidden, Message: "not allowed" } }.Json() )
}