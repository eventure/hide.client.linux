package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
	
	"github.com/eventure/hide.client.linux/connection"
	"github.com/eventure/hide.client.linux/resolvers/doh"
	"github.com/eventure/hide.client.linux/resolvers/plain"
	"github.com/eventure/hide.client.linux/rest"
)

const (
	CodeConfig = "configuration"
	CodeRoute = "route"
	CodeConnect = "connect"
	CodeDisconnect = "disconnect"
	CodeToken = "token"
)

func ( s *Server ) configuration( writer http.ResponseWriter, request *http.Request ) {
	switch request.Method {
		case "GET":
			writer.WriteHeader( http.StatusOK )
			encoder := json.NewEncoder( writer )
			s.connection.Lock(); s.connection.Unlock()
			if err := encoder.Encode( s.connection.Config ); err != nil { log.Println( "Serv: [ERR] Configure failed: ", err ); return }
			log.Println( "Serv: Configuration sent to", request.RemoteAddr )
			s.connection.StateNotify( &connection.State{Code: connection.ConfigurationGet})
		case "POST":
			logBuffer := &bytes.Buffer{}
			decoder := json.NewDecoder( io.TeeReader( io.LimitReader( request.Body, 8192 ), logBuffer ) )
			s.connection.Lock(); s.connection.Unlock()
			if err := decoder.Decode( s.connection.Config ); err != nil {
				log.Println( "Serv: [ERR] Configure failed:", err )
				writer.WriteHeader( http.StatusBadRequest )
				writer.Write( Result{ Error: &Error{ Code: CodeConfig, Message: err.Error() } }.Json() )
				return
			}
			log.Println( "Serv: Configured from", request.RemoteAddr, "with", logBuffer.String() )
			writer.WriteHeader( http.StatusOK )
			writer.Write( Result{ Result: true }.Json() )
			s.connection.StateNotify( &connection.State{Code: connection.ConfigurationSet})
		default: http.Error( writer, "not found", http.StatusNotFound )
	}
}

func ( s *Server ) route( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	if !s.connectionOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.connectionOps.Store( 0 )
	
	switch code := s.connection.Code(); code {
		case connection.Clean:
			if err := s.connection.Init(); err != nil { writer.Write( Result{ Error: &Error{ Code: CodeRoute, Message: err.Error() } }.Json() ); return }
			writer.Write( Result{ Result: s.connection.State() }.Json() )
		default:
			writer.Write( Result{ Error: &Error{ Code: CodeRoute, Message: "bad state: " + code } }.Json() )
	}
}

func ( s *Server ) connect( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	if !s.connectionOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.connectionOps.Store( 0 )
	
	writer.Header().Add( "content-type", "application/json" )
	switch code := s.connection.Code(); code {
		case connection.Routed: break
		case connection.Clean:
			if err := s.connection.Init(); err != nil {
				writer.Write( Result{ Error: &Error{ Code: CodeConnect, Message: err.Error() } }.Json() ); return
			}
			break
		default: writer.Write( Result{ Error: &Error{ Code: CodeConnect, Message: "bad state: " + code } }.Json() ); return
	}
	wg := sync.WaitGroup{}
	wg.Add( 1 )
	s.connection.SetConnectNotify( func( err error ) {
		switch err {
			case nil: writer.Write( Result{ Result: s.connection.State() }.Json() )
			default:  writer.Write( Result{ Error: &Error{ Code: CodeConnect, Message: err.Error() } }.Json() )
		}
		wg.Done()
	} )
	s.connection.ScheduleConnect( 0 )
	wg.Wait()
}

func ( s *Server ) disconnect( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	if !s.connectionOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.connectionOps.Store( 0 )
	
	writer.Header().Add( "content-type", "application/json" )
	switch code := s.connection.Code(); code {
		case connection.Connected, connection.Connecting: break
		default: writer.Write( Result{ Error: &Error{ Code: CodeDisconnect, Message: "bad state: " + code } }.Json() ); return
	}
	s.connection.Disconnect()
	writer.Write( Result{ Result: s.connection.State() }.Json() )
}

func ( s *Server ) destroy( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	if !s.connectionOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.connectionOps.Store( 0 )
	
	writer.Header().Add( "content-type", "application/json" )
	switch s.connection.Code() {
		case connection.Connected, connection.Connecting: s.connection.Disconnect(); s.connection.Shutdown(); break
		case connection.Routed: s.connection.Shutdown(); break
		default: break
	}
	writer.Write( Result{ Result: s.connection.State() }.Json() )
}

func ( s *Server ) state( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	writer.Header().Add( "content-type", "application/json" )
	writer.Write( Result{ Result: s.connection.State() }.Json() )
}

func ( s *Server ) watch( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }

	writer.Header().Add( "content-type", "application/json" )
	wg := sync.WaitGroup{}
	wg.Add(1)

	var stateNotifyFn func( state *connection.State )
	stateNotifyFn = func( state *connection.State ) {
		stateJson, _ := json.Marshal( state )
		stateJson = append( stateJson, '\n' )
		if _, err := writer.Write( stateJson ); err != nil { s.connection.StateNotifyFnDel( &stateNotifyFn ); wg.Done(); return }
		writer.( http.Flusher ).Flush()
	}
	s.connection.StateNotifyFnAdd( &stateNotifyFn )
	wg.Wait()
}

func ( s *Server ) token( writer http.ResponseWriter, request *http.Request ) {
	if !s.remoteOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.remoteOps.Store( 0 )
	switch request.Method {
		case "DELETE":
			writer.Header().Add( "content-type", "application/json" )
			s.connection.Lock(); defer s.connection.Unlock()
			writer.Write( Result{ Result: os.Remove( s.connection.Config.Rest.AccessTokenPath ) }.Json() )
		case "GET":
			writer.Header().Add( "content-type", "application/json" )
			switch accessToken, err := s.connection.AccessTokenFetch(); err {
				case nil: writer.Write( Result{ Result: accessToken }.Json() )
				default:  writer.Write( Result{ Error: &Error{ Code: CodeToken, Message: err.Error() } }.Json())
			}
		default:
			http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return
	}
	return
}

func ( s *Server ) log( writer http.ResponseWriter, request *http.Request ) {
	logs := []byte( nil )
	if ringLog, ok := log.Writer().( *RingLog ); ok { logs = ringLog.Dump() }
	switch request.Method {
		case "GET":
			writer.Header().Add( "content-type", "text/plain" )
			writer.Write( logs )
			s.connection.StateNotify( &connection.State{Code: connection.LogDump})
		default:
			http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return
	}
	return
}

var cacheControlRegex = regexp.MustCompile( "[[:space:]]*max-age[[:space:]]*=[[:space:]]*([[:digit:]]+)" )

func ( s *Server ) serverList(writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
	if !s.remoteOps.CompareAndSwap( 0, 1 ) { http.Error( writer, http.StatusText( http.StatusConflict ), http.StatusConflict ); return }
	defer s.remoteOps.Store( 0 )
	
	if slb := s.serverListBytes.Load(); slb != nil { writer.Header().Add( "content-type", "application/json" ); writer.Write( *slb ); log.Println( "sLst: ServerList sent" ); return }
	
	s.connection.Lock(); defer s.connection.Unlock()
	
	client := rest.New( s.connection.Config.Rest )																										// Create a REST client ( must be a new one since FetchServerList changes client's configuration )
	
	dohResolver := doh.New( s.connection.Config.DoH )																									// Create a DoH resolver
	dohResolver.Init()
	client.SetDohResolver(dohResolver)
	
	plainResolver := plain.New( s.connection.Config.Plain )																								// Create a Plain resolver
	if err := plainResolver.Init(); err != nil { log.Println( "sLst: [ERR] Plain resolver init failed", err ); http.Error( writer, err.Error(), http.StatusBadGateway ); return }
	client.SetPlainResolver(plainResolver)
	
	ctx, cancel := context.WithTimeout( context.Background(), s.connection.Config.Rest.RestTimeout )
	defer cancel()
	
	response, headers, err := client.FetchServerList( ctx )
	if err != nil { log.Println( "sLst: [ERR] Server list fetch failed:", err ); http.Error( writer, err.Error(), http.StatusBadGateway ); return }
	
	if maxAgeMatches := cacheControlRegex.FindStringSubmatch( headers.Get( "cache-control" ) ); len( maxAgeMatches ) > 1 {
		if maxAge, err := strconv.ParseInt( maxAgeMatches[1], 10, 64 ); err == nil {
			s.serverListBytes.Store( &response )
			ttl := time.Duration( maxAge ) * time.Second
			time.AfterFunc( ttl, func() { s.serverListBytes.Store( nil ); log.Println( "sLst: Server list expired" ) } )
			log.Println( "sLst: Caching server list for", ttl )
		}
	}

	writer.Header().Add( "content-type", "application/json" )
	writer.Write( response )
	
	log.Println( "sLst: ServerList sent" )
}