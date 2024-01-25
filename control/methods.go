package control

import (
	"encoding/json"
	"github.com/eventure/hide.client.linux/connection"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
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
			if err := encoder.Encode( s.connection.Config ); err != nil { log.Println( "Serv: [ERR] Configure failed: ", err ); return }
			log.Println( "Serv: Configuration sent to", request.RemoteAddr )
		case "POST":
			decoder := json.NewDecoder( io.LimitReader( request.Body, 8192 ) )
			if err := decoder.Decode( s.connection.Config ); err != nil {
				log.Println( "Serv: [ERR] Configure failed:", err )
				writer.WriteHeader( http.StatusBadRequest )
				writer.Write( Result{ Error: &Error{ Code: CodeConfig, Message: err.Error() } }.Json() )
				return
			}
			log.Println( "Serv: Configured from", request.RemoteAddr )
			writer.WriteHeader( http.StatusOK )
			writer.Write( Result{ Result: true }.Json() )
		default: http.Error( writer, "not found", http.StatusNotFound )
	}
}

func ( s *Server ) route( writer http.ResponseWriter, request *http.Request ) {
	if request.Method != "GET" { http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return }
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
	wg.Add( 1 )
	s.connection.SetStateNotify( func( state *connection.State ) {
		stateJson, _ := json.Marshal( state )
		stateJson = append( stateJson, '\n' )
		_, err := writer.Write( stateJson )
		if err != nil { wg.Done(); return }
		writer.( http.Flusher ).Flush()
	})
	wg.Wait()
	s.connection.SetStateNotify( nil )
}

func ( s *Server ) token( writer http.ResponseWriter, request *http.Request ) {
	switch request.Method {
		case "DELETE":
			writer.Header().Add( "content-type", "application/json" )
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
		default:
			http.Error( writer, http.StatusText( http.StatusNotFound ), http.StatusNotFound ); return
	}
	return
}