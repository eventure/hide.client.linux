package doh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	
	"github.com/jedisct1/go-dnsstamps"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

type RouteOps interface {
	ThrowRouteAdd( logPrefix string, dst *net.IPNet ) ( err error )
	ThrowRouteDel( logPrefix string, dst *net.IPNet ) ( err error )
}

type Config struct {
	Servers		[]string	// DNS stamps
	UpdateURLs	[]string	// Update URLs
	Filename	string		// Storage file
}

type Resolver struct {
	*Config
	dohServers	[]string
	dialer		*net.Dialer
	mark		int
	routeOps	RouteOps	// Routing subsystem interface
}

type DoHResponse struct {
	index		int
	ip			net.IP
	err			error
}

func New( config *Config ) *Resolver { if config == nil { config = &Config{} }; return &Resolver{ Config: config } }
func (d *Resolver) SetRouteOps( routeOps RouteOps ) { d.routeOps = routeOps }
func (d *Resolver) SetMark(mark int) { d.mark = mark }

func ( d *Resolver ) Init() {
	if len( d.Config.Filename ) > 0 {
		switch file, errFile := os.Open( d.Config.Filename ); errFile {
			case nil:	d.dohServers = d.ParseDnsStamps(file)
						log.Println( "Init: Parsed", len(d.dohServers), "usable DoH servers from", d.Config.Filename )
						_ = file.Close()
			default:	if errors.Is(errFile, os.ErrNotExist) { log.Println( "Init: [WARN] DoH resolvers file", d.Config.Filename, "does not exist" ); break }
						log.Println( "Init: [ERR] Read", d.Config.Filename, "failed:", errFile )
						_ = file.Close()
		}
	}
	d.dohServers = append( d.dohServers, d.Config.Servers... )																						// Add configured DoH servers
	d.RandomizeOrder()
	d.dialer = &net.Dialer{																															// Use a custom dialer to set the socket mark on sockets when those are configured
		Control: func( network, address string, rawConn syscall.RawConn ) ( err error ) {
			if d.mark == 0 { return }
			_ = rawConn.Control( func( fd uintptr ) {
				if err = syscall.SetsockoptInt( int(fd), unix.SOL_SOCKET, unix.SO_MARK, d.mark ); err != nil { log.Println( "Dial: [ERR] Set mark failed:", err ) }
			})
			return
		},
	}
	log.Println( "Init: Using total of", len(d.dohServers), "DoH resolvers" )
	return
}

// createDnsMessage creates a DNS message
func ( d *Resolver ) createDnsMessage( name string, messageType dnsmessage.Type ) ( buf []byte, err error ) {
	qname, err := dnsmessage.NewName(name)
	if err != nil { return }
	/* optRR := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{ Type: dnsmessage.TypeOPT, Class: 1280, Name: dnsmessage.MustNewName(".") },
		Body:   &dnsmessage.OPTResource{},
	} */
	message := dnsmessage.Message{
		Header:			dnsmessage.Header{ RecursionDesired: true },
		Questions:		[]dnsmessage.Question{ { Name: qname, Type: messageType, Class: dnsmessage.ClassINET } },
		// Additionals:	[]dnsmessage.Resource{optRR},
	}
	return message.Pack()
}

// parseMessageForName parses a DNS message, checks validity, looks for answers regarding name
func ( d *Resolver ) parseMessageForNameAndType( message []byte, name string, questionType dnsmessage.Type ) ( ip net.IP , err error ) {
	msg := dnsmessage.Message{}
	if err = msg.Unpack( message ); err != nil { return }
	if !msg.Header.Response { err = errors.New( "not a response message" ); return }
	if msg.Header.OpCode != 0 { err = errors.New( "not a query response" ); return }
	if msg.Header.RCode != dnsmessage.RCodeSuccess { err = errors.New( "bad response code " + msg.Header.RCode.String() ); return }
	
	valid := false																																	// Check the questions section, it must contain "name"
	for _, question := range msg.Questions { if question.Name.String() == name { valid = true; break } }
	if !valid { err = errors.New( "questions section does not contain" + name ); return }
	
	for _, answer := range msg.Answers {
		if answer.Header.Name.String() != name { err = errors.New( "answer for an invalid name" ); return }
		if answer.Header.Class != dnsmessage.ClassINET { err = errors.New( "invalid answer class" ); return }
		if answer.Header.Type != questionType { err = errors.New( "query and answer type mismatch" ); return }
		if answer.Header.Type == dnsmessage.TypeA { if aResource, ok := answer.Body.(*dnsmessage.AResource); ok { ip = aResource.A[:] } }
		if answer.Header.Type == dnsmessage.TypeAAAA { if aaaaResource, ok := answer.Body.(*dnsmessage.AAAAResource); ok { ip = aaaaResource.AAAA[:] } }
	}
	return
}

// postDnsMessage issues a HTTP POST request with appropriate headers. When endpoint contains an address a direct connection, without DNS resolution, will be made
func ( d *Resolver ) postDnsMessage( ctx context.Context, url string, endpoint string, message []byte ) ( responseBody []byte, err error ) {
	request, err := http.NewRequestWithContext( ctx, "POST", url, bytes.NewReader( message ) )
	if err != nil { return }
	request.Header.Add( "content-type", "application/dns-message" )
	request.Header.Add( "accept", "application/dns-message" )
	httpClient := http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				if len(endpoint) > 0 { addr = endpoint }
				return d.dialer.DialContext(ctx, network, addr)
			},
		},
	}
	
	if len( endpoint ) > 0 && d.routeOps != nil {																									// Add a throw route when required
		host, _, _ := net.SplitHostPort(endpoint)
		if ip := net.ParseIP(host); ip != nil {
			mask := net.CIDRMask(128,128)
			if ip4 := ip.To4(); ip4 != nil { ip, mask = ip4, net.CIDRMask(32,32) }
			if err = d.routeOps.ThrowRouteAdd( url, &net.IPNet{IP: ip, Mask: mask }); err != nil { return nil, err }
			defer d.routeOps.ThrowRouteDel( url, &net.IPNet{IP: ip, Mask: mask } )
		}
	}
	
	response, err := httpClient.Do( request )
	if err != nil { return }
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK { err = ErrHttpStatus( response.StatusCode ); return }
	return io.ReadAll(response.Body)
}

// ParallelDoH issues DNS-over-HTTPs requests in parallel. The number of parallel requests is determined by the dohServers slice length
func ( d *Resolver ) ParallelDoH( ctx context.Context, dohServers []string, name string, questionType dnsmessage.Type ) ( responses chan DoHResponse, err error ){
	requestBuf, err := d.createDnsMessage( name, questionType )																						// Create a DNS message to resolve "name"
	if err != nil { log.Println( "PDoH: [ERR] Create DNS message failed:", err ); return }
	
	responses = make( chan DoHResponse, len(dohServers) )
	var responseBuf []byte
	var stamp dnsstamps.ServerStamp
	for i := 0; i < len(dohServers); i++ {																											// Send POST requests
		go func() {
			response := DoHResponse{index: i}
			defer func() { responses <- response } ()																								// Always send on a channel signaling completion, even if no IP got resolved
			
			dohServer, endpoint := dohServers[i], ""																								// DoH servers may be URLs or DNS stamps
			if strings.HasPrefix( dohServer, "sdns://" ) {
				stamp, response.err = dnsstamps.NewServerStampFromString(dohServer)
				if response.err != nil { log.Println( "PDoH: [ERR] Bad DNS stamp in", dohServer ); return }
				if stamp.Proto != dnsstamps.StampProtoTypeDoH { log.Println( "PDoH: [ERR] Not a DoH server in", dohServer ); response.err = errors.New("bad server"); return }
				dohServer = "https://" + stamp.ProviderName + stamp.Path
				endpoint = stamp.ServerAddrStr
			}
			
			log.Println( "PDoH: Asking", dohServer, "for", questionType, "of", strings.TrimSuffix(name, ".") )
			start := time.Now()
			responseBuf, response.err = d.postDnsMessage( ctx, dohServer, endpoint, requestBuf )
			if errors.Is( response.err, context.DeadlineExceeded ) { log.Println( "PDoH: [ERR]", dohServer, "timed out" ); return }
			if errors.Is( response.err, context.Canceled ) { return }
			if response.err != nil { log.Println( "PDoH: [ERR]", dohServer, "failed:", response.err ); return }
			response.ip, response.err = d.parseMessageForNameAndType( responseBuf, name, questionType )
			if response.err != nil { log.Println( "PDoH: [ERR] Parse DNS message from", dohServer, "failed:", response.err ); return }
			if response.ip == nil { log.Println( "PDoH: [ERR]", dohServer, "could not resolve", questionType, "for", strings.TrimSuffix(name, "."), "in", time.Since(start) ); return }
			log.Println( "PDoH:", dohServer, "resolved", strings.TrimSuffix(name, "."), "to", response.ip.String(), "in", time.Since(start) )
		}()
	}
	return
}

// ResolveType resolves "name" of type "queryType" in two phases. In the first phase a lookup for "name" is done. In the second phase a lookup for the dash encoded IP is done
// A DoH server that resolved in phase 1 won't be used in phase 2 unless necessary
func ( d *Resolver ) ResolveType( ctx context.Context, name string, queryType dnsmessage.Type ) ( ip net.IP, err error ) {
	defer func() { if err != nil { log.Println( "DoHx: [ERR] DoH failed:", err ) } }()
	if len(d.dohServers) == 0 { err = errors.New( "empty DoH server list" ); return }
	if !strings.HasSuffix( name, "." ) { name += "." }
	
	dohServers, successfulServerIndex := d.dohServers, 0
	for i, parallelism := 1, 1; len(dohServers) > 0; i++ {
		parallelism *= i
		if parallelism > len( dohServers ) { parallelism = len( dohServers ) }																		// Use up to parallelism DoH servers
		log.Println( "DoH1: Using", parallelism, "DoH server(s) in iteration", i )
		
		dohCtx, cancel := context.WithTimeout( ctx, 5 * time.Second )
		responses, pErr := d.ParallelDoH( dohCtx, dohServers[:parallelism], name, queryType )														// Resolve name
		if pErr != nil { cancel(); return nil, pErr }
		
		var response DoHResponse
		for count := 0; count < cap(responses); count ++ { if response = <-responses; response.err == nil { break } }								// Wait for a first successful response
		cancel()																																	// Cancel all the other parallel DoH queries
		if response.err == nil { ip = response.ip; successfulServerIndex += response.index; break }													// There was a successful response
		
		dohServers = dohServers[parallelism:]																										// DoH servers used so far failed, proceed with the next batch
		successfulServerIndex += parallelism
	}
	
	if ip == nil { log.Println( "DoH1: [ERR] Resolve", queryType, "for", strings.TrimSuffix(name, "."), "failed" ); return }
	log.Println( "DoH1: Resolved", queryType, "for", strings.TrimSuffix(name, "."), "to", ip )														// IP resolved, time to verify it
	
	dohServers = d.dohServers
	if len(dohServers) > 1 {																														// When there's just one DoH server in the list we have to reuse it
		dohServers[successfulServerIndex], dohServers[len(dohServers)-1] = dohServers[len(dohServers)-1], dohServers[successfulServerIndex]
		dohServers = dohServers[:len(dohServers)-1]
	}
	
	if !strings.HasSuffix( name, ".hideservers.net." ) { return }																					// Skip verifications, except for hideservers.net
	switch queryType {																																// Construct the name as a dash-encoded IP address
		case dnsmessage.TypeA:		name = strings.ReplaceAll( ip.String(), ".", "-" ) + ".hideservers.net."
		case dnsmessage.TypeAAAA:	name = strings.ReplaceAll( ip.String(), ":", "-" ) + "-v6.hideservers.net."
	}
	verified := false
	successfulServerIndex = 0;
	for i, parallelism := 1, 1; len(dohServers) > 0; i++ {
		parallelism *= i
		if parallelism > len( dohServers ) { parallelism = len( dohServers ) }																		// Use up to parallelism DoH servers
		log.Println( "DoH2: Using", parallelism, "DoH server(s) in iteration", i )
		
		dohCtx, cancel := context.WithTimeout( ctx, 5 * time.Second )
		responses, pErr := d.ParallelDoH( dohCtx, dohServers[:parallelism], name, queryType )														// Resolve name
		if pErr != nil { cancel(); return nil, pErr }
		
		for count := 0; count < cap(responses); count ++ {
			if response := <-responses; response.ip.Equal(ip) { verified = true; successfulServerIndex += response.index; break }					// Got a response which matches the ip returned in the first phase
		}
		cancel()																																	// Cancel all the other parallel DoH queries
		if verified { break }
		
		dohServers = dohServers[parallelism:]																										// None of the used DoH servers provided an answer, skip them in the next iteration
		successfulServerIndex += parallelism																										// the next iteration
	}
	if !verified { log.Println( "DoH2: [ERR] Could not verify", ip ); ip = nil; return }
	return
}

func ( d *Resolver ) Resolve( ctx context.Context, name string ) ( ips []net.IP, err error ) {
	ip, err := d.ResolveType( ctx, name, dnsmessage.TypeA )
	if err != nil { return }
	if ip != nil { ips = append( ips, ip ) }
	ip, err = d.ResolveType( ctx, name, dnsmessage.TypeAAAA )
	if err != nil { return }
	if ip != nil { ips = append( ips, ip ) }
	return
}