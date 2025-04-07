package doh

import (
	"bufio"
	"errors"
	"github.com/jedisct1/go-dnsstamps"
	"github.com/vishvananda/netlink"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ParseDnsStamps parses DNS stamps read from a reader, checks if they're of DoH type and checks if the IPs associated to those DoH servers can be reached
func ( d *Resolver ) ParseDnsStamps( reader io.Reader ) ( dohServers []string ) {
	line, stamp, ip, err := "", dnsstamps.ServerStamp{}, net.IP(nil), error(nil)
	for scanner := bufio.NewScanner(reader); scanner.Scan(); {
		line = strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "sdns://" ) { continue }
		
		if stamp, err = dnsstamps.NewServerStampFromString(line); err != nil { log.Println( "dPrs: [ERR] Parse", line, "failed:", err ); continue }
		if stamp.Proto != dnsstamps.StampProtoTypeDoH { continue }
		
		if len(stamp.ServerAddrStr) == 0 { stamp.ServerAddrStr = stamp.ProviderName + ":443" }
		host, _, err := net.SplitHostPort(stamp.ServerAddrStr)
		if err != nil { log.Println( "dPrs: Split host:port failed on", stamp.ServerAddrStr, "for", stamp.ProviderName, "with:", err ); continue }
		
		if ip = net.ParseIP(host); ip == nil { /* log.Println( "dPrs: [ERR] Parse", host, "as an IP failed" );*/ continue }
		if route, err := netlink.RouteGet( ip ); err != nil || len(route) == 0 { /* log.Println( "dPrs: [ERR]", ip, "unreachable" ); */ continue }
		
		dohServers = append( dohServers, line )
	}
	return
}

// Update fetches DNS stamp lists and filters them to remove non-DoH servers and/or network family incompatible DoH servers
func ( d *Resolver ) Update() ( err error ) {
	if len(d.Config.Filename) == 0 { err = errors.New("no filename"); log.Println( "dUpd: [ERR] Failed:", err ); return }
	if len(d.Config.UpdateURLs) == 0 { return }
	httpClient := &http.Client{Transport: &http.Transport{ DisableKeepAlives: true, ForceAttemptHTTP2: true }, Timeout: 5 * time.Second }
	var request *http.Request
	var response *http.Response
	var file *os.File
	
	for _, source := range d.Config.UpdateURLs {
		log.Println( "dUpd: Downloading resolver list from", source )
		if request, err = http.NewRequest( "GET", source, nil ); err != nil { log.Println( "dUpd: [ERR] Resolvers update failed:", err ); return }
		if response, err = httpClient.Do( request ); err != nil { log.Println( "dUpd: [ERR] Resolvers update failed:", err ); continue }
		if response.StatusCode != 200 { log.Println( "dUpd: [ERR] Resolvers update from", source, "failed with status code", response.StatusCode ); continue }
		defer response.Body.Close()
		
		if file == nil {
			if file, err = os.Create(d.Config.Filename); err != nil { log.Println( "dUpd: [ERR] Create", d.Config.Filename, "failed:", err ); return }
			defer func() { log.Println( "dUpd: Resolvers stored to", d.Config.Filename ); _ = file.Close() } ()
		}
		if _, err = io.Copy(file, response.Body); err != nil { log.Println( "dUpd: Write", d.Config.Filename, "failed:", err ); return }
		if _, err = file.Write( []byte{'\n'} ); err != nil { log.Println( "dUpd: Write (newline)", d.Config.Filename, "failed:", err ); return }
	}
	return
}

func ( d *Resolver ) RandomizeOrder() {
	for i := 0; i < len(d.dohServers); i++ {
		j := rand.Intn( len(d.dohServers) )
		d.dohServers[i], d.dohServers[j] = d.dohServers[j], d.dohServers[i]
	}
}

func ( d *Resolver ) Dump() ( err error ) {
	stamp := dnsstamps.ServerStamp{}
	for _, dohServer := range d.dohServers {
		if stamp, err = dnsstamps.NewServerStampFromString(dohServer); err != nil { log.Println( "dump: [ERR] Parse", dohServer, "failed:", err ); continue }
		log.Println( "dump:", stamp.ProviderName + stamp.Path, stamp.ServerAddrStr, "-", dohServer)
	}
	return
}