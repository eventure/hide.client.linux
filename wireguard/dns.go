package wireguard

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
)

// Update the system-wide DNS
func (l *Link) dnsSet( dnses []net.IP ) ( err error ) {
	if err = os.Rename( "/etc/resolv.conf", l.Config.ResolvConfBackupFile ); err != nil { // Rename the resolv.conf to conserve it
		linkError := err.( *os.LinkError )
		fmt.Println( "Link: [ERR] Rename of /etc/resolv.conf to", l.Config.ResolvConfBackupFile, "failed,", linkError.Err )
		return
	}
	fmt.Println( "Link: /etc/resolv.conf moved to", l.Config.ResolvConfBackupFile )
	nameServers := "timeout 1\n"																														// Create new content
	for _, dns := range dnses { nameServers += "nameserver " + dns.String() + "\n" }
	if err = ioutil.WriteFile( "/etc/resolv.conf", []byte( nameServers ), 0644 ); err != nil {															// Create the new /etc/resolv.conf
		fmt.Println( "Link: /etc/resolv.conf create failed,", err )
		if moveErr := os.Rename( l.Config.ResolvConfBackupFile, "/etc/resolv.conf" ); moveErr != nil {
			fmt.Println( "Link: [ERR] Rename of", l.Config.ResolvConfBackupFile, "to /etc/resolv.conf failed,", moveErr )
			return
		} else { fmt.Println( "Link: [CLEANUP]", l.Config.ResolvConfBackupFile, "moved back to /etc/resolv.conf" ) }
		return
	}
	fmt.Println( "Link: /etc/resolv.conf created" )
	return
}

func (l *Link) dnsRestore() ( err error ) {
	if err = os.Remove( "/etc/resolv.conf" ); err != nil {
		fmt.Println( "Link: [ERR] /etc/resolv.conf remove failed,", err )
		linkError := err.( *os.LinkError )
		if linkError.Err != os.ErrNotExist { return }
	}
	if err = os.Rename( l.Config.ResolvConfBackupFile, "/etc/resolv.conf" ); err != nil {
		fmt.Println( "Link: [ERR] Rename of", l.Config.ResolvConfBackupFile, "to /etc/resolv.conf failed,", err )
		return
	}
	fmt.Println( "Link: /etc/resolv.conf restored" )
	return
}
